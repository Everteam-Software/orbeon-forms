/**
 *  Copyright (C) 2008 Orbeon, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify it under the terms of the
 *  GNU Lesser General Public License as published by the Free Software Foundation; either version
 *  2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 *  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU Lesser General Public License for more details.
 *
 *  The full text of the license is available at http://www.gnu.org/copyleft/lesser.html
 */
package org.orbeon.oxf.xforms;

import org.apache.commons.collections.map.CompositeMap;
import org.dom4j.Attribute;
import org.dom4j.Element;
import org.dom4j.QName;
import org.orbeon.oxf.common.OXFException;
import org.orbeon.oxf.common.ValidationException;
import org.orbeon.oxf.util.PropertyContext;
import org.orbeon.oxf.util.XPathCache;
import org.orbeon.oxf.xforms.action.actions.XFormsSetvalueAction;
import org.orbeon.oxf.xforms.control.XFormsControl;
import org.orbeon.oxf.xforms.control.XFormsPseudoControl;
import org.orbeon.oxf.xforms.control.XFormsSingleNodeControl;
import org.orbeon.oxf.xforms.control.XFormsValueControl;
import org.orbeon.oxf.xforms.control.controls.XFormsRepeatIterationControl;
import org.orbeon.oxf.xforms.event.events.XFormsComputeExceptionEvent;
import org.orbeon.oxf.xforms.processor.XFormsServer;
import org.orbeon.oxf.xforms.xbl.XBLContainer;
import org.orbeon.oxf.xml.XMLConstants;
import org.orbeon.oxf.xml.XMLUtils;
import org.orbeon.oxf.xml.dom4j.Dom4jUtils;
import org.orbeon.oxf.xml.dom4j.ExtendedLocationData;
import org.orbeon.oxf.xml.dom4j.LocationData;
import org.orbeon.saxon.expr.XPathContext;
import org.orbeon.saxon.expr.XPathContextMajor;
import org.orbeon.saxon.om.*;
import org.orbeon.saxon.style.StandardNames;
import org.orbeon.saxon.sxpath.XPathEvaluator;
import org.orbeon.saxon.trans.IndependentContext;
import org.orbeon.saxon.trans.XPathException;
import org.orbeon.saxon.type.BuiltInAtomicType;
import org.orbeon.saxon.type.BuiltInSchemaFactory;
import org.orbeon.saxon.value.AtomicValue;
import org.orbeon.saxon.value.SequenceExtent;
import org.orbeon.saxon.value.StringValue;
import org.orbeon.saxon.value.ValidationErrorValue;

import java.util.*;

/**
 * Represent a given model's binds.
 */
public class XFormsModelBinds {

    private final XFormsModel model;                            // model to which we belong

    private final XBLContainer container;
    private final XFormsContainingDocument containingDocument;  // current containing document
    private final boolean computedBindsCalculate;               // whether computed binds (readonly, required, relevant) are evaluated with recalculate or revalidate

    private final List<Element> bindElements;
    private List<Bind> topLevelBinds = new ArrayList<Bind>();
    private Map<String, Bind> singleNodeContextBinds = new HashMap<String, Bind>();
    private Map<NodeInfo, List<BindIteration>> iterationsForContextNodeInfo = new HashMap<NodeInfo, List<BindIteration>>();
    private List<Bind> offlineBinds = new ArrayList<Bind>();
    private Map<String, String> variableNamesToIds = new HashMap<String, String>();

    private XFormsModelSchemaValidator xformsValidator;         // validator for standard XForms schema types

    private boolean isFirstCalculate;                           // whether this is the first recalculate for the associated XForms model

    private static final Map<String, String> BUILTIN_XFORMS_SCHEMA_TYPES = new HashMap<String, String>();

    static {
        BUILTIN_XFORMS_SCHEMA_TYPES.put("dayTimeDuration", "");
        BUILTIN_XFORMS_SCHEMA_TYPES.put("yearMonthDuration", "");
        BUILTIN_XFORMS_SCHEMA_TYPES.put("email", "");
        BUILTIN_XFORMS_SCHEMA_TYPES.put("card-number", "");
    }

    /**
     * Create an instance of XFormsModelBinds if the given model has xforms:bind elements.
     *
     * @param model XFormsModel
     * @return      XFormsModelBinds or null if the model doesn't have xforms:bind elements
     */
    public static XFormsModelBinds create(XFormsModel model) {
        final List<Element> bindElements = Dom4jUtils.elements(model.getModelDocument().getRootElement(), XFormsConstants.XFORMS_BIND_QNAME);
        final boolean hasBinds = bindElements != null && bindElements.size() > 0;

        return hasBinds ? new XFormsModelBinds(model, bindElements) : null;
    }

    private XFormsModelBinds(XFormsModel model, List<Element> bindElements) {
        this.model = model;

        this.container = model.getXBLContainer();
        this.containingDocument = model.getContainingDocument();
        this.computedBindsCalculate = XFormsProperties.getComputedBinds(containingDocument).equals(XFormsProperties.COMPUTED_BINDS_RECALCULATE_VALUE);

        this.bindElements = bindElements;

        // For the lifecycle of an XForms document, new XFormsModelBinds() may be created multiple times, e.g. if the
        // state is deserialized, but we know that new XFormsModelBinds() will occur only once during document
        // initialization. So the assignation below is ok.
        this.isFirstCalculate = containingDocument.isInitializing();
    }

    /**
     * Rebuild all binds, computing all bind nodesets (but not computing the MIPs)
     *
     * @param propertyContext   current context
     */
    public void rebuild(PropertyContext propertyContext) {

        if (XFormsServer.logger.isDebugEnabled())
            containingDocument.startHandleOperation("model", "performing rebuild", "model id", model.getEffectiveId());

        // Reset everything
        model.getContextStack().resetBindingContext(propertyContext, model);
        topLevelBinds.clear();
        singleNodeContextBinds.clear();
        iterationsForContextNodeInfo.clear();
        offlineBinds.clear();
        variableNamesToIds.clear();

        // Iterate through all top-level bind elements
        for (Element currentBindElement: bindElements) {
            // Create and remember as top-level bind
            final Bind currentBind = new Bind(propertyContext, currentBindElement, true);
            topLevelBinds.add(currentBind);
        }

        if (XFormsServer.logger.isDebugEnabled())
            containingDocument.endHandleOperation();
    }

    /**
     * Apply calculate binds.
     *
     * @param propertyContext   current context
     */
    public void applyCalculateBinds(final PropertyContext propertyContext) {

        if (XFormsServer.logger.isDebugEnabled())
            containingDocument.startHandleOperation("model", "performing recalculate", "model id", model.getEffectiveId());

        // Reset context stack just to re-evaluate the variables
        model.getContextStack().resetBindingContext(propertyContext, model);

        if (isFirstCalculate) {
            // Handle default values
            iterateBinds(propertyContext, new BindRunner() {
                public void applyBind(PropertyContext propertyContext, Bind bind, List<Item> nodeset, int position) {
                    handleXXFormsDefaultBind(propertyContext, bind, nodeset, position);
                }
            });
            // This will be false from now on as we have done our first handling of calculate binds
            isFirstCalculate = false;
        }

        // Handle calculations
        // NOTE: we do not correctly handle computational dependencies, but it doesn't hurt
        // to evaluate "calculate" binds before the other binds.
        iterateBinds(propertyContext, new BindRunner() {
            public void applyBind(PropertyContext propertyContext, Bind bind, List<Item> nodeset, int position) {
                handleCalculateBind(propertyContext, bind, nodeset, position);
            }
        });

        // Update computed expression binds if requested (done here according to XForms 1.1)
        if (computedBindsCalculate) {
            applyComputedExpressionBinds(propertyContext);
        }

        if (XFormsServer.logger.isDebugEnabled())
            containingDocument.endHandleOperation();
    }

    /**
     * Apply required, relevant and readonly binds.
     *
     * @param propertyContext   current PropertyContext
     */
    public void applyComputedExpressionBinds(final PropertyContext propertyContext) {

        // Reset context stack just to re-evaluate the variables
        model.getContextStack().resetBindingContext(propertyContext, model);

        // Clear state
        final List<XFormsInstance> instances = model.getInstances();
        if (instances != null) {
            for (XFormsInstance instance: instances) {
                XFormsUtils.iterateInstanceData(instance, new XFormsUtils.InstanceWalker() {
                    public void walk(NodeInfo nodeInfo) {
                        InstanceData.clearOtherState(nodeInfo);
                    }
                }, true);
            }

            iterateBinds(propertyContext, new BindRunner() {
                public void applyBind(PropertyContext propertyContext, Bind bind, List<Item> nodeset, int position) {
                    handleComputedExpressionBind(propertyContext, bind, nodeset, position);
                }
            });
        }
    }

    /**
     * Apply validation binds
     *
     * @param propertyContext   current PropertyContext
     * @param invalidInstances
     */
    public void applyValidationBinds(final PropertyContext propertyContext, final Map<String, String> invalidInstances) {

        // Reset context stack just to re-evaluate the variables
        model.getContextStack().resetBindingContext(propertyContext, model);

        // Handle validation
        iterateBinds(propertyContext, new BindRunner() {
            public void applyBind(PropertyContext propertyContext, Bind bind, List<Item> nodeset, int position) {
                handleValidationBind(propertyContext, bind, nodeset, position, invalidInstances);
            }
        });

        // Update computed expression binds if requested (done here upon a preference)
        if (!computedBindsCalculate) {
            applyComputedExpressionBinds(propertyContext);
        }
    }

    /**
     * Return the nodeset for a given bind and context item, as per "4.7.2 References to Elements within a bind
     * Element".
     *
     * @param bindId        id of the bind to handle
     * @param contextItem   context item if necessary
     * @return              bind nodeset
     */
    public List<Item> getBindNodeset(String bindId, Item contextItem) {

        final Bind singleNodeContextBind = singleNodeContextBinds.get(bindId);
        if (singleNodeContextBind != null) {
            // This bind has a single-node context (incl. top-level bind), so ignore context item and just return the bind nodeset
            return singleNodeContextBind.getNodeset();
        } else {
            // Nested bind, context item will be used

            // This requires a context node, not just any item
            if (contextItem instanceof NodeInfo) {
                final List<BindIteration> iterationsForContextNode = iterationsForContextNodeInfo.get(contextItem);
                if (iterationsForContextNode != null) {
                    for (BindIteration currentIteration: iterationsForContextNode) {
                        final Bind currentBind = currentIteration.getBind(bindId);
                        if (currentBind != null) {
                            // Found
                            return currentBind.getNodeset();
                        }
                    }
                }
            }
        }

        // Nothing found
        return XFormsConstants.EMPTY_ITEM_LIST;
    }

    /**
     * Return all binds marked with xxforms:offline="true".
     *
     * @return  List<Bind> of offline binds
     */
    public List<Bind> getOfflineBinds() {
        return offlineBinds;
    }

    /**
     * Return a JSON string containing the control -> mips and variable -> control mappings for all models.
     *
     * Example of output:
     *
     * {
     *     "mips": {
     *         "total-control": { "calculate": { "xpath": "$units * $price" }, ... other MIPs ... },
     *         "my-group": { "relevant": { "xpath": "$price > 10", "inherited": ["inherited-control-1", "inherited-control-2", ... ]} }
     *         ... other controls ...
     *     },
     *     "variables": {
     *         "units": "units-control",
     *         "price": "price-control"
     *     }
     * };
     *
     * @param containingDocument
     * @return  JSON string
     */
    public static String getOfflineBindMappings(XFormsContainingDocument containingDocument) {

        if (XFormsServer.logger.isDebugEnabled())
            containingDocument.startHandleOperation("model", "getting offline bind mappings");

        final Map<String, XFormsControl> effectiveIdsToControls = containingDocument.getControls().getCurrentControlTree().getEffectiveIdsToControls();
        final FastStringBuffer sb = new FastStringBuffer('{');

        final Map<NodeInfo, Object> nodesToControlsMapping = getNodesToControlsMapping(effectiveIdsToControls);

        // Handle MIPs
        sb.append("\"mips\": {");
        {
            boolean controlFound = false;
            // Iterate through models
            // TODO: Nested containers
            for (XFormsModel currentModel: containingDocument.getModels()) {
                final XFormsModelBinds currentBinds = currentModel.getBinds();
                if (currentBinds != null) {
                    final List<Bind> offlineBinds = currentBinds.getOfflineBinds();
                    //  Iterate through offline binds
                    for (Bind currentBind: offlineBinds) {
                        final List<Item> currentNodeset = currentBind.getNodeset();

                        // Find ids of controls inheriting the readonly and relevant MIPs if necessary
                        final String readonly = currentBind.getReadonly();
                        final String relevant = currentBind.getRelevant();
                        final List<XFormsControl> controlsInheritingMIPs;
                        if (readonly != null || relevant != null ) {
                            // Find ids of controls that inherit the property

                            // Find attributes and elements which are children of nodes in the current nodeset
                            final List<Item> nestedNodeset = new ArrayList<Item>();
                            XFormsUtils.getNestedAttributesAndElements(nestedNodeset, currentNodeset);
                            if (nestedNodeset.size() > 0) {
                                // Find all controls bound to those nested nodes: they are influenced by the mips
                                controlsInheritingMIPs = getBoundControls(nodesToControlsMapping, nestedNodeset);
                            } else {
                                // No controls are bound to nested nodes
                                controlsInheritingMIPs = null;
                            }
                        } else {
                            controlsInheritingMIPs = null;
                        }

                        // Find controls directly bound to nodes in the bind nodeset
                        final List<XFormsControl> boundControls = getBoundControls(nodesToControlsMapping, currentNodeset);

                        if (boundControls.size() > 0) {
                            for (XFormsControl currentControl: boundControls) {

                                if (controlFound)
                                    sb.append(',');
                                controlFound = true;

                                // Control id
                                sb.append('"');
                                sb.append(currentControl.getEffectiveId());
                                sb.append("\": {");


                                // Output MIPs
                                boolean mipFound = false;
                                mipFound = appendNameValue(sb, mipFound, "calculate", currentBind.getCalculate(), null);
                                mipFound = appendNameValue(sb, mipFound, "relevant", relevant, controlsInheritingMIPs);
                                mipFound = appendNameValue(sb, mipFound, "readonly", readonly, controlsInheritingMIPs);
                                mipFound = appendNameValue(sb, mipFound, "required", currentBind.getRequired(), null);
                                mipFound = appendNameValue(sb, mipFound, "constraint", currentBind.getConstraint(), null);

                                // Output type MIP as an exploded QName
                                final String typeMip = currentBind.getType();
                                if (typeMip != null) {
                                    final QName typeMipQName = Dom4jUtils.extractTextValueQName(currentModel.getXBLContainer().getNamespaceMappings(currentBind.getBindElement()), typeMip, false);
                                    mipFound = appendNameValue(sb, mipFound, "type", Dom4jUtils.qNameToExplodedQName(typeMipQName), null);
                                }

                                sb.append('}');
                            }
                        }
                    }
                }
            }
        }
        // Handle variables
        sb.append("},\"variables\": {");
        {
            // Iterate through models
            // TODO: Nested containers
            for (XFormsModel currentModel: containingDocument.getModels()) {
                // Iterate through variables
                // NOTE: We assume top-level or single-node context binds
                final XFormsModelBinds currentBinds = currentModel.getBinds();
                if (currentBinds != null) {
                    final Map<String, ValueRepresentation> variables = currentModel.getBinds().getVariables(null);
                    boolean controlFound = false;
                    for (Map.Entry<String, ValueRepresentation> currentEntry: variables.entrySet()) {
                        final String currentVariableName = currentEntry.getKey();
                        final SequenceExtent currentVariableValue = (SequenceExtent) currentEntry.getValue();

                        // Find controls bound to the bind exposed as a variable
                        final List<Item> currentNodeset = sequenceExtentToList(currentVariableValue);
                        final List<XFormsControl> boundControls = getBoundControls(nodesToControlsMapping, currentNodeset);
                        if (boundControls.size() > 0) {
                            for (XFormsControl currentControl: boundControls) {
                                // Make sure this is a value control (e.g. we can't get the value of bound groups in the UI)
                                if (currentControl instanceof XFormsValueControl) {
                                    final String effectiveControlId = currentControl.getEffectiveId();
                                    controlFound = appendNameValue(sb, controlFound, currentVariableName, effectiveControlId, null);
                                    // We only handle the first value control found
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        sb.append('}');

        final String result = sb.toString();

        if (XFormsServer.logger.isDebugEnabled())
            containingDocument.endHandleOperation();

        return result;
    }

    private static List<Item> sequenceExtentToList(SequenceExtent sequenceExtent) {
        try {
            final List<Item> result = new ArrayList<Item>(sequenceExtent.getLength());
            final SequenceIterator si = sequenceExtent.iterate(null);
            for (Item item = si.next(); item != null; item = si.next()) {
                result.add(item);
            }
            return result;
        } catch (XPathException e) {
            // Should not happen with SequenceExtent
            throw new OXFException(e);
        }
    }

    private static List<XFormsControl> getBoundControls(Map<NodeInfo, Object> nodesToControlsMapping, List<Item> nodeset) {
        final List<XFormsControl> result = new ArrayList<XFormsControl>();

        // Iterate through nodeset
        for (Item currentNodeInfo: nodeset) {
            final Object match = nodesToControlsMapping.get(currentNodeInfo);
            if (match == null) {
                // Nothing to see here
            } else if (match instanceof XFormsControl) {
                // Control
                result.add((XFormsControl) match);
            } else {
                // List
                result.addAll((Collection) match);
            }
        }
        return result;
    }

    private static Map<NodeInfo, Object> getNodesToControlsMapping(Map<String, XFormsControl> idsToXFormsControls) {
        final Map<NodeInfo, Object> result = new HashMap<NodeInfo, Object>();

        // Iterate through controls
        for (Map.Entry<String,XFormsControl> currentEntry: idsToXFormsControls.entrySet()) {
            final XFormsControl currentControl = currentEntry.getValue();

            if (currentControl instanceof XFormsSingleNodeControl
                    && (currentControl instanceof XFormsRepeatIterationControl || !(currentControl instanceof XFormsPseudoControl))) {
                // Only check real single-node controls (includes xforms:group, xforms:switch, xforms:trigger) which have a new binding
                // But also support repeat iterations, as their MIPs
                final NodeInfo boundNode = ((XFormsSingleNodeControl) currentControl).getBoundNode();
                if (boundNode != null) {
                    // There is a match
                    final Object existing = result.get(boundNode);// multiple controls may be bound to a node
                    if (existing == null) {
                        // No control yet, put the control in (hopefully the most frequent case)
                        result.put(boundNode, currentControl);
                    } else if (existing instanceof XFormsControl) {
                        // There is just one control, which we replace with a list
                        final List<Object> newList = new ArrayList<Object>();
                        newList.add(existing);
                        newList.add(currentControl);
                        result.put(boundNode, newList);
                    } else  {
                        // More than one control already, just add to it
                        final List<Object> existingList = (List<Object>) existing;
                        existingList.add(currentControl);
                    }
                }
            }
        }
        return result;
    }

    private static boolean appendNameValue(FastStringBuffer sb, boolean found, String name, String value, List<XFormsControl> controlsInheritingMIPs) {
        if (value != null) {
            if (found)
                sb.append(',');

            sb.append('"');
            sb.append(XFormsUtils.escapeJavaScript(name));
            sb.append("\": { \"value\":\"");
            sb.append(XFormsUtils.escapeJavaScript(value));
            sb.append('"');
            if (controlsInheritingMIPs != null) {
                sb.append(", \"inherited\":[");

                int idIndex = 0;
                for (XFormsControl currentControl: controlsInheritingMIPs) {
                    if (idIndex > 0)
                        sb.append(',');

                    sb.append('"');
                    sb.append(XFormsUtils.escapeJavaScript(currentControl.getEffectiveId()));
                    sb.append('"');
                }

                sb.append(']');
            }
            sb.append('}');
            return true;
        } else {
            return found;
        }
    }

    /**
     * Iterate over all binds and for each one do the callback.
     *
     * @param propertyContext   current context
     * @param bindRunner
     */
    private void iterateBinds(PropertyContext propertyContext, BindRunner bindRunner) {
        // Iterate over top-level binds
        for (Bind currentBind: topLevelBinds) {
            try {
                currentBind.applyBinds(propertyContext, bindRunner);
            } catch (Exception e) {
                throw ValidationException.wrapException(e, new ExtendedLocationData(currentBind.getLocationData(), "evaluating XForms binds", currentBind.getBindElement()));
            }
        }
    }

    private void handleXXFormsDefaultBind(final PropertyContext propertyContext, Bind bind, List<Item> nodeset, int position) {

        // Handle xxforms:default MIP
        if (bind.getXXFormsDefault() != null) {
            // Compute default value
            try {
                final NodeInfo currentNodeInfo = (NodeInfo) nodeset.get(position - 1);

                final String stringResult = XPathCache.evaluateAsString(propertyContext, nodeset, position, bind.getXXFormsDefault(),
                        container.getNamespaceMappings(bind.getBindElement()), getVariables(currentNodeInfo),
                        XFormsContainingDocument.getFunctionLibrary(), model.getContextStack().getFunctionContext(),
                        bind.getLocationData().getSystemID(), bind.getLocationData());

                // TODO: Detect if we have already handled this node and dispatch xforms-binding-exception
                // TODO: doSetValue may dispatch an xforms-binding-exception. It should reach the bind, but we don't support that yet so pass the model.
                XFormsSetvalueAction.doSetValue(propertyContext, containingDocument, model, currentNodeInfo, stringResult, null, true);

            } catch (Exception e) {
                final ValidationException ve = ValidationException.wrapException(e, new ExtendedLocationData(bind.getLocationData(), "evaluating XForms calculate bind",
                        bind.getBindElement(), new String[] { "expression", bind.getCalculate() }));

                container.dispatchEvent(propertyContext, new XFormsComputeExceptionEvent(model, ve.getMessage(), ve));
            }
        }
    }

    private void handleCalculateBind(final PropertyContext propertyContext, Bind bind, List<Item> nodeset, int position) {
        // Handle calculate MIP
        if (bind.getCalculate() != null) {
            // Compute calculated value
            try {
                final NodeInfo currentNodeInfo = (NodeInfo) nodeset.get(position - 1);

                final String stringResult = XPathCache.evaluateAsString(propertyContext, nodeset, position, bind.getCalculate(),
                        container.getNamespaceMappings(bind.getBindElement()), getVariables(currentNodeInfo),
                        XFormsContainingDocument.getFunctionLibrary(), model.getContextStack().getFunctionContext(),
                        bind.getLocationData().getSystemID(), bind.getLocationData());

                // TODO: Detect if we have already handled this node and dispatch xforms-binding-exception
                // TODO: doSetValue may dispatch an xforms-binding-exception. It should reach the bind, but we don't support that yet so pass the model.
                XFormsSetvalueAction.doSetValue(propertyContext, containingDocument, model, currentNodeInfo, stringResult, null, true);

            } catch (Exception e) {
                final ValidationException ve = ValidationException.wrapException(e, new ExtendedLocationData(bind.getLocationData(), "evaluating XForms calculate bind",
                        bind.getBindElement(), new String[] { "expression", bind.getCalculate() }));

                container.dispatchEvent(propertyContext, new XFormsComputeExceptionEvent(model, ve.getMessage(), ve));
            }
        }
    }

    private Map<String, ValueRepresentation> getVariables(NodeInfo contextNodeInfo) {

        if (variableNamesToIds.size() > 0) {
            final Map<String, ValueRepresentation> bindVariablesValues = new HashMap<String, ValueRepresentation>();

            // Add bind variables
            for (Map.Entry<String, String> currentEntry: variableNamesToIds.entrySet()) {
                final String currentVariableName = currentEntry.getKey();
                final String currentBindId = currentEntry.getValue();

                final List<Item> currentBindNodeset = getBindNodeset(currentBindId, contextNodeInfo);
                bindVariablesValues.put(currentVariableName, new SequenceExtent(currentBindNodeset));
            }

            // Combine bind variables with model variables
            return new CompositeMap(bindVariablesValues, model.getContextStack().getCurrentVariables());
        } else {
            // Just return the regular variables in scope
            return model.getContextStack().getCurrentVariables();
        }
    }

    private void handleComputedExpressionBind(PropertyContext propertyContext, Bind bind, List<Item> nodeset, int position) {

        final NodeInfo currentNodeInfo = (NodeInfo) nodeset.get(position - 1);
        final Map<String, ValueRepresentation> currentVariables = getVariables(currentNodeInfo);

        // Handle required MIP
        if (bind.getRequired() != null) {
            // Evaluate "required" XPath expression on this node
            try {
                // Get MIP value
                final boolean required = evaluateBooleanExpression1(propertyContext, bind, bind.getRequired(), nodeset, position, currentVariables);

                // Update node with MIP value
                InstanceData.setRequired(currentNodeInfo, required);
            } catch (Exception e) {
                final ValidationException ve = ValidationException.wrapException(e, new ExtendedLocationData(bind.getLocationData(), "evaluating XForms required bind",
                        bind.getBindElement(), new String[] { "expression", bind.getRequired() }));

                container.dispatchEvent(propertyContext, new XFormsComputeExceptionEvent(model, ve.getMessage(), ve));
            }
        }

        // Handle relevant MIP
        if (bind.getRelevant() != null) {
            // Evaluate "relevant" XPath expression on this node
            try {
                final boolean relevant = evaluateBooleanExpression1(propertyContext, bind, bind.getRelevant(), nodeset, position, currentVariables);
                // Mark node
                InstanceData.setRelevant(currentNodeInfo, relevant);
            } catch (Exception e) {
                final ValidationException ve = ValidationException.wrapException(e, new ExtendedLocationData(bind.getLocationData(), "evaluating XForms relevant bind",
                        bind.getBindElement(), new String[] { "expression", bind.getRelevant() }));

                container.dispatchEvent(propertyContext, new XFormsComputeExceptionEvent(model, ve.getMessage(), ve));
            }
        }

        // Handle readonly MIP
        if (bind.getReadonly() != null) {
            // The bind has a readonly attribute
            // Evaluate "readonly" XPath expression on this node
            try {
                final boolean readonly = evaluateBooleanExpression1(propertyContext, bind, bind.getReadonly(), nodeset, position, currentVariables);

                // Mark node
                InstanceData.setReadonly(currentNodeInfo, readonly);
            } catch (Exception e) {
                final ValidationException ve = ValidationException.wrapException(e, new ExtendedLocationData(bind.getLocationData(), "evaluating XForms readonly bind",
                        bind.getBindElement(), new String[] { "expression", bind.getReadonly() }));


                container.dispatchEvent(propertyContext, new XFormsComputeExceptionEvent(model, ve.getMessage(), ve));
            }
        } else if (bind.getCalculate() != null) {
            // The bind doesn't have a readonly attribute, but has a calculate: set readonly to true()
            // Mark node
            InstanceData.setReadonly(currentNodeInfo, true);
        }

        final Map<String, String> customMips = bind.getCustomMips();
        if (customMips != null && customMips.size() > 0) {
            for (Map.Entry<String, String> entry: customMips.entrySet()) {
                final String key = entry.getKey();
                final String expression = entry.getValue();

                try {
                    final String stringResult = XPathCache.evaluateAsString(propertyContext, nodeset, position, expression,
                            container.getNamespaceMappings(bind.getBindElement()), getVariables(currentNodeInfo),
                            XFormsContainingDocument.getFunctionLibrary(), model.getContextStack().getFunctionContext(),
                            bind.getLocationData().getSystemID(), bind.getLocationData());

                    InstanceData.setCustom(currentNodeInfo, key, stringResult);
                } catch (Exception e) {
                    final ValidationException ve = ValidationException.wrapException(e, new ExtendedLocationData(bind.getLocationData(), "evaluating XForms custom bind",
                            bind.getBindElement(), new String[] { "name", key, "expression", expression }));

                    container.dispatchEvent(propertyContext, new XFormsComputeExceptionEvent(model, ve.getMessage(), ve));
                }
            }
        }
    }

    private boolean evaluateBooleanExpression1(PropertyContext propertyContext, Bind bind, String xpathExpression,
                                               List<Item> nodeset, int position, Map<String, ValueRepresentation> currentVariables) {
        final String xpath = "boolean(" + xpathExpression + ")";
        return (Boolean) XPathCache.evaluateSingle(propertyContext,
                nodeset, position, xpath, container.getNamespaceMappings(bind.getBindElement()), currentVariables,
                XFormsContainingDocument.getFunctionLibrary(), model.getContextStack().getFunctionContext(), bind.getLocationData().getSystemID(), bind.getLocationData());
    }

//    private boolean evaluateBooleanExpression2(PropertyContext propertyContext, Bind bind, String xpathExpression, List<Item> nodeset, int position, Map currentVariables) {
//        return XPathCache.evaluateAsBoolean(propertyContext,
//            nodeset, position, xpathExpression, containingDocument.getNamespaceMappings(bind.getBindElement()), currentVariables,
//            XFormsContainingDocument.getFunctionLibrary(), model.getContextStack().getFunctionContext(), bind.getLocationData().getSystemID(), bind.getLocationData());
//    }

    private void handleValidationBind(PropertyContext propertyContext, Bind bind, List<Item> nodeset, int position, Map<String, String> invalidInstances) {

        final NodeInfo currentNodeInfo = (NodeInfo) nodeset.get(position - 1);
        final Map<String, String> namespaceMap = container.getNamespaceMappings(bind.getBindElement());

        // Current validity value
        // NOTE: This may have been set by schema validation earlier in the validation process
        boolean isValid = InstanceData.getValid(currentNodeInfo);

        // Current required value (computed during preceding recalculate)
        final boolean isRequired = InstanceData.getRequired(currentNodeInfo);

        // Node value, retrieved if needed
        String nodeValue = null;

        // Handle type MIP
        // NOTE: We must always handle the type first because types are not only used by validation, but by controls
        if (bind.getType() != null) {

            // "The type model item property is not applied to instance nodes that contain child elements"
            if (currentNodeInfo.getNodeKind() != org.w3c.dom.Document.ELEMENT_NODE || !XFormsUtils.hasChildrenElements(currentNodeInfo)) {

                // Need an evaluator to check and convert type below
                final XPathEvaluator xpathEvaluator;
                try {
                    xpathEvaluator = new XPathEvaluator();
                    // NOTE: Not sure declaring namespaces here is necessary just to perform the cast
                    final IndependentContext context = xpathEvaluator.getStaticContext();
                    for (String prefix: namespaceMap.keySet()) {
                        context.declareNamespace(prefix, namespaceMap.get(prefix));
                    }
                } catch (Exception e) {
                    throw ValidationException.wrapException(e, bind.getLocationData());

                    // TODO: xxx check what XForms event must be dispatched
                }

                {
                    // Get type namespace and local name
                    final String typeQName = bind.getType();
                    final String typeNamespaceURI;
                    final String typeLocalname;
                    {
                        final int prefixPosition = typeQName.indexOf(':');
                        if (prefixPosition > 0) {
                            final String prefix = typeQName.substring(0, prefixPosition);
                            typeNamespaceURI = namespaceMap.get(prefix);
                            if (typeNamespaceURI == null)
                                throw new ValidationException("Namespace not declared for prefix '" + prefix + "'",
                                        bind.getLocationData());

                            // TODO: xxx check what XForms event must be dispatched

                            typeLocalname = typeQName.substring(prefixPosition + 1);
                        } else {
                            typeNamespaceURI = "";
                            typeLocalname = typeQName;
                        }
                    }

                    // Get value to validate if not already computed above
                    if (nodeValue == null)
                        nodeValue = XFormsInstance.getValueForNodeInfo(currentNodeInfo);

                    // TODO: "[...] these datatypes can be used in the type model item property without the addition of the
                    // XForms namespace qualifier if the namespace context has the XForms namespace as the default
                    // namespace."

                    final boolean isBuiltInSchemaType = XMLConstants.XSD_URI.equals(typeNamespaceURI);
                    final boolean isBuiltInXFormsType = XFormsConstants.XFORMS_NAMESPACE_URI.equals(typeNamespaceURI);
                    final boolean isBuiltInXXFormsType = XFormsConstants.XXFORMS_NAMESPACE_URI.equals(typeNamespaceURI);

                    final boolean isBuiltInXFormsSchemaType = isBuiltInXFormsType && BUILTIN_XFORMS_SCHEMA_TYPES.get(typeLocalname) != null;

                    if (isBuiltInXFormsSchemaType) {
                        // xforms:dayTimeDuration, xforms:yearMonthDuration, xforms:email, xforms:card-number
                        if (xformsValidator == null) {
                            xformsValidator = new XFormsModelSchemaValidator("oxf:/org/orbeon/oxf/xforms/xforms-types.xsd");
                            xformsValidator.loadSchemas(propertyContext);
                        }

                        final String validationError =
                            xformsValidator.validateDatatype(currentNodeInfo, nodeValue, typeNamespaceURI, typeLocalname, typeQName, bind.getLocationData(), bind.getId());

                        if (validationError != null) {
                            isValid = false;
                            InstanceData.addSchemaError(currentNodeInfo, validationError, nodeValue, bind.getId());
                        }

                    } else if (isBuiltInXFormsType && nodeValue.length() == 0) {
                        // Don't consider the node invalid if the string is empty with xforms:* types
                    } else if (isBuiltInSchemaType || isBuiltInXFormsType) {
                        // Built-in schema or XForms type

                        // Use XML Schema namespace URI as Saxon doesn't know anytyhing about XForms types
                        final String newTypeNamespaceURI = XMLConstants.XSD_URI;

                        // Get type information
                        final int requiredTypeFingerprint = StandardNames.getFingerprint(newTypeNamespaceURI, typeLocalname);
                        if (requiredTypeFingerprint == -1) {
                            throw new ValidationException("Invalid schema type '" + bind.getType() + "'", bind.getLocationData());

                            // TODO: xxx check what XForms event must be dispatched
                        }

                        // Try to perform casting
                        // TODO: Should we actually perform casting? This for example removes leading and trailing space around tokens. Is that expected?
                        final StringValue stringValue = new StringValue(nodeValue);
                        final XPathContext xpContext = new XPathContextMajor(stringValue, xpathEvaluator.getStaticContext().getConfiguration());
                        final AtomicValue result = stringValue.convertPrimitive((BuiltInAtomicType) BuiltInSchemaFactory.getSchemaType(requiredTypeFingerprint), true, xpContext);

                        // Set error on node if necessary
                        if (result instanceof ValidationErrorValue) {
                            isValid = false;
                            InstanceData.updateValueValid(currentNodeInfo, false, bind.getId());
                        }
                    } else if (isBuiltInXXFormsType) {
                        // Built-in extension types

                        // NOTE: For the two types below, we use the required MIP to influence validity. This is not
                        // the common XForms practice but it is convenient here.
                        final boolean isOptionalAndEmpty = !isRequired && "".equals(nodeValue);
                        if (typeLocalname.equals("xml")) {
                            // xxforms:xml type
                            if (!isOptionalAndEmpty && !XMLUtils.isWellFormedXML(nodeValue)) {
                                isValid = false;
                                InstanceData.updateValueValid(currentNodeInfo, false, bind.getId());
                            }
                        } else if (typeLocalname.equals("xpath2")) {
                            // xxforms:xpath2 type
                            if (!isOptionalAndEmpty && !XFormsUtils.isXPath2Expression(nodeValue, namespaceMap)) {
                                isValid = false;
                                InstanceData.updateValueValid(currentNodeInfo, false, bind.getId());
                            }

                        } else {
                            throw new ValidationException("Invalid schema type '" + bind.getType() + "'", bind.getLocationData());

                            // TODO: xxx check what XForms event must be dispatched
                        }

                    } else if (model.getSchemaValidator() != null && model.getSchemaValidator().hasSchema()) {
                        // Other type and there is a schema

                        // There are possibly types defined in the schema
                        final String validationError
                                = model.getSchemaValidator().validateDatatype(currentNodeInfo, nodeValue, typeNamespaceURI, typeLocalname, typeQName, bind.getLocationData(), bind.getId());

                        // Set error on node if necessary
                        if (validationError != null) {
                            isValid = false;
                            InstanceData.addSchemaError(currentNodeInfo, validationError, nodeValue, bind.getId());
                        }
                    } else {
                        throw new ValidationException("Invalid schema type '" + bind.getType() + "'", bind.getLocationData());

                        // TODO: xxx check what XForms event must be dispatched
                    }

                    // Set type on node
                    InstanceData.setType(currentNodeInfo, XMLUtils.buildExplodedQName(typeNamespaceURI, typeLocalname));
                }
            }
        }

        // Bail is we are already invalid
        if (!isValid) {
            // Remember invalid instances
            final XFormsInstance instanceForNodeInfo = containingDocument.getInstanceForNode(currentNodeInfo);
            invalidInstances.put(instanceForNodeInfo.getEffectiveId(), "");
            return;
        }

        // Handle required MIP
        if (isRequired) {// this assumes that the required MIP has been already computed (during recalculate)
            // Current node is required...
            if (nodeValue == null)
                nodeValue = XFormsInstance.getValueForNodeInfo(currentNodeInfo);

            if ("".equals(nodeValue)) {// TODO: configurable notion of "empty"
                // ...and empty
                isValid = false;
                InstanceData.updateValueValid(currentNodeInfo, false, bind.getId());
            }
        }

        // Bail is we are already invalid
        if (!isValid) {
            // Remember invalid instances
            final XFormsInstance instanceForNodeInfo = containingDocument.getInstanceForNode(currentNodeInfo);
            invalidInstances.put(instanceForNodeInfo.getEffectiveId(), "");
            return;
        }

        // Handle XPath constraint MIP

        // NOTE: We evaluate the constraint here, so that if the type is not respected the constraint is not evaluated.
        // This can also prevent XPath errors, e.g.: <xforms:bind nodeset="foobar" type="xs:integer" constraint=". > 10"/>
        if (bind.getConstraint() != null) {
            // Evaluate constraint
            try {
                // Get MIP value
                final boolean valid = evaluateBooleanExpression1(propertyContext, bind, bind.getConstraint(), nodeset, position, getVariables(currentNodeInfo));

                // Update node with MIP value
                isValid &= valid;
                // TODO: why do we allow calling this with valid == true?
                InstanceData.updateValueValid(currentNodeInfo, valid, bind.getId());
            } catch (Exception e) {
                final ValidationException ve = ValidationException.wrapException(e, new ExtendedLocationData(bind.getLocationData(), "evaluating XForms constraint bind",
                        bind.getBindElement(), new String[] { "expression", bind.getConstraint() }));

                container.dispatchEvent(propertyContext, new XFormsComputeExceptionEvent(model, ve.getMessage(), ve));
            }
        }

        // Remember invalid instances
        if (!isValid) {
            final XFormsInstance instanceForNodeInfo = containingDocument.getInstanceForNode(currentNodeInfo);
            invalidInstances.put(instanceForNodeInfo.getEffectiveId(), "");
        }
    }

    private static interface BindRunner {
        public void applyBind(PropertyContext propertyContext, Bind bind, List<Item> nodeset, int position);
    }

    private class Bind {

        private Element bindElement;
        private String id;          // bind id
        private String name;        // bind name
        private List<Item> nodeset;       // actual nodeset for this bind

        private List<BindIteration> childrenIterations; // List<BindIteration>
        private Map<String, String> customMips;         // Map<String name, String expression> where: foo:bar="true()" => "foo-bar" -> "true()"

        public Bind(PropertyContext propertyContext, Element bindElement, boolean isSingleNodeContext) {
            this.bindElement = bindElement;
            this.id = bindElement.attributeValue(XFormsConstants.ID_QNAME);
            this.name = bindElement.attributeValue(XFormsConstants.NAME_QNAME);

            // Remember variables
            if (name != null)
                variableNamesToIds.put(name, id);

            // If this bind is marked for offline handling, remember it
            if ("true".equals(bindElement.attributeValue(XFormsConstants.XXFORMS_OFFLINE_QNAME)))
                offlineBinds.add(this);

            // Remember custom MIPs
            {
                for (Iterator iterator = bindElement.attributeIterator(); iterator.hasNext();) {
                    final Attribute attribute = (Attribute) iterator.next();
                    final QName attributeQName = attribute.getQName();
                    final String attributePrefix = attributeQName.getNamespacePrefix();
                    final String attributeURI = attributeQName.getNamespaceURI();
                    // NOTE: Also allow for xxforms:events-mode extension MIP
                    if (attributePrefix != null && attributePrefix.length() > 0
                            && !(attributeURI.equals(XFormsConstants.XFORMS_NAMESPACE_URI)
                                     || (attributeURI.equals(XFormsConstants.XXFORMS_NAMESPACE_URI)
                                            && !attributeQName.getName().equals(XFormsConstants.XXFORMS_EVENT_MODE_QNAME.getName()))
                                     || attributePrefix.startsWith("xml"))) {
                        // Any QName-but-not-NCName which is not in the xforms or xxforms namespace
                        if (customMips == null)
                            customMips = new HashMap<String, String>();
                        // E.g. foo:bar="true()" => "foo-bar" -> "true()"
                        customMips.put(attribute.getQualifiedName().replace(':', '-'), attribute.getValue());
                    }
                }
            }

            // Compute nodeset for this bind
            model.getContextStack().pushBinding(propertyContext, bindElement);
            {
                // NOTE: This should probably go into XFormsContextStack
                if (model.getContextStack().getCurrentBindingContext().isNewBind()) {
                    // Case where a @nodeset or @ref attribute is present -> a current nodeset is therefore available
                    // NOTE: @ref is not supported by XForms 1.1, but it probably should!
                    this.nodeset = model.getContextStack().getCurrentNodeset();
                } else {
                    // Case where of missing @nodeset attribute (it is optional in XForms 1.1 and defaults to the context item)
                    final Item contextItem = model.getContextStack().getContextItem();
                    this.nodeset = (contextItem == null) ? XFormsConstants.EMPTY_ITEM_LIST : Collections.singletonList(contextItem);
                }
                final int nodesetSize = this.nodeset.size();

                // "4.7.2 References to Elements within a bind Element [...] If a target bind element is outermost, or if
                // all of its ancestor bind elements have nodeset attributes that select only one node, then the target bind
                // only has one associated bind object, so this is the desired target bind object whose nodeset is used in
                // the Single Node Binding or Node Set Binding"
                if (isSingleNodeContext)
                    singleNodeContextBinds.put(id, this);

                final List<Element> childElements = Dom4jUtils.elements(bindElement, XFormsConstants.XFORMS_BIND_QNAME);
                if (childElements.size() > 0) {
                    // There are children binds
                    childrenIterations = new ArrayList<BindIteration>();

                    // Iterate over nodeset and produce child iterations
                    for (int currentPosition = 1; currentPosition <= nodesetSize; currentPosition++) {
                        model.getContextStack().pushIteration(currentPosition);
                        {
                            // Create iteration and remember it
                            final boolean isNewSingleNodeContext = isSingleNodeContext && nodesetSize == 1;
                            final BindIteration currentBindIteration = new BindIteration(propertyContext, isNewSingleNodeContext, childElements);
                            childrenIterations.add(currentBindIteration);

                            // Create mapping context node -> iteration
                            final NodeInfo iterationNodeInfo = (NodeInfo) nodeset.get(currentPosition - 1);
                            List<BindIteration> iterations = iterationsForContextNodeInfo.get(iterationNodeInfo);
                            if (iterations == null) {
                                iterations = new ArrayList<BindIteration>();
                                iterationsForContextNodeInfo.put(iterationNodeInfo, iterations);
                            }
                            iterations.add(currentBindIteration);
                        }
                        model.getContextStack().popBinding();
                    }
                }
            }
            model.getContextStack().popBinding();
        }

        public void applyBinds(PropertyContext propertyContext, BindRunner bindRunner) {
            if (nodeset != null && nodeset.size() > 0) {
                // Handle each node in this node-set
                final Iterator<BindIteration> j = (childrenIterations != null) ? childrenIterations.iterator() : null;

                for (int index = 1; index <= nodeset.size(); index++) {
                    final BindIteration currentBindIteration = (j != null) ? j.next() : null;

                    // Handle current node
                    bindRunner.applyBind(propertyContext, this, nodeset, index);

                    // Handle children iterations if any
                    if (currentBindIteration != null) {
                        currentBindIteration.applyBinds(propertyContext, bindRunner);
                    }
                }
            }
        }

        public String getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public List<Item> getNodeset() {
            return nodeset;
        }

        public LocationData getLocationData() {
            return new ExtendedLocationData((LocationData) bindElement.getData(), "xforms:bind element", bindElement);
        }

        public Element getBindElement() {
            return bindElement;
        }

//        public Map getNamespaceMappings() {
//            containingDocument.getNamespaceMappings(model.getPrefix(), getId());
//        }

        public String getRelevant() {
            return bindElement.attributeValue(XFormsConstants.RELEVANT_QNAME);
        }

        public String getCalculate() {
            return bindElement.attributeValue(XFormsConstants.CALCULATE_QNAME);
        }

        public String getType() {
            return bindElement.attributeValue(XFormsConstants.TYPE_QNAME);
        }

        public String getConstraint() {
            return bindElement.attributeValue(XFormsConstants.CONSTRAINT_QNAME);
        }

        public String getRequired() {
            return bindElement.attributeValue(XFormsConstants.REQUIRED_QNAME);
        }

        public String getReadonly() {
            return bindElement.attributeValue(XFormsConstants.READONLY_QNAME);
        }

        public String getXXFormsDefault() {
            return bindElement.attributeValue(XFormsConstants.XXFORMS_DEFAULT_QNAME);
        }

        public Map<String, String> getCustomMips() {
            return customMips;
        }
    }

    private class BindIteration {

        private List<Bind> childrenBinds;

        public BindIteration(PropertyContext propertyContext, boolean isSingleNodeContext, List<Element> childElements) {

            if (childElements.size() > 0) {
                // There are child elements
                childrenBinds = new ArrayList<Bind>();

                // Iterate over child elements and create children binds
                for (Element currentBindElement: childElements) {
                    final Bind currentBind = new Bind(propertyContext, currentBindElement, isSingleNodeContext);
                    childrenBinds.add(currentBind);
                }
            }
        }

        public void applyBinds(PropertyContext propertyContext, BindRunner bindRunner) {
            for (final Bind currentBind: childrenBinds) {
                currentBind.applyBinds(propertyContext, bindRunner);
            }
        }

        public Bind getBind(String bindId) {
            for (final Bind currentBind: childrenBinds) {
                if (currentBind.getId().equals(bindId))
                    return currentBind;
            }
            return null;
        }
    }
}
