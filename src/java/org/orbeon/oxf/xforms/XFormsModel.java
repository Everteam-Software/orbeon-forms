/**
 * Copyright (C) 2009 Orbeon, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU Lesser General Public License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * The full text of the license is available at http://www.gnu.org/copyleft/lesser.html
 */
package org.orbeon.oxf.xforms;

import org.dom4j.Document;
import org.dom4j.Element;
import org.orbeon.oxf.common.OXFException;
import org.orbeon.oxf.common.ValidationException;
import org.orbeon.oxf.pipeline.api.ExternalContext;
import org.orbeon.oxf.pipeline.api.PipelineContext;
import org.orbeon.oxf.processor.ProcessorImpl;
import org.orbeon.oxf.resources.URLFactory;
import org.orbeon.oxf.util.*;
import org.orbeon.oxf.xforms.control.XFormsControl;
import org.orbeon.oxf.xforms.control.XFormsSingleNodeControl;
import org.orbeon.oxf.xforms.control.controls.XFormsRepeatIterationControl;
import org.orbeon.oxf.xforms.event.*;
import org.orbeon.oxf.xforms.event.events.*;
import org.orbeon.oxf.xforms.function.xxforms.XXFormsExtractDocument;
import org.orbeon.oxf.xforms.processor.XFormsServer;
import org.orbeon.oxf.xforms.submission.OptimizedSubmission;
import org.orbeon.oxf.xforms.submission.XFormsModelSubmission;
import org.orbeon.oxf.xforms.xbl.XBLContainer;
import org.orbeon.oxf.xml.TransformerUtils;
import org.orbeon.oxf.xml.dom4j.Dom4jUtils;
import org.orbeon.oxf.xml.dom4j.ExtendedLocationData;
import org.orbeon.oxf.xml.dom4j.LocationData;
import org.orbeon.saxon.dom4j.NodeWrapper;
import org.orbeon.saxon.om.DocumentInfo;
import org.orbeon.saxon.om.Navigator;
import org.orbeon.saxon.om.NodeInfo;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.*;

/**
 * Represents an XForms model.
 */
public class XFormsModel implements XFormsEventTarget, XFormsEventObserver, XFormsObjectResolver {

    private Document modelDocument;

    // Model attributes
    private String staticId;
    private String prefixedId;
    private String effectiveId;

    // Instances
    private List<String> instanceIds;
    private List<XFormsInstance> instances;
    private Map<String, XFormsInstance> instancesMap;   // Map<String instanceStaticId, XFormsInstance>

    // Submissions
    private Map<String, XFormsModelSubmission> submissions;    // Map<String submissionStaticId, XFormsModelSubmission>

    // Binds
    private XFormsModelBinds binds;
    private boolean mustBindValidate;

    // Schema validation
    private XFormsModelSchemaValidator schemaValidator;
    private boolean mustSchemaValidate;

    // Container
    private XBLContainer container;
    private XFormsContextStack contextStack;    // context stack for evaluation, used by binds, submissions, event handlers

    // Containing document
    private XFormsContainingDocument containingDocument;
    
    // Logging
    private final IndentedLogger connectionLogger;
    private final boolean logBody;

    public XFormsModel(XBLContainer container, String effectiveId, Document modelDocument) {

        // Set container
        this.container = container;
        this.containingDocument = container.getContainingDocument();

        // Initialize instance logging
        if (XFormsModelSubmission.logger.isDebugEnabled()) {
            // Create new indented logger just for the Connection object. This will log more stuff.
            // NOTE: Use the XFormsModelSubmission logger for this, for consistency with submissions which want to
            // unify with instance loading anyway.
            connectionLogger = new IndentedLogger(XFormsModelSubmission.logger, "XForms submission (synchronous)",
                    containingDocument.getIndentedLogger().getLogIndentLevel());
            logBody = true;
        } else {
            // Use regular logger
            connectionLogger = containingDocument.getIndentedLogger();
            logBody = false;
        }
        
        // Remember document
        this.modelDocument = modelDocument;

        // Basic check trying to make sure this is an XForms model
        // TODO: should rather use schema here or when obtaining document passed to this constructor
        final Element modelElement = modelDocument.getRootElement();
        final String rootNamespaceURI = modelElement.getNamespaceURI();
        if (!rootNamespaceURI.equals(XFormsConstants.XFORMS_NAMESPACE_URI))
            throw new ValidationException("Root element of XForms model must be in namespace '"
                    + XFormsConstants.XFORMS_NAMESPACE_URI + "'. Found instead: '" + rootNamespaceURI + "'",
                    (LocationData) modelElement.getData());

        staticId = modelElement.attributeValue("id");
        this.effectiveId = effectiveId;

        // Extract list of instances ids
        {
            final List<Element> instanceContainers = Dom4jUtils.elements(modelElement, XFormsConstants.XFORMS_INSTANCE_QNAME);
            instanceIds = new ArrayList<String>(instanceContainers.size());
            for (Element instanceContainer: instanceContainers) {
                final String instanceId = XFormsInstance.getInstanceStaticId(instanceContainer);
                instanceIds.add(instanceId);
            }
        }

        // Get <xforms:submission> elements (may be missing)
        {
            final List<Element> submissionElements = Dom4jUtils.elements(modelElement, XFormsConstants.XFORMS_SUBMISSION_QNAME);
            for (Element submissionElement: submissionElements) {
                final String submissionId = submissionElement.attributeValue("id");

                if (this.submissions == null)
                    this.submissions = new HashMap<String, XFormsModelSubmission>();

                this.submissions.put(submissionId, new XFormsModelSubmission(this.container, submissionId, submissionElement, this));
            }
        }

        // Create binds object
        binds = XFormsModelBinds.create(this);
        mustBindValidate = binds != null;

        // Create context stack
        this.contextStack = new XFormsContextStack(this);
    }

    public void updateEffectiveId(String effectiveId) {
        this.effectiveId = effectiveId;

        // Update effective ids of all nested instances
        if (instances != null) {
            for (XFormsInstance currentInstance: instances) {
                // NOTE: we pass the new model id, not the instance id
                currentInstance.updateModelEffectiveId(effectiveId);
            }
        }
    }

    public String getPrefixedId() {
        if (prefixedId == null) {
            prefixedId = XFormsUtils.getEffectiveIdNoSuffix(effectiveId);
        }
        return prefixedId;
    }

    public XFormsContextStack getContextStack() {
        return contextStack;
    }

    public XBLContainer getXBLContainer() {
        return container;
    }

    public XBLContainer getXBLContainer(XFormsContainingDocument containingDocument) {
        return getXBLContainer();
    }

    public XFormsContainingDocument getContainingDocument() {
        return containingDocument;
    }

    public Document getModelDocument() {
        return modelDocument;
    }

    /**
     * Get object with the id specified.
     */
    public Object getObjectByEffectiveId(String effectiveId) {

        // If prefixes or suffixes don't match, object can't be found here
        if (!getXBLContainer().getFullPrefix().equals(XFormsUtils.getEffectiveIdPrefix(effectiveId))
                || !XFormsUtils.getEffectiveIdSuffix(getXBLContainer().getEffectiveId()).equals(XFormsUtils.getEffectiveIdSuffix(effectiveId))) {
            return null;
        }

        // Find by static id
        return resolveObjectById(null, XFormsUtils.getStaticIdFromId(effectiveId));
    }

    /**
     * Resolve an object. This optionally depends on a source, and involves resolving whether the source is within a
     * repeat or a component.
     *
     * @param sourceEffectiveId  effective id of the source, or null
     * @param targetStaticId     static id of the target
     * @return                   object, or null if not found
     */
    public Object resolveObjectById(String sourceEffectiveId, String targetStaticId) {

        if (targetStaticId.indexOf(XFormsConstants.COMPONENT_SEPARATOR) != -1 || targetStaticId.indexOf(XFormsConstants.REPEAT_HIERARCHY_SEPARATOR_1) != -1)
            throw new OXFException("Target id must be static id: " + targetStaticId);

        // Check this id
        if (targetStaticId.equals(getId()))
            return this;

        // Search instances
        if (instancesMap != null) {
            final XFormsInstance instance = instancesMap.get(targetStaticId);
            if (instance != null)
                return instance;
        }

        // Search submissions
        if (submissions != null) {
            final XFormsModelSubmission resultSubmission = submissions.get(targetStaticId);
            if (resultSubmission != null)
                return resultSubmission;
        }

        return null;
    }

    /**
     * Return the default instance for this model, i.e. the first instance. Return null if there is
     * no instance in this model.
     *
     * @return  XFormsInstance or null
     */
    public XFormsInstance getDefaultInstance() {
        return (instances != null && instances.size() > 0) ? instances.get(0) : null;
    }

    /**
     * Return the id of the default instance for this model. Return null if there is no instance in this model.
     *
     * @return  instance id or null
     */
    public String getDefaultInstanceId() {
        return (instanceIds != null && instanceIds.size() > 0) ? instanceIds.get(0) : null;
    }

    /**
     * Return all XFormsInstance objects for this model, in the order they appear in the model.
     */
    public List<XFormsInstance> getInstances() {
        return instances;
    }

    /**
     * Return the number of instances in this model.
     */
    public int getInstanceCount() {
        return instanceIds.size();
    }

    /**
     * Return the XFormsInstance with given id, null if not found.
     */
    public XFormsInstance getInstance(String instanceStaticId) {
        return (instancesMap == null) ? null : instancesMap.get(instanceStaticId);
    }

    /**
     * Return the XFormsInstance object containing the given node.
     */
    public XFormsInstance getInstanceForNode(NodeInfo nodeInfo) {

        final DocumentInfo documentInfo = nodeInfo.getDocumentRoot();

        if (instances != null) {
            for (XFormsInstance currentInstance: instances) {
                if (currentInstance.getDocumentInfo().isSameNodeInfo(documentInfo))
                    return currentInstance;
            }
        }

        return null;
    }

    /**
     * Set an instance document for this model. There may be multiple instance documents. Each instance document may
     * have an associated id that identifies it.
     */
    public XFormsInstance setInstanceDocument(Object instanceDocument, String modelEffectiveId, String instanceStaticId, String instanceSourceURI,
                                              String username, String password, boolean cached, long timeToLive, String validation, boolean handleXInclude) {
        // Initialize containers if needed
        if (instances == null) {
            instances = Arrays.asList(new XFormsInstance[instanceIds.size()]);
            instancesMap = new HashMap<String, XFormsInstance>(instanceIds.size());
        }
        // Prepare and set instance
        final int instancePosition = instanceIds.indexOf(instanceStaticId);
        final XFormsInstance newInstance;
        {
            if (instanceDocument instanceof Document) {
                newInstance = new XFormsInstance(modelEffectiveId, instanceStaticId, (Document) instanceDocument, instanceSourceURI,
                        username, password, cached, timeToLive, validation, handleXInclude, XFormsProperties.isExposeXPathTypes(containingDocument));
            } else if (instanceDocument instanceof DocumentInfo) {
                newInstance = new ReadonlyXFormsInstance(modelEffectiveId, instanceStaticId, (DocumentInfo) instanceDocument, instanceSourceURI,
                        username, password, cached, timeToLive, validation, handleXInclude, XFormsProperties.isExposeXPathTypes(containingDocument));
            } else {
                throw new OXFException("Invalid type for instance document: " + instanceDocument.getClass().getName());
            }
        }
        instances.set(instancePosition, newInstance);

        // Create mapping instance id -> instance
        if (instanceStaticId != null)
            instancesMap.put(instanceStaticId, newInstance);

        return newInstance;
    }

    /**
     * Set an instance. The id of the instance must exist in the model.
     *
     * @param instance          XFormsInstance to set
     * @param replaced          whether this is an instance replacement (as result of a submission)
     */
    private void setInstance(XFormsInstance instance, boolean replaced) {

        // Mark the instance as replaced if needed
        instance.setReplaced(replaced);

        // Initialize containers if needed
        if (instances == null) {
            instances = Arrays.asList(new XFormsInstance[instanceIds.size()]);
            instancesMap = new HashMap<String, XFormsInstance>(instanceIds.size());
        }
        // Prepare and set instance
        final String instanceId = instance.getId();// use static id as instanceIds contains static ids
        final int instancePosition = instanceIds.indexOf(instanceId);

        instances.set(instancePosition, instance);

        // Create mapping instance id -> instance
        instancesMap.put(instanceId, instance);
    }

    public String getId() {
        return staticId;
    }

    public String getEffectiveId() {
        return effectiveId;
    }

    public LocationData getLocationData() {
        return (LocationData) modelDocument.getRootElement().getData();
    }

    public XFormsModelBinds getBinds() {
        return binds;
    }

    public XFormsModelSchemaValidator getSchemaValidator() {
        return schemaValidator;
    }

    private void loadSchemasIfNeeded(PropertyContext propertyContext) {
        if (schemaValidator == null) {
            if (!XFormsProperties.isSkipSchemaValidation(containingDocument)) {
                final Element modelElement = modelDocument.getRootElement();
                schemaValidator = new XFormsModelSchemaValidator(modelElement);
                schemaValidator.loadSchemas(propertyContext);

                mustSchemaValidate = schemaValidator.hasSchema();
            }
        }
    }

    public String[] getSchemaURIs() {
        if (schemaValidator != null) {
            return schemaValidator.getSchemaURIs();
        } else {
            return null;
        }
    }

    /**
     * Restore the state of the model when the model object was just recreated.
     *
     * @param propertyContext   current context
     */
    public void restoreState(PropertyContext propertyContext) {
        // Ensure schema are loaded
        loadSchemasIfNeeded(propertyContext);

        // Restore instances
        restoreInstances(propertyContext);

        // Refresh binds, but do not recalculate (only evaluate "computed expression binds")
        deferredActionContext.rebuild = true;
        deferredActionContext.revalidate = true;

        doRebuild(propertyContext);
        if (binds != null)
            binds.applyComputedExpressionBinds(propertyContext);
        doRevalidate(propertyContext);

        synchronizeInstanceDataEventState();
    }

    /**
     * Serialize this model's instances.
     *
     * @param instancesElement  container element for serialized instances
     */
    public void serializeInstances(Element instancesElement) {
        if (instances != null) {
            for (XFormsInstance currentInstance: instances) {

                // TODO: can we avoid storing the instance in the dynamic state if it has not changed from static state?

                final boolean isReadonlyNonReplacedInline = currentInstance.isReadOnly() && !currentInstance.isReplaced() && currentInstance.getSourceURI() == null;
                if (!isReadonlyNonReplacedInline) {
                    // Serialize full instance of instance metadata (latter if instance is cached)
                    // If it is readonly, not replaced, and inline, then don't even add information to the dynamic state

                    instancesElement.add(currentInstance.createContainerElement(!currentInstance.isCache()));

                    containingDocument.logDebug("serialize", currentInstance.isCache() ? "storing instance metadata to dynamic state" : "storing full instance to dynamic state",
                        "model effective id", effectiveId, "instance static id", currentInstance.getId());

                    // Log instance if needed
                    currentInstance.logIfNeeded(getContainingDocument(), "serialized instance");
                }
            }
        }
    }

    /**
     * Restore all the instances serialized as children of the given container element.
     *
     * @param propertyContext   current context
     */
    private void restoreInstances(PropertyContext propertyContext) {

        // Find serialized instances from context
        final Element instancesElement = (Element) propertyContext.getAttribute(XBLContainer.XFORMS_DYNAMIC_STATE_RESTORE_INSTANCES);

        // Get instances from dynamic state first
        if (instancesElement != null) {
            for (Element currentInstanceElement: Dom4jUtils.elements(instancesElement)) {
                // Check that the instance belongs to this model
                final String currentModelEffectiveId = currentInstanceElement.attributeValue("model-id");
                if (effectiveId.equals(currentModelEffectiveId)) {
                    // Create and set instance document on current model
                    final XFormsInstance newInstance = new XFormsInstance(currentInstanceElement);
                    final boolean isReadonlyHint = XFormsInstance.isReadonlyHint(currentInstanceElement);
                    // NOTE: Here instance must contain document
                    setInstanceLoadFromCacheIfNecessary(propertyContext, isReadonlyHint, newInstance, null);
                    containingDocument.logDebug("restore", "restoring instance from dynamic state", "model effective id", effectiveId, "instance static id", newInstance.getId());
                }
            }
        }

        // Then get instances from static state if necessary
        // This can happen if the instance is inline, readonly, and not replaced
        for (Element containerElement: containingDocument.getStaticState().getInstanceContainers(getPrefixedId())) {
            final String instanceStaticId = XFormsInstance.getInstanceStaticId(containerElement);
            if (instancesMap.get(instanceStaticId) == null) {
                // Must create instance

                final String xxformsExcludeResultPrefixes = containerElement.attributeValue(XFormsConstants.XXFORMS_EXCLUDE_RESULT_PREFIXES);
                final List<Element> children = Dom4jUtils.elements(containerElement);

                final boolean isReadonlyHint = XFormsInstance.isReadonlyHint(containerElement);
                final String xxformsValidation = containerElement.attributeValue(XFormsConstants.XXFORMS_VALIDATION_QNAME);

                // Extract document
                final Object instanceDocument = XXFormsExtractDocument.extractDocument(children.get(0), xxformsExcludeResultPrefixes, isReadonlyHint);

                // Set instance and associated information
                setInstanceDocument(instanceDocument, effectiveId, instanceStaticId, null, null, null, false, -1, xxformsValidation, false);
            }
        }
    }

    public void performDefaultAction(final PropertyContext propertyContext, XFormsEvent event) {
        final String eventName = event.getEventName();
        if (XFormsEvents.XFORMS_MODEL_CONSTRUCT.equals(eventName)) {
            // 4.2.1 The xforms-model-construct Event
            // Bubbles: Yes / Cancelable: No / Context Info: None
            doModelConstruct(propertyContext);
        } else if (XFormsEvents.XXFORMS_READY.equals(eventName)) {
            // This is called after xforms-ready events have been dispatched to all models
            doAfterReady();
        } else if (XFormsEvents.XFORMS_MODEL_CONSTRUCT_DONE.equals(eventName)) {
            // 4.2.2 The xforms-model-construct-done Event
            // Bubbles: Yes / Cancelable: No / Context Info: None
            // TODO: implicit lazy instance construction
        } else if (XFormsEvents.XFORMS_REBUILD.equals(eventName)) {
            // 4.3.7 The xforms-rebuild Event
            // Bubbles: Yes / Cancelable: Yes / Context Info: None
            doRebuild(propertyContext);
        } else if (XFormsEvents.XFORMS_RECALCULATE.equals(eventName)) {
            // 4.3.6 The xforms-recalculate Event
            // Bubbles: Yes / Cancelable: Yes / Context Info: None
            doRecalculate(propertyContext);
        } else if (XFormsEvents.XFORMS_REVALIDATE.equals(eventName)) {
            // 4.3.5 The xforms-revalidate Event
            // Bubbles: Yes / Cancelable: Yes / Context Info: None
            doRevalidate(propertyContext);
        } else if (XFormsEvents.XFORMS_REFRESH.equals(eventName)) {
            // 4.3.4 The xforms-refresh Event
            // Bubbles: Yes / Cancelable: Yes / Context Info: None
            doRefresh(propertyContext);
        } else if (XFormsEvents.XFORMS_RESET.equals(eventName)) {
            // 4.3.8 The xforms-reset Event
            // Bubbles: Yes / Cancelable: Yes / Context Info: None
            doReset(propertyContext);
        } else if (XFormsEvents.XFORMS_COMPUTE_EXCEPTION.equals(eventName) || XFormsEvents.XFORMS_LINK_EXCEPTION.equals(eventName)) {
            // 4.5.4 The xforms-compute-exception Event
            // Bubbles: Yes / Cancelable: No / Context Info: Implementation-specific error string.
            // The default action for this event results in the following: Fatal error.

            // 4.5.2 The xforms-link-exception Event
            // Bubbles: Yes / Cancelable: No / Context Info: The URI that failed to load (xsd:anyURI)
            // The default action for this event results in the following: Fatal error.

            final XFormsExceptionEvent exceptionEvent = (XFormsExceptionEvent) event;
            final Throwable throwable = exceptionEvent.getThrowable();
            if (throwable instanceof RuntimeException)
                throw (RuntimeException) throwable;
            else
                throw new ValidationException("Received fatal error event: " + eventName, throwable, (LocationData) modelDocument.getRootElement().getData());
        }
    }

    private void doReset(PropertyContext propertyContext) {
        // TODO
        // "The instance data is reset to the tree structure and values it had immediately
        // after having processed the xforms-ready event."

        // "Then, the events xforms-rebuild, xforms-recalculate, xforms-revalidate and
        // xforms-refresh are dispatched to the model element in sequence."
        container.dispatchEvent(propertyContext, new XFormsRebuildEvent(XFormsModel.this));
        container.dispatchEvent(propertyContext, new XFormsRecalculateEvent(XFormsModel.this));
        container.dispatchEvent(propertyContext, new XFormsRevalidateEvent(XFormsModel.this));
        container.dispatchEvent(propertyContext, new XFormsRefreshEvent(XFormsModel.this));
    }

    private void doAfterReady() {
    }

    private void doModelConstruct(PropertyContext propertyContext) {
        final Element modelElement = modelDocument.getRootElement();

        // 1. All XML Schema loaded (throws xforms-link-exception)

        loadSchemasIfNeeded(propertyContext);
        // TODO: throw exception event

        // 2. Create XPath data model from instance (inline or external) (throws xforms-link-exception)
        //    Instance may not be specified.

        if (instances == null) {
            instances = Arrays.asList(new XFormsInstance[instanceIds.size()]);
            instancesMap = new HashMap<String, XFormsInstance>(instanceIds.size());
        }
        {
            // Build initial instance documents
            final List<Element> instanceContainers = Dom4jUtils.elements(modelElement, XFormsConstants.XFORMS_INSTANCE_QNAME);
            if (instanceContainers.size() > 0) {
                // Iterate through all instances
                int instancePosition = 0;
                for (Element containerElement : instanceContainers) {
                    // Skip processing in case somebody has already set this particular instance
                    if (instances.get(instancePosition++) != null) {
                        // NOP
                    } else {
                        // Did not get the instance from static state

                        final LocationData locationData = (LocationData) containerElement.getData();
                        final String instanceStaticId = XFormsInstance.getInstanceStaticId(containerElement);
                        final boolean isReadonlyHint = XFormsInstance.isReadonlyHint(containerElement);
                        final boolean isCacheHint = XFormsInstance.isCacheHint(containerElement);
                        final long xxformsTimeToLive = XFormsInstance.getTimeToLive(containerElement);
                        final String xxformsValidation = containerElement.attributeValue(XFormsConstants.XXFORMS_VALIDATION_QNAME);

                        // Load instance. This might throw an exception event (and therefore a Java exception) in case of fatal problem.
                        loadInstance(propertyContext, containerElement, instanceStaticId, isReadonlyHint, isCacheHint, xxformsTimeToLive, xxformsValidation, locationData);
                    }
                }
            }
        }

        // 3. P3P (N/A)

        // 4. Instance data is constructed. Evaluate binds:
        //    a. Evaluate nodeset
        //    b. Apply model item properties on nodes
        //    c. Throws xforms-binding-exception if the node has already model item property with same name
        // TODO: a, b, c

        // 5. xforms-rebuild, xforms-recalculate, xforms-revalidate
        deferredActionContext.rebuild = true;
        deferredActionContext.recalculate = true;
        deferredActionContext.revalidate = true;

        doRebuild(propertyContext);
        doRecalculate(propertyContext);
        doRevalidate(propertyContext);

        synchronizeInstanceDataEventState();
    }

    private void setInstanceLoadFromCacheIfNecessary(PropertyContext propertyContext, boolean readonlyHint, XFormsInstance newInstance, Element locationDataElement) {
        if (newInstance.getDocumentInfo() == null && newInstance.getSourceURI() != null) {
            // Instance not initialized yet and must be loaded from URL

            // This means that the instance was cached
            if (!newInstance.isCache())
                throw new ValidationException("Non-initialized instance has to be cacheable for id: " + newInstance.getEffectiveId(),
                        (locationDataElement != null) ? (LocationData) locationDataElement.getData() : getLocationData());

            if (XFormsServer.logger.isDebugEnabled())
                containingDocument.logDebug("model", "using instance from instance cache (instance was not initialized)",
                        "id", newInstance.getEffectiveId());

            // NOTE: No XInclude supported to read instances with @src for now
            final XFormsInstance cachedInstance
                    = XFormsServerSharedInstancesCache.instance().findConvert(propertyContext, containingDocument.getIndentedLogger(),
                        newInstance.getId(), newInstance.getEffectiveModelId(), newInstance.getSourceURI(), null, readonlyHint, false,
                        XFormsProperties.isExposeXPathTypes(containingDocument), newInstance.getTimeToLive(), newInstance.getValidation(), INSTANCE_LOADER);

            setInstance(cachedInstance, newInstance.isReplaced());
        } else {
            // Instance is initialized, just use it

            // This means that the instance was not cached
            if (newInstance.isCache())
                throw new ValidationException("Initialized instance has to be non-cacheable for id: " + newInstance.getEffectiveId(),
                        (locationDataElement != null) ? (LocationData) locationDataElement.getData() : getLocationData());

            if (XFormsServer.logger.isDebugEnabled())
                containingDocument.logDebug("model", "using initialized instance from state",
                        "id", newInstance.getEffectiveId());

            setInstance(newInstance, newInstance.isReplaced());
        }
    }

    private void loadInstance(PropertyContext propertyContext, Element instanceContainer, String instanceStaticId, boolean readonlyHint, boolean isCacheHint, long xxformsTimeToLive, String xxformsValidation, LocationData locationData) {
        containingDocument.startHandleOperation("model", "loading instance",
                "instance id", instanceContainer.attributeValue("id"));
        {
            // Get instance resource URI, can be from @src or @resource

            final String srcAttribute = instanceContainer.attributeValue("src");
            final String resourceAttribute = instanceContainer.attributeValue("resource");

            final List<Element> children = Dom4jUtils.elements(instanceContainer);
            if (srcAttribute != null) {
                // "If the src attribute is given, then it takes precedence over inline content and the resource
                // attribute, and the XML data for the instance is obtained from the link."

                if (srcAttribute.trim().equals("")) {
                    // Got a blank src attribute, just dispatch xforms-link-exception
                    final LocationData extendedLocationData = new ExtendedLocationData(locationData, "processing XForms instance", instanceContainer);
                    final Throwable throwable = new ValidationException("Invalid blank URL specified for instance: " + instanceStaticId, extendedLocationData);
                    container.dispatchEvent(propertyContext, new XFormsLinkExceptionEvent(XFormsModel.this, srcAttribute, instanceContainer, throwable));
                }

                // Load instance
                loadExternalInstance(propertyContext, instanceContainer, instanceStaticId, srcAttribute, locationData, readonlyHint, isCacheHint, xxformsTimeToLive, xxformsValidation);
            } else if (children != null && children.size() >= 1) {
                // "If the src attribute is omitted, then the data for the instance is obtained from inline content if
                // it is given or the resource attribute otherwise. If both the resource attribute and inline content
                // are provided, the inline content takes precedence."

                final String xxformsExcludeResultPrefixes = instanceContainer.attributeValue(XFormsConstants.XXFORMS_EXCLUDE_RESULT_PREFIXES);

                if (children.size() > 1) {
                    final LocationData extendedLocationData = new ExtendedLocationData(locationData, "processing XForms instance", instanceContainer);
                    final Throwable throwable = new ValidationException("xforms:instance element must contain exactly one child element", extendedLocationData);
                    container.dispatchEvent(propertyContext, new XFormsLinkExceptionEvent(XFormsModel.this, null, instanceContainer, throwable));
                }

                try {
                    // Extract document
                    final Object instanceDocument = XXFormsExtractDocument.extractDocument((Element) children.get(0), xxformsExcludeResultPrefixes, readonlyHint);

                    // Set instance and associated information if everything went well
                    // NOTE: No XInclude supported to read instances with @src for now
                    setInstanceDocument(instanceDocument, effectiveId, instanceStaticId, null, null, null, false, -1, xxformsValidation, false);
                } catch (Exception e) {
                    final LocationData extendedLocationData = new ExtendedLocationData(locationData, "processing XForms instance", instanceContainer);
                    final Throwable throwable = new ValidationException("Error extracting or setting inline instance", extendedLocationData);
                    container.dispatchEvent(propertyContext, new XFormsLinkExceptionEvent(XFormsModel.this, null, instanceContainer, throwable));
                }
            } else if (resourceAttribute != null) {
                // "the data for the instance is obtained from inline content if it is given or the
                // resource attribute otherwise"

                // Load instance
                loadExternalInstance(propertyContext, instanceContainer, instanceStaticId, resourceAttribute, locationData, readonlyHint, isCacheHint, xxformsTimeToLive, xxformsValidation);
            } else {
                // Everything missing
                final LocationData extendedLocationData = new ExtendedLocationData(locationData, "processing XForms instance", instanceContainer);
                final Throwable throwable = new ValidationException("Required @src attribute, @resource attribute, or inline content for instance: " + instanceStaticId, extendedLocationData);
                container.dispatchEvent(propertyContext, new XFormsLinkExceptionEvent(XFormsModel.this, "", instanceContainer, throwable));
            }
        }
        containingDocument.endHandleOperation();
    }

    private void loadExternalInstance(final PropertyContext propertyContext, Element instanceContainer, final String instanceStaticId,
                                      String instanceResource, LocationData locationData,
                                      boolean readonlyHint, boolean cacheHint, long xxformsTimeToLive, String xxformsValidation) {
        // External instance
        final ExternalContext externalContext = (ExternalContext) propertyContext.getAttribute(PipelineContext.EXTERNAL_CONTEXT);

        // Perform HHRI encoding
        final String instanceResourceHHRI = XFormsUtils.encodeHRRI(instanceResource, true);

        // Resolve to absolute resource path
        final String resourceAbsolutePathOrAbsoluteURL
                = XFormsUtils.resolveServiceURL(propertyContext, instanceContainer, instanceResourceHHRI,
                    ExternalContext.Response.REWRITE_MODE_ABSOLUTE_PATH);

        try {
            if (cacheHint && ProcessorImpl.getProcessorInputSchemeInputName(resourceAbsolutePathOrAbsoluteURL) == null) {
                // Instance 1) has cache hing and 2) is not input:*, so it can be cached
                // NOTE: We don't allow sharing for input:* URLs because this is very likely NOT to make sense

                // TODO: This doesn't handle optimized submissions!

                // Make sure URL is absolute to make it unique
                final String absoluteResolvedURLString; {
                    // TODO: most likely WRONG; should use resolveServiceURL(), right?
                    final URL absoluteResolvedURL = NetUtils.createAbsoluteURL(resourceAbsolutePathOrAbsoluteURL, null, externalContext);
                    absoluteResolvedURLString = absoluteResolvedURL.toExternalForm();
                }

                // NOTE: No XInclude supported to read instances with @src for now
                final XFormsInstance sharedXFormsInstance
                        = XFormsServerSharedInstancesCache.instance().findConvert(propertyContext, containingDocument.getIndentedLogger(),
                            instanceStaticId, effectiveId,
                            absoluteResolvedURLString, null, readonlyHint, false, XFormsProperties.isExposeXPathTypes(containingDocument),
                            xxformsTimeToLive, xxformsValidation, INSTANCE_LOADER);

                setInstance(sharedXFormsInstance, false);
            } else {
                // Instance cannot be cached

                // NOTE: Optimizing with include() for servlets has limitations, in particular
                // the proper split between servlet path and path info is not done.
                final ExternalContext.Request request = externalContext.getRequest();
                final boolean optimizeLocal =
                        !NetUtils.urlHasProtocol(resourceAbsolutePathOrAbsoluteURL)
                                && (request.getContainerType().equals("portlet")
                                    || request.getContainerType().equals("servlet")
                                       && XFormsProperties.isOptimizeLocalInstanceInclude(containingDocument));

                if (optimizeLocal) {
                    // Use URL resolved against current context
                    final URI resolvedURI = XFormsUtils.resolveXMLBase(instanceContainer, instanceResourceHHRI);
                    loadInstanceOptimized(propertyContext, externalContext, instanceContainer, instanceStaticId, resolvedURI.toString(), readonlyHint, xxformsValidation);
                } else {
                    // Use full resolved resource URL
                    // o absolute URL, e.g. http://example.org/instance.xml
                    // o absolute path relative to server root, e.g. /orbeon/foo/bar/instance.xml
                    loadInstance(externalContext, instanceContainer, instanceStaticId, resourceAbsolutePathOrAbsoluteURL, readonlyHint, xxformsValidation);
                }
            }
        } catch (Exception e) {
            final ValidationException validationException
                = ValidationException.wrapException(e, new ExtendedLocationData(locationData, "reading external instance", instanceContainer));
            container.dispatchEvent(propertyContext, new XFormsLinkExceptionEvent(XFormsModel.this, resourceAbsolutePathOrAbsoluteURL, instanceContainer, validationException));
        }
    }

    private final InstanceLoader INSTANCE_LOADER = new InstanceLoader();

    // TODO: Use XFormsModelSubmission instead of duplicating code here
    private class InstanceLoader implements XFormsServerSharedInstancesCache.Loader {
        public ReadonlyXFormsInstance load(PropertyContext propertyContext, String instanceStaticId, String modelEffectiveId, String instanceSourceURI, boolean handleXInclude, long timeToLive, String validation) {
            final URL sourceURL;
            try {
                sourceURL = URLFactory.createURL(instanceSourceURI);
            } catch (MalformedURLException e) {
                throw new OXFException(e);
            }

            if (XFormsServer.logger.isDebugEnabled())
                containingDocument.logDebug("model", "loading instance into cache", "id", instanceStaticId, "URI", instanceSourceURI);

            final ExternalContext externalContext = (ExternalContext) propertyContext.getAttribute(PipelineContext.EXTERNAL_CONTEXT);
            final ConnectionResult connectionResult = new Connection().open(externalContext,
                    connectionLogger, logBody, Connection.Method.GET.name(), sourceURL, null, null, null, null, null,
                    XFormsProperties.getForwardSubmissionHeaders(containingDocument));

            // Handle connection errors
            if (connectionResult.statusCode != 200) {
                connectionResult.close();
                throw new OXFException("Got invalid return code while loading instance from URI: " + instanceSourceURI + ", " + connectionResult.statusCode);
            }

            try {
                // Read result as XML and create new shared instance
                // TODO: Handle validating?
                final DocumentInfo documentInfo = TransformerUtils.readTinyTree(connectionResult.getResponseInputStream(), connectionResult.resourceURI, handleXInclude);
                return new ReadonlyXFormsInstance(effectiveId, instanceStaticId, documentInfo, instanceSourceURI,
                        null, null, true, timeToLive, validation, handleXInclude, XFormsProperties.isExposeXPathTypes(containingDocument));
            } catch (Exception e) {
                throw new OXFException("Got exception while loading instance from URI: " + instanceSourceURI, e);
            } finally {
                // Clean-up
                connectionResult.close();
            }
        }
    }

    private void loadInstance(ExternalContext externalContext, Element instanceContainer, String instanceId,
                              String resourceAbsolutePathOrAbsoluteURL, boolean isReadonlyHint, String xxformsValidation) {

        // Connect using external protocol

        final URL absoluteResolvedURL;
        final String absoluteResolvedURLString;
        {

            final String inputName = ProcessorImpl.getProcessorInputSchemeInputName(resourceAbsolutePathOrAbsoluteURL);
            if (inputName != null) {
                // URL is input:*, keep it as is
                absoluteResolvedURL = null;
                absoluteResolvedURLString = resourceAbsolutePathOrAbsoluteURL;
            } else {
                // URL is regular URL, make sure it is absolute
                absoluteResolvedURL = NetUtils.createAbsoluteURL(resourceAbsolutePathOrAbsoluteURL, null, externalContext);
                absoluteResolvedURLString = absoluteResolvedURL.toExternalForm();
            }
        }

        // Extension: username and password
        // NOTE: Those don't use AVTs for now, because XPath expressions in those could access
        // instances that haven't been loaded yet.
        final String xxformsUsername = instanceContainer.attributeValue(XFormsConstants.XXFORMS_USERNAME_QNAME);
        final String xxformsPassword = instanceContainer.attributeValue(XFormsConstants.XXFORMS_PASSWORD_QNAME);

        final Object instanceDocument;// Document or DocumentInfo
        if (containingDocument.getURIResolver() == null) {
            // Connect directly if there is no resolver or if the instance is globally cached

            if (XFormsServer.logger.isDebugEnabled())
                containingDocument.logDebug("model", "getting document from URI", "URI", absoluteResolvedURLString);

            final ConnectionResult connectionResult = new Connection().open(externalContext, connectionLogger, logBody,
                    Connection.Method.GET.name(), absoluteResolvedURL, xxformsUsername, xxformsPassword, null, null, null,
                    XFormsProperties.getForwardSubmissionHeaders(containingDocument));

            try {
                // Handle connection errors
                if (connectionResult.statusCode != 200) {
                    throw new OXFException("Got invalid return code while loading instance: " + absoluteResolvedURLString + ", " + connectionResult.statusCode);
                }

                // TODO: Handle validating and XInclude!

                // Read result as XML
                // TODO: use submission code
                if (!isReadonlyHint) {
                    instanceDocument = TransformerUtils.readDom4j(connectionResult.getResponseInputStream(), connectionResult.resourceURI, false);
                } else {
                    instanceDocument = TransformerUtils.readTinyTree(connectionResult.getResponseInputStream(), connectionResult.resourceURI, false);
                }
            } finally {
                // Clean-up
                connectionResult.close();
            }

        } else {
            // Optimized case that uses the provided resolver
            if (XFormsServer.logger.isDebugEnabled())
                containingDocument.logDebug("model", "getting document from resolver", "URI", absoluteResolvedURLString);

            // TODO: Handle validating and handleXInclude!

            if (!isReadonlyHint) {
                instanceDocument = containingDocument.getURIResolver().readURLAsDocument(absoluteResolvedURLString, xxformsUsername, xxformsPassword,
                        XFormsProperties.getForwardSubmissionHeaders(containingDocument));
            } else {
                instanceDocument = containingDocument.getURIResolver().readURLAsDocumentInfo(absoluteResolvedURLString, xxformsUsername, xxformsPassword,
                        XFormsProperties.getForwardSubmissionHeaders(containingDocument));
            }
        }

        // Set instance and associated information if everything went well
        // NOTE: No XInclude supported to read instances with @src for now
        setInstanceDocument(instanceDocument, effectiveId, instanceId, absoluteResolvedURLString, xxformsUsername, xxformsPassword, false, -1, xxformsValidation, false);
    }

    private void loadInstanceOptimized(PropertyContext propertyContext, ExternalContext externalContext, Element instanceContainer,
                                       String instanceId, String resourceAbsolutePathOrAbsoluteURL, boolean isReadonlyHint, String xxformsValidation) {

        // Whether or not to rewrite URLs
        final boolean isNoRewrite = XFormsUtils.resolveUrlNorewrite(instanceContainer);

        if (XFormsServer.logger.isDebugEnabled())
            containingDocument.logDebug("model", "getting document from optimized URI",
                        "URI", resourceAbsolutePathOrAbsoluteURL, "norewrite", Boolean.toString(isNoRewrite));

        // Run submission
        final ConnectionResult connectionResult = OptimizedSubmission.openOptimizedConnection(propertyContext, externalContext, containingDocument,
                null, "get", resourceAbsolutePathOrAbsoluteURL, isNoRewrite, null, null, null, false,
                OptimizedSubmission.MINIMAL_HEADERS_TO_FORWARD, null);

        final Object instanceDocument;// Document or DocumentInfo
        try {
            // Handle connection errors
            if (connectionResult.statusCode != 200) {
                throw new OXFException("Got invalid return code while loading instance: " + resourceAbsolutePathOrAbsoluteURL + ", " + connectionResult.statusCode);
            }

            // TODO: Handle validating and handleXInclude!

            // Read result as XML
            // TODO: use submission code
            if (!isReadonlyHint) {
                instanceDocument = TransformerUtils.readDom4j(connectionResult.getResponseInputStream(), connectionResult.resourceURI, false);
            } else {
                instanceDocument = TransformerUtils.readTinyTree(connectionResult.getResponseInputStream(), connectionResult.resourceURI, false);
            }
        } finally {
            // Clean-up
            connectionResult.close();
        }

        // Set instance and associated information if everything went well
        // NOTE: No XInclude supported to read instances with @src for now
        setInstanceDocument(instanceDocument, effectiveId, instanceId, resourceAbsolutePathOrAbsoluteURL, null, null, false, -1, xxformsValidation, false);
    }
    
    public void performTargetAction(PropertyContext propertyContext, XBLContainer container, XFormsEvent event) {
        // NOP
    }

    public void synchronizeInstanceDataEventState() {
        if (instances != null) {
            for (XFormsInstance currentInstance: instances) {
                currentInstance.synchronizeInstanceDataEventState();
            }
        }
    }

    public void doRebuild(PropertyContext propertyContext) {

        // Rebuild bind tree only if needed.
        if (binds != null && deferredActionContext.rebuild) {
            binds.rebuild(propertyContext);
            // TODO: rebuild computational dependency data structures

            // Controls may have @bind or xxforms:bind() references, so we need to mark them as dirty. Will need dependencies for controls to fix this.
            containingDocument.getControls().markDirtySinceLastRequest(true);
        }

        // "Actions that directly invoke rebuild, recalculate, revalidate, or refresh always
        // have an immediate effect, and clear the corresponding flag."
        deferredActionContext.rebuild = false;
    }

    public void doRecalculate(PropertyContext propertyContext) {

        // Recalculate only if needed
        if (instances != null && binds != null && deferredActionContext.recalculate) {
            // Apply calculate binds
            binds.applyCalculateBinds(propertyContext);
        }

        // "Actions that directly invoke rebuild, recalculate, revalidate, or refresh always
        // have an immediate effect, and clear the corresponding flag."
        deferredActionContext.recalculate = false;
    }


    public void doRevalidate(final PropertyContext propertyContext) {

        // Validate only if needed, including checking the flags, because if validation state is clean, validation
        // being idempotent, revalidating is not needed.
        if (instances != null && (mustBindValidate || mustSchemaValidate) && deferredActionContext.revalidate) {
            if (XFormsServer.logger.isDebugEnabled())
                containingDocument.startHandleOperation("model", "performing revalidate", "model id", getEffectiveId());

            // Clear validation state
            for (XFormsInstance currentInstance: instances) {
                XFormsUtils.iterateInstanceData(currentInstance, new XFormsUtils.InstanceWalker() {
                    public void walk(NodeInfo nodeInfo) {
                        InstanceData.clearValidationState(nodeInfo);
                    }
                }, true);
            }

            // Run validation
            final Map<String, String> invalidInstances = new HashMap<String, String>();

            // Validate using schemas if needed
            if (mustSchemaValidate) {
                // Apply schemas to all instances
                for (XFormsInstance currentInstance: instances) {
                    // Currently we don't support validating read-only instances
                    if (!currentInstance.isReadOnly()) {
                        if (!schemaValidator.validateInstance(currentInstance)) {
                            // Remember that instance is invalid
                            invalidInstances.put(currentInstance.getEffectiveId(), "");
                        }
                    }
                }
            }

            // Validate using binds if needed
            if (mustBindValidate)
                binds.applyValidationBinds(propertyContext, invalidInstances);

            // NOTE: It is possible, with binds and the use of xxforms:instance(), that some instances in
            // invalidInstances do not belong to this model. Those instances won't get events with the dispatching
            // algorithm below.
            for (XFormsInstance currentInstance: instances) {
                if (invalidInstances.get(currentInstance.getEffectiveId()) == null) {
                    container.dispatchEvent(propertyContext, new XXFormsValidEvent(currentInstance));
                } else {
                    container.dispatchEvent(propertyContext, new XXFormsInvalidEvent(currentInstance));
                }
            }

            if (XFormsServer.logger.isDebugEnabled())
                containingDocument.endHandleOperation();
        }

        // "Actions that directly invoke rebuild, recalculate, revalidate, or refresh always
        // have an immediate effect, and clear the corresponding flag."
        deferredActionContext.revalidate = false;
    }

    private void doRefresh(PropertyContext propertyContext) {

        // Only refresh if needed
        if (deferredActionContext.refresh) {
            containingDocument.getControls().doRefresh(propertyContext, this);
        }
        // NOTE: deferredActionContext.refresh is set to false in refreshDone()
    }

    /**
     * Handle an updated instance after a submission with instance replacement/update.
     *
     * @param propertyContext   current context
     * @param updatedInstance   instance to replace or update (can be new instance object or existing one)
     * @param updatedTreeRoot   root of the tree which was updated (can be root element or another element)
     */
    public void handleUpdatedInstance(PropertyContext propertyContext, final XFormsInstance updatedInstance, final NodeInfo updatedTreeRoot) {

        // Set the instance on this model
        // Instance object might already be there, or might be a new one. In any case, instance needs to be marked as updated.
        setInstance(updatedInstance, true);

        // NOTE: The current spec specifies direct calls, but it might be updated to require setting flags instead.
        {
            final XFormsModel.DeferredActionContext deferredActionContext = getDeferredActionContext();
            deferredActionContext.rebuild = true;
            deferredActionContext.recalculate = true;
            deferredActionContext.revalidate = true;
        }

        final XFormsControls xformsControls = containingDocument.getControls();
        if (xformsControls.isInitialized()) {
            // Controls exist, otherwise there is no point in doing anything controls-related

            // The controls will be dirty
            containingDocument.getControls().markDirtySinceLastRequest(true);

            // As of 2009-03-18 decision, XForms 1.1 specifies that deferred event handling flags are set instead of
            // performing RRRR directly
            deferredActionContext.setAllDeferredFlags(true);

            if (updatedInstance.isReadOnly()) {
                // Read-only instance: replacing does not cause value change events at the moment, so we just set the
                // flags but do not mark values as changed. Anyway, that event logic is broken, see below.

                // NOP for now
            } else {
                // Read-write instance

                // NOTE: Besides setting the flags, for read-write instances, we go through a marking process used for
                // event dispatch. This process requires:
                //
                // o up-to-date control bindings, for 1) relevance handling and 2) type handling
                // o which in turn requires RRR
                //
                // So we do perform RRR below, which clears the flags set above. This should be seen as temporary
                // measure until we do proper (i.e. not like XForms 1.1 specifies!) UI event updates.

                // Update control bindings if needed 
                doRebuild(propertyContext);
                doRecalculate(propertyContext);
                doRevalidate(propertyContext);
                xformsControls.updateControlBindingsIfNeeded(propertyContext);

                if (XFormsServer.logger.isDebugEnabled())
                    containingDocument.logDebug("model", "marking nodes for value change following instance replacement",
                            "instance id", updatedInstance.getEffectiveId());

                // Mark all nodes to which single-node controls are bound
                xformsControls.visitAllControls(new XFormsControls.XFormsControlVisitorAdapter() {
                    public void startVisitControl(XFormsControl control) {

                        // Don't do anything if it's not a single node control
                        // NOTE: We don't dispatch events to repeat iterations
                        if (!(control instanceof XFormsSingleNodeControl && !(control instanceof XFormsRepeatIterationControl)))
                            return;

                        // This can happen if control is not bound to anything (includes xforms:group[not(@ref) and not(@bind)])
                        final NodeInfo boundNodeInfo = ((XFormsSingleNodeControl) control).getBoundNode();
                        if (boundNodeInfo == null)
                            return;

                        // We only mark nodes in mutable documents
                        if (!(boundNodeInfo instanceof NodeWrapper))
                            return;

                        // Mark node only if it is within the updated tree
                        if (!Navigator.isAncestorOrSelf(updatedTreeRoot, boundNodeInfo))
                            return;

                        // Finally, mark node
                        InstanceData.markValueChanged(boundNodeInfo);
                    }
                });
            }
        }
    }

    private final DeferredActionContext deferredActionContext = new DeferredActionContext();

    public static class DeferredActionContext {
        public boolean rebuild;
        public boolean recalculate;
        public boolean revalidate;
        public boolean refresh;

        public void setAllDeferredFlags(boolean value) {
            rebuild = value;
            recalculate = value;
            revalidate = value;
            refresh = value;
        }
    }

    public DeferredActionContext getDeferredActionContext() {
        return deferredActionContext;
    }

    public void setAllDeferredFlags(boolean value) {
        deferredActionContext.setAllDeferredFlags(value);
    }

    public void refreshDone() {
        deferredActionContext.refresh = false;
    }

    public void startOutermostActionHandler() {
        // NOP now that deferredActionContext is always created
    }

    public void endOutermostActionHandler(PipelineContext pipelineContext) {

        // Process deferred behavior
        final DeferredActionContext currentDeferredActionContext = deferredActionContext;
        // NOTE: We used to clear deferredActionContext , but this caused events to be dispatched in a different
        // order. So we are now leaving the flag as is, and waiting until they clear themselves.

        if (currentDeferredActionContext.rebuild) {
            containingDocument.startOutermostActionHandler();
            container.dispatchEvent(pipelineContext, new XFormsRebuildEvent(this));
            containingDocument.endOutermostActionHandler(pipelineContext);
        }
        if (currentDeferredActionContext.recalculate) {
            containingDocument.startOutermostActionHandler();
            container.dispatchEvent(pipelineContext, new XFormsRecalculateEvent(this));
            containingDocument.endOutermostActionHandler(pipelineContext);
        }
        if (currentDeferredActionContext.revalidate) {
            containingDocument.startOutermostActionHandler();
            container.dispatchEvent(pipelineContext, new XFormsRevalidateEvent(this));
            containingDocument.endOutermostActionHandler(pipelineContext);
        }
        if (currentDeferredActionContext.refresh) {
            containingDocument.startOutermostActionHandler();
            container.dispatchEvent(pipelineContext, new XFormsRefreshEvent(this));
            containingDocument.endOutermostActionHandler(pipelineContext);
        }
    }

    public void rebuildRecalculateIfNeeded(PropertyContext propertyContext) {
        doRebuild(propertyContext);
        doRecalculate(propertyContext);
    }

    public XFormsEventObserver getParentEventObserver(XBLContainer container) {
        // There is no point for events to propagate beyond the model
        // TODO: This could change in the future once models are more integrated in the components hierarchy
        return null;
    }

    /**
     * Return the List of XFormsEventHandler objects within this object.
     */
    public List getEventHandlers(XBLContainer container) {
        return containingDocument.getStaticState().getEventHandlers(XFormsUtils.getEffectiveIdNoSuffix(getEffectiveId()));
    }
}
