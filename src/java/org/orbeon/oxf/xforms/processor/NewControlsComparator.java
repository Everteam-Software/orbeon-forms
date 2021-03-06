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
package org.orbeon.oxf.xforms.processor;

import org.orbeon.oxf.pipeline.api.PipelineContext;
import org.orbeon.oxf.xforms.XFormsConstants;
import org.orbeon.oxf.xforms.XFormsContainingDocument;
import org.orbeon.oxf.xforms.control.XFormsContainerControl;
import org.orbeon.oxf.xforms.control.XFormsControl;
import org.orbeon.oxf.xforms.control.XFormsSingleNodeControl;
import org.orbeon.oxf.xforms.control.XFormsValueControl;
import org.orbeon.oxf.xforms.control.controls.*;
import org.orbeon.oxf.xforms.itemset.Itemset;
import org.orbeon.oxf.xml.ContentHandlerHelper;
import org.orbeon.oxf.xml.XMLConstants;
import org.xml.sax.helpers.AttributesImpl;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class NewControlsComparator extends BaseControlsComparator {

    public NewControlsComparator(PipelineContext pipelineContext, ContentHandlerHelper ch, XFormsContainingDocument containingDocument, Map<String, Itemset> itemsetsFull1, Map<String, Itemset> itemsetsFull2, Map valueChangeControlIds) {
        super(pipelineContext, ch, containingDocument, itemsetsFull1, itemsetsFull2, valueChangeControlIds);
    }

    public void diff(List<XFormsControl> state1, List<XFormsControl> state2) {
        diff(state1, state2, false);
    }

    public void diff(List<XFormsControl> state1, List<XFormsControl> state2, boolean isWithinNewRepeatIteration) {

        // Normalize
        if (state1 != null && state1.size() == 0)
            state1 = null;
        if (state2 != null && state2.size() == 0)
            state2 = null;

        // Trivial case
        if (state1 == null && state2 == null)
            return;

        // Only state1 can be null
//        if (state2 == null) {
//            throw new IllegalStateException("Illegal state when comparing controls.");
//        }
        // Both lists should have the same size if present, except when grouping controls become relevant/non-relevant,
        // in which case one of the containing controls may contain 0 children
        if (state1 != null && state2 != null && state1.size() != state2.size()) {
            throw new IllegalStateException("Illegal state when comparing controls.");
        }

        {
            final AttributesImpl attributesImpl = new AttributesImpl();

            final Iterator<XFormsControl> leftIterator = (state1 == null) ? null : state1.iterator();
            final Iterator<XFormsControl> rightIterator = (state2 == null) ? null : state2.iterator();
            final Iterator<XFormsControl> leadingIterator = (rightIterator != null) ? rightIterator : leftIterator;

            while (leadingIterator.hasNext()) {
                final XFormsControl xformsControl1 = (leftIterator == null) ? null : leftIterator.next();
                final XFormsControl xformsControl2 = (rightIterator == null) ? null : rightIterator.next();

                final XFormsControl leadingControl = (xformsControl2 != null) ? xformsControl2 : xformsControl1;

                // 1: Check current control
                if (leadingControl instanceof XFormsSingleNodeControl) {
                    // xforms:repeat doesn't need to be handled independently, iterations do it

                    final XFormsSingleNodeControl xformsSingleNodeControl1 = (XFormsSingleNodeControl) xformsControl1;
                    final XFormsSingleNodeControl xformsSingleNodeControl2 = (XFormsSingleNodeControl) xformsControl2;

                    // Output diffs between controlInfo1 and controlInfo2

                    attributesImpl.clear();

                    if (xformsSingleNodeControl2 != null) {

                        final boolean isValueChangeControl = valueChangeControlIds != null && valueChangeControlIds.get(leadingControl.getEffectiveId()) != null;
                        if ((!xformsSingleNodeControl2.equalsExternal(pipelineContext, xformsSingleNodeControl1) || isValueChangeControl)
                                && !(isStaticReadonly && xformsSingleNodeControl2.isReadonly() && xformsSingleNodeControl2 instanceof XFormsTriggerControl)
                                && !(xformsSingleNodeControl2 instanceof XFormsGroupControl && XFormsGroupControl.INTERNAL_APPEARANCE.equals(xformsSingleNodeControl2.getAppearance()))) {
                            // Don't send anything if nothing has changed
                            // But we force a change for controls whose values changed in the request
                            // Also, we don't output anything for triggers in static readonly mode

                            // Whether it is necessary to output information about this control because the control was previously non-existing
                            final boolean isNewlyVisibleSubtree = xformsSingleNodeControl1 == null;

                            // Whether it is necessary to output information about this control
                            boolean doOutputElement = false;

                            if (!(xformsSingleNodeControl2 instanceof XFormsRepeatIterationControl)) {
                                // Anything but a repeat iteration

                                // Control id
                                attributesImpl.addAttribute("", "id", "id", ContentHandlerHelper.CDATA, leadingControl.getEffectiveId());

                                // Model item properties
                                if (isNewlyVisibleSubtree && xformsSingleNodeControl2.isReadonly()
                                        || xformsSingleNodeControl1 != null && xformsSingleNodeControl1.isReadonly() != xformsSingleNodeControl2.isReadonly()) {
                                    attributesImpl.addAttribute("", XFormsConstants.READONLY_ATTRIBUTE_NAME,
                                            XFormsConstants.READONLY_ATTRIBUTE_NAME,
                                            ContentHandlerHelper.CDATA, Boolean.toString(xformsSingleNodeControl2.isReadonly()));
                                    doOutputElement = true;
                                }
                                if (isNewlyVisibleSubtree && xformsSingleNodeControl2.isRequired()
                                        || xformsSingleNodeControl1 != null && xformsSingleNodeControl1.isRequired() != xformsSingleNodeControl2.isRequired()) {
                                    attributesImpl.addAttribute("", XFormsConstants.REQUIRED_ATTRIBUTE_NAME,
                                            XFormsConstants.REQUIRED_ATTRIBUTE_NAME,
                                            ContentHandlerHelper.CDATA, Boolean.toString(xformsSingleNodeControl2.isRequired()));
                                    doOutputElement = true;
                                }
                                // TRICKY:
                                //
                                // * Non-concrete control and within a new iteration, default for relevance is true
                                // * Non-concrete control and NOT within a new iteration, default for relevance is false (xforms-disabled class present)
                                if (isNewlyVisibleSubtree && xformsSingleNodeControl2.isRelevant() != isWithinNewRepeatIteration
                                        || xformsSingleNodeControl1 != null && xformsSingleNodeControl1.isRelevant() != xformsSingleNodeControl2.isRelevant()) {
                                    attributesImpl.addAttribute("", XFormsConstants.RELEVANT_ATTRIBUTE_NAME,
                                            XFormsConstants.RELEVANT_ATTRIBUTE_NAME,
                                            ContentHandlerHelper.CDATA, Boolean.toString(xformsSingleNodeControl2.isRelevant()));
                                    doOutputElement = true;
                                }
                                if (isNewlyVisibleSubtree && !xformsSingleNodeControl2.isValid()
                                        || xformsSingleNodeControl1 != null && xformsSingleNodeControl1.isValid() != xformsSingleNodeControl2.isValid()) {
                                    attributesImpl.addAttribute("", XFormsConstants.VALID_ATTRIBUTE_NAME,
                                            XFormsConstants.VALID_ATTRIBUTE_NAME,
                                            ContentHandlerHelper.CDATA, Boolean.toString(xformsSingleNodeControl2.isValid()));
                                    doOutputElement = true;
                                }

                                // Notify the client that this control must be static readonly in case it just appeared
                                if (isNewlyVisibleSubtree && xformsSingleNodeControl2.isStaticReadonly() && xformsSingleNodeControl2.isRelevant())
                                    attributesImpl.addAttribute("", "static", "static", ContentHandlerHelper.CDATA, "true");

                                // Custom MIPs
                                doOutputElement = diffCustomMIPs(attributesImpl, xformsSingleNodeControl1, xformsSingleNodeControl2, isNewlyVisibleSubtree, doOutputElement);

                                // Type attribute
                                final boolean isOutputControlWithValueAttribute = xformsSingleNodeControl2 instanceof XFormsOutputControl && ((XFormsOutputControl) xformsSingleNodeControl2).getValueAttribute() != null;
                                if (!isOutputControlWithValueAttribute) {

                                    final String typeValue1 = isNewlyVisibleSubtree ? null : xformsSingleNodeControl1.getType();
                                    final String typeValue2 = xformsSingleNodeControl2.getType();

                                    if (!((typeValue1 == null && typeValue2 == null) || (typeValue1 != null && typeValue2 != null && typeValue1.equals(typeValue2)))) {
                                        final String attributeValue = typeValue2 != null ? typeValue2 : "";
                                        // NOTE: No type is considered equivalent to xs:string or xforms:string
                                        // TODO: should have more generic code in XForms engine to equate "no type" and "xs:string"
                                        doOutputElement |= addAttributeIfNeeded(attributesImpl, "type", attributeValue, isNewlyVisibleSubtree,
                                            attributeValue.equals("") || XMLConstants.XS_STRING_EXPLODED_QNAME.equals(attributeValue) || XFormsConstants.XFORMS_STRING_EXPLODED_QNAME.equals(attributeValue));
                                    }
                                }

                                // Label, help, hint, alert, etc.
                                {
                                    final String labelValue1 = isNewlyVisibleSubtree ? null : xformsSingleNodeControl1.getLabel(pipelineContext);
                                    final String labelValue2 = xformsSingleNodeControl2.getLabel(pipelineContext);

                                    if (!((labelValue1 == null && labelValue2 == null) || (labelValue1 != null && labelValue2 != null && labelValue1.equals(labelValue2)))) {
                                        final String escapedLabelValue2 = xformsSingleNodeControl2.getEscapedLabel(pipelineContext);
                                        final String attributeValue = escapedLabelValue2 != null ? escapedLabelValue2 : "";
                                        doOutputElement |= addAttributeIfNeeded(attributesImpl, "label", attributeValue, isNewlyVisibleSubtree, attributeValue.equals(""));
                                    }
                                }

                                {
                                    final String helpValue1 = isNewlyVisibleSubtree ? null : xformsSingleNodeControl1.getHelp(pipelineContext);
                                    final String helpValue2 = xformsSingleNodeControl2.getHelp(pipelineContext);

                                    if (!((helpValue1 == null && helpValue2 == null) || (helpValue1 != null && helpValue2 != null && helpValue1.equals(helpValue2)))) {
                                final String escapedHelpValue2 = xformsSingleNodeControl2.getEscapedHelp(pipelineContext);
                                final String attributeValue = escapedHelpValue2 != null ? escapedHelpValue2 : "";
                                        doOutputElement |= addAttributeIfNeeded(attributesImpl, "help", attributeValue, isNewlyVisibleSubtree, attributeValue.equals(""));
                                    }
                                }

                                {
                                    final String hintValue1 = isNewlyVisibleSubtree ? null : xformsSingleNodeControl1.getHint(pipelineContext);
                                    final String hintValue2 = xformsSingleNodeControl2.getHint(pipelineContext);

                                    if (!((hintValue1 == null && hintValue2 == null) || (hintValue1 != null && hintValue2 != null && hintValue1.equals(hintValue2)))) {
                                        final String attributeValue = hintValue2 != null ? hintValue2 : "";
                                        doOutputElement |= addAttributeIfNeeded(attributesImpl, "hint", attributeValue, isNewlyVisibleSubtree, attributeValue.equals(""));
                                    }
                                }

                                {
                                    final String alertValue1 = isNewlyVisibleSubtree ? null : xformsSingleNodeControl1.getAlert(pipelineContext);
                                    final String alertValue2 = xformsSingleNodeControl2.getAlert(pipelineContext);

                                    if (!((alertValue1 == null && alertValue2 == null) || (alertValue1 != null && alertValue2 != null && alertValue1.equals(alertValue2)))) {
                                        final String escapedAlertValue2 = xformsSingleNodeControl2.getEscapedAlert(pipelineContext);
                                        final String attributeValue = escapedAlertValue2 != null ? escapedAlertValue2 : "";
                                        doOutputElement |= addAttributeIfNeeded(attributesImpl, "alert", attributeValue, isNewlyVisibleSubtree, attributeValue.equals(""));
                                    }
                                }

                                // Output control-specific attributes
                                doOutputElement |= xformsSingleNodeControl2.addAttributesDiffs(pipelineContext, xformsSingleNodeControl1, attributesImpl, isNewlyVisibleSubtree);

                                // Get current value if possible for this control
                                // NOTE: We issue the new value in all cases because we don't have yet a mechanism to tell the
                                // client not to update the value, unlike with attributes which can be omitted
                                if (xformsSingleNodeControl2 instanceof XFormsValueControl && !(xformsSingleNodeControl2 instanceof XFormsUploadControl)) {

                                    // TODO: Output value only when changed

                                    final XFormsValueControl xformsValueControl = (XFormsValueControl) xformsSingleNodeControl2;

                                    // Create element with text value
                                    final String value;
                                    {
                                        // Value may become null when controls are unbound
                                        final String tempValue = xformsValueControl.getExternalValue(pipelineContext);
                                        value = (tempValue == null) ? "" : tempValue;
                                    }
                                    if (doOutputElement || !isNewlyVisibleSubtree || (isNewlyVisibleSubtree && !value.equals(""))) {
                                        ch.startElement("xxf", XFormsConstants.XXFORMS_NAMESPACE_URI, "control", attributesImpl);
                                        ch.text(value);
                                        ch.endElement();
                                    }
                                } else {
                                    // No value, just output element with no content
                                    if (doOutputElement)
                                        ch.element("xxf", XFormsConstants.XXFORMS_NAMESPACE_URI, "control", attributesImpl);
                                }

                                // Output extension attributes in no namespace
                                // TODO: If only some attributes changed, then we also output xxf:control above, which is unnecessary
                                xformsSingleNodeControl2.addAttributesDiffs(xformsSingleNodeControl1, ch, isNewlyVisibleSubtree);
                            } else {

                                // Use the effective id of the parent repeat
                                attributesImpl.addAttribute("", "id", "id", ContentHandlerHelper.CDATA, xformsSingleNodeControl2.getParent().getEffectiveId());

                                // Repeat iteration only handles relevance
                                if (isNewlyVisibleSubtree && !xformsSingleNodeControl2.isRelevant() // NOTE: we output if we are NOT relevant as the client must mark non-relevant elements
                                        || xformsSingleNodeControl1 != null && xformsSingleNodeControl1.isRelevant() != xformsSingleNodeControl2.isRelevant()) {
                                    attributesImpl.addAttribute("", XFormsConstants.RELEVANT_ATTRIBUTE_NAME,
                                            XFormsConstants.RELEVANT_ATTRIBUTE_NAME,
                                            ContentHandlerHelper.CDATA, Boolean.toString(xformsSingleNodeControl2.isRelevant()));
                                    doOutputElement = true;
                                }

                                // Repeat iteration
                                if (doOutputElement) {
                                    final XFormsRepeatIterationControl repeatIterationInfo = (XFormsRepeatIterationControl) xformsSingleNodeControl2;
                                    attributesImpl.addAttribute("", "iteration", "iteration", ContentHandlerHelper.CDATA, Integer.toString(repeatIterationInfo.getIterationIndex()));

                                    ch.element("xxf", XFormsConstants.XXFORMS_NAMESPACE_URI, "repeat-iteration", attributesImpl);
                                }
                            }
                        }

                        // Handle out of band differences
                        diffOutOfBand(xformsControl1, xformsControl2);
                    } else {
                        // xformsControl2 == null (&& xformsControl1 != null)
                        // We went from an existing control to a non-relevant control

                        // Control id
                        attributesImpl.addAttribute("", "id", "id", ContentHandlerHelper.CDATA, leadingControl.getEffectiveId());

                        // The only information we send is the non-relevance of the control if needed
                        if (xformsSingleNodeControl1.isRelevant()) {
                            attributesImpl.addAttribute("", XFormsConstants.RELEVANT_ATTRIBUTE_NAME,
                                        XFormsConstants.RELEVANT_ATTRIBUTE_NAME,
                                        ContentHandlerHelper.CDATA, Boolean.toString(false));

                            if (!(xformsSingleNodeControl1 instanceof XFormsRepeatIterationControl)) {
                                ch.element("xxf", XFormsConstants.XXFORMS_NAMESPACE_URI, "control", attributesImpl);
                            } else {
                                final XFormsRepeatIterationControl repeatIterationInfo = (XFormsRepeatIterationControl) xformsSingleNodeControl1;
                                attributesImpl.addAttribute("", "iteration", "iteration", ContentHandlerHelper.CDATA, Integer.toString(repeatIterationInfo.getIterationIndex()));
                                ch.element("xxf", XFormsConstants.XXFORMS_NAMESPACE_URI, "repeat-iteration", attributesImpl);
                            }
                        }
                    }
                } else if (xformsControl2 instanceof XXFormsDialogControl) {
                    // Out of band xxforms:dialog differences

                    final XXFormsDialogControl dialogControl1 = (XXFormsDialogControl) xformsControl1;
                    final XXFormsDialogControl dialogControl2 = (XXFormsDialogControl) xformsControl2;

                    diffDialogs(dialogControl1, dialogControl2);
                }

                // 2: Check children if any
                if (leadingControl instanceof XFormsContainerControl) {

                    final boolean isRepeatControl = leadingControl instanceof XFormsRepeatControl;

                    final XFormsContainerControl containerControl1 = (XFormsContainerControl) xformsControl1;
                    final XFormsContainerControl containerControl2 = (XFormsContainerControl) xformsControl2;

                    final List<XFormsControl> children1 = (containerControl1 == null) ? null : (containerControl1.getChildren() != null && containerControl1.getChildren().size() == 0) ? null : containerControl1.getChildren();
                    final List<XFormsControl> children2 = (containerControl2 == null) ? null : (containerControl2.getChildren() != null && containerControl2.getChildren().size() == 0) ? null : containerControl2.getChildren();

                    if (isRepeatControl) {

                        // Repeat update

                        final XFormsRepeatControl repeatControlInfo = (XFormsRepeatControl) leadingControl;

                        final int size1 = (children1 == null) ? 0 : children1.size();
                        final int size2 = (children2 == null) ? 0 : children2.size();

                        if (size1 == size2) {
                            // No add or remove of children

                            // Delete first template if needed
                            if (size2 == 0 && xformsControl1 == null) {
                                outputDeleteRepeatTemplate(ch, xformsControl2, 1);
                            }

                            // Diff children
                            diff(children1, children2, isWithinNewRepeatIteration);
                        } else if (size2 > size1) {
                            // Size has grown

                            // Copy template instructions
                            outputCopyRepeatTemplate(ch, repeatControlInfo, size1 + 1, size2);

                            // Diff the common subset
                            diff(children1, children2.subList(0, size1), isWithinNewRepeatIteration);

                            // Issue new values for new iterations
                            diff(null, children2.subList(size1, size2), true);

                        } else if (size2 < size1) {
                            // Size has shrunk

                            outputDeleteRepeatTemplate(ch, leadingControl, size1 - size2);

                            // Diff the remaining subset
                            diff(children1.subList(0, size2), children2, isWithinNewRepeatIteration);
                        }
                    } else {
                        // Other grouping controls
                        diff(children1, children2, isWithinNewRepeatIteration);
                    }
                }
            }
        }
    }
}
