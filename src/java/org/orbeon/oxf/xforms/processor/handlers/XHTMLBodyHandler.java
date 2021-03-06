/**
 *  Copyright (C) 2005 Orbeon, Inc.
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
package org.orbeon.oxf.xforms.processor.handlers;

import org.dom4j.QName;
import org.orbeon.oxf.servlet.OrbeonXFormsFilter;
import org.orbeon.oxf.xforms.*;
import org.orbeon.oxf.xml.ContentHandlerHelper;
import org.orbeon.oxf.xml.ElementHandlerController;
import org.orbeon.oxf.xml.XMLConstants;
import org.orbeon.oxf.xml.XMLUtils;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;

import java.util.Iterator;
import java.util.Map;

/**
 * Handle xhtml:body.
 */
public class XHTMLBodyHandler extends XFormsBaseHandler {

    private ContentHandlerHelper helper;

//    private String formattingPrefix;

    public XHTMLBodyHandler() {
        super(false, true);
    }

    public void start(String uri, String localname, String qName, Attributes attributes) throws SAXException {

        final XFormsStaticState staticState = containingDocument.getStaticState();

        // Register control handlers on controller
        {
            final ElementHandlerController controller = handlerContext.getController();
            controller.registerHandler(XFormsInputHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "input");
            controller.registerHandler(XFormsOutputHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "output");
            controller.registerHandler(XFormsTriggerHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "trigger");
            controller.registerHandler(XFormsSubmitHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "submit");
            controller.registerHandler(XFormsSecretHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "secret");
            controller.registerHandler(XFormsTextareaHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "textarea");
            controller.registerHandler(XFormsUploadHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "upload");
            controller.registerHandler(XFormsRangeHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "range");
            controller.registerHandler(XFormsSelectHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "select");
            controller.registerHandler(XFormsSelect1Handler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "select1");

            controller.registerHandler(XFormsGroupHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "group");
            controller.registerHandler(XFormsSwitchHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "switch");
            controller.registerHandler(XFormsCaseHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "case");
            controller.registerHandler(XFormsRepeatHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "repeat");

            controller.registerHandler(XXFormsDialogHandler.class.getName(), XFormsConstants.XXFORMS_NAMESPACE_URI, "dialog");

            // Add handlers for LHHA elements
            if (true) {// TODO: check w/ XFStaticState if there are any standalone LHHA elements
                controller.registerHandler(XFormsLabelHintHelpAlertHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "label");
                controller.registerHandler(XFormsLabelHintHelpAlertHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "help");
                controller.registerHandler(XFormsLabelHintHelpAlertHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "hint");
                controller.registerHandler(XFormsLabelHintHelpAlertHandler.class.getName(), XFormsConstants.XFORMS_NAMESPACE_URI, "alert");
            }

            // Add handlers for custom components
            final Map componentBindings = staticState.getXblBindings().getComponentBindings();
            if (componentBindings != null) {
                for (Iterator i = componentBindings.keySet().iterator(); i.hasNext();) {
                    final QName currentQName = (QName) i.next();
                    controller.registerHandler(XXFormsComponentHandler.class.getName(), currentQName.getNamespaceURI(), currentQName.getName());
                }
            }
        }

        // Add class for YUI skin
        // TODO: should be configurable somehow
        attributes = XMLUtils.appendToClassAttribute(attributes, "yui-skin-sam");

        // Start xhtml:body
        final ContentHandler contentHandler = handlerContext.getController().getOutput();
        contentHandler.startElement(uri, localname, qName, attributes);
        helper = new ContentHandlerHelper(contentHandler);

        final XFormsControls xformsControls = containingDocument.getControls();
        final String htmlPrefix = XMLUtils.prefixFromQName(qName);

        // Get formatting prefix and declare it if needed
        // TODO: would be nice to do this here, but then we need to make sure this prefix is available to other handlers
//        formattingPrefix = handlerContext.findFormattingPrefixDeclare();

        final String xformsSubmissionPath;
        {
            final String requestPath = handlerContext.getExternalContext().getRequest().getRequestPath();
            final boolean isForwarded = OrbeonXFormsFilter.OPS_RENDERER_PATH.equals(requestPath);
            if (isForwarded) {
                // This is the case where the request was forwarded to us (separate deployment)
                xformsSubmissionPath = "/xforms-server-submit";// TODO: read property!
            } else {
                // Submission posts to URL of the current page and xforms-xml-submission.xpl intercepts that
                xformsSubmissionPath = requestPath;
            }
        }

        // Noscript panel is included before the xhtml:form element, in case the form is hidden through CSS
        if (!handlerContext.isNoScript()) {
            // TODO: must send startPrefixMapping()/endPrefixMapping()?
            helper.element("", XMLConstants.XINCLUDE_URI, "include", new String[] { "href", "oxf:/config/noscript-panel.xml" });
        }

        // Create xhtml:form element
        final boolean hasUpload = staticState.hasControlByName("upload");
        helper.startElement(htmlPrefix, XMLConstants.XHTML_NAMESPACE_URI, "form", new String[] {
                // Add id so that things work in portals    
                "id", XFormsUtils.namespaceId(containingDocument, "xforms-form"),
                // Regular classes
                "class", "xforms-form" + (handlerContext.isNoScript() ? " xforms-noscript" : " xforms-initially-hidden"),
                // Submission parameters
                "action", xformsSubmissionPath, "method", "POST",
                // In noscript mode, don't add event handler
                "onsubmit", handlerContext.isNoScript() ? null : "return false",
                hasUpload ? "enctype" : null, hasUpload ? "multipart/form-data" : null});

        {
            // Output encoded static and dynamic state
            helper.element(htmlPrefix, XMLConstants.XHTML_NAMESPACE_URI, "input", new String[] {
                    "type", "hidden", "name", "$static-state", "value", handlerContext.getEncodedClientState().getStaticState()
            });
            helper.element(htmlPrefix, XMLConstants.XHTML_NAMESPACE_URI, "input", new String[]{
                    "type", "hidden", "name", "$dynamic-state", "value", handlerContext.getEncodedClientState().getDynamicState()
            });
        }

        if (!handlerContext.isNoScript()) {
            // Other fields used by JavaScript
            helper.element(htmlPrefix, XMLConstants.XHTML_NAMESPACE_URI, "input", new String[]{
                    "type", "hidden", "name", "$server-events", "value", ""
            });
            helper.element(htmlPrefix, XMLConstants.XHTML_NAMESPACE_URI, "input", new String[]{
                    "type", "hidden", "name", "$client-state", "value", ""
            });

            // Store information about nested repeats hierarchy
            {
                helper.element(htmlPrefix, XMLConstants.XHTML_NAMESPACE_URI, "input", new String[]{
                        "type", "hidden", "name", "$repeat-tree", "value", staticState.getRepeatHierarchyString()
                });
            }

            // Store information about the initial index of each repeat
            {
                final StringBuffer repeatIndexesStringBuffer = new StringBuffer();
                final Map repeatIdToIndex = xformsControls.getCurrentControlTree().getMinimalRepeatIdToIndex(staticState);
                if (repeatIdToIndex.size() != 0) {
                    for (Iterator i = repeatIdToIndex.entrySet().iterator(); i.hasNext();) {
                        final Map.Entry currentEntry = (Map.Entry) i.next();
                        final String repeatId = (String) currentEntry.getKey();
                        final Integer index = (Integer) currentEntry.getValue();

                        if (repeatIndexesStringBuffer.length() > 0)
                            repeatIndexesStringBuffer.append(',');

                        repeatIndexesStringBuffer.append(repeatId);
                        repeatIndexesStringBuffer.append(' ');
                        repeatIndexesStringBuffer.append(index);
                    }
                }

                helper.element(htmlPrefix, XMLConstants.XHTML_NAMESPACE_URI, "input", new String[]{
                        "type", "hidden", "name", "$repeat-indexes", "value", repeatIndexesStringBuffer.toString()
                });
            }

            // Ajax loading indicator
            if (XFormsProperties.isAjaxShowLoadingIcon(containingDocument)) {

                helper.startElement(htmlPrefix, XMLConstants.XHTML_NAMESPACE_URI, "span", new String[]{ "class", "xforms-loading-loading" });
                helper.text("Loading..."); // text is hardcoded, but you can rewrite it in the theme if needed
                helper.endElement();

                helper.element(htmlPrefix, XMLConstants.XHTML_NAMESPACE_URI, "span", new String[]{ "class", "xforms-loading-none" });
            }

            // Ajax error panel
            if (XFormsProperties.isAjaxShowErrors(containingDocument)) {
                // XInclude dialog so users can configure it
                // TODO: must send startPrefixMapping()/endPrefixMapping()?
                helper.element("", XMLConstants.XINCLUDE_URI, "include", new String[] { "href", "oxf:/config/error-dialog.xml" });
            }

            // Help panel
            // TODO: must send startPrefixMapping()/endPrefixMapping()?
            helper.element("", XMLConstants.XINCLUDE_URI, "include", new String[] { "href", "oxf:/config/help-panel.xml" });

            // Templates
            {
                final String spanQName = XMLUtils.buildQName(htmlPrefix, "span");
                final String TEMPLATE_ID = "$xforms-effective-id$";

                // HACK: We would be ok with just one template, but IE 6 doesn't allow setting the input/@type attribute properly

                // xforms:select[@appearance = 'full'], xforms:input[@type = 'xs:boolean']
                XFormsSelect1Handler.outputItemFullTemplate(pipelineContext, handlerContext, contentHandler, htmlPrefix, spanQName,
                        containingDocument, reusableAttributes, attributes,
                        "xforms-select-full-template", TEMPLATE_ID, TEMPLATE_ID, true, "checkbox");

                // xforms:select1[@appearance = 'full']
                XFormsSelect1Handler.outputItemFullTemplate(pipelineContext, handlerContext, contentHandler, htmlPrefix, spanQName,
                        containingDocument, reusableAttributes, attributes,
                        "xforms-select1-full-template", TEMPLATE_ID, TEMPLATE_ID, true, "radio");
            }

        } else {
            // Noscript mode
            helper.element(htmlPrefix, XMLConstants.XHTML_NAMESPACE_URI, "input", new String[]{
                    "type", "hidden", "name", "$noscript", "value", "true"
            });
        }
    }

    public void end(String uri, String localname, String qName) throws SAXException {
        // Close xhtml:form
        helper.endElement();

        // Close xhtml:body
        final ContentHandler contentHandler = handlerContext.getController().getOutput();
        contentHandler.endElement(uri, localname, qName);
    }
}
