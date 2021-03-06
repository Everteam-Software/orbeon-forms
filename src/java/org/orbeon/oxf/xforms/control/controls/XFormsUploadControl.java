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
package org.orbeon.oxf.xforms.control.controls;

import org.apache.commons.lang.StringUtils;
import org.dom4j.Element;
import org.orbeon.oxf.common.OXFException;
import org.orbeon.oxf.common.ValidationException;
import org.orbeon.oxf.pipeline.api.ExternalContext;
import org.orbeon.oxf.pipeline.api.PipelineContext;
import org.orbeon.oxf.util.NetUtils;
import org.orbeon.oxf.util.PropertyContext;
import org.orbeon.oxf.xforms.*;
import org.orbeon.oxf.xforms.action.actions.XFormsSetvalueAction;
import org.orbeon.oxf.xforms.control.XFormsControl;
import org.orbeon.oxf.xforms.control.XFormsSingleNodeControl;
import org.orbeon.oxf.xforms.control.XFormsValueControl;
import org.orbeon.oxf.xforms.event.events.XFormsDeselectEvent;
import org.orbeon.oxf.xforms.xbl.XBLContainer;
import org.orbeon.oxf.xml.XMLConstants;
import org.orbeon.oxf.xml.dom4j.Dom4jUtils;
import org.orbeon.saxon.om.NodeInfo;
import org.xml.sax.helpers.AttributesImpl;

import java.io.File;
import java.io.IOException;
import java.net.URI;

/**
 * Represents an xforms:upload control.
 *
 * @noinspection SimplifiableIfStatement
 */
public class XFormsUploadControl extends XFormsValueControl {

    private FileInfo fileInfo;

    public XFormsUploadControl(XBLContainer container, XFormsControl parent, Element element, String name, String id) {
        super(container, parent, element, name, id);

        fileInfo = new FileInfo(this, getContextStack(), element);
    }

    @Override
    protected void evaluate(PropertyContext propertyContext) {
        super.evaluate(propertyContext);

        getState(propertyContext);
        getFileMediatype(propertyContext);
        getFileName(propertyContext);
        getFileSize(propertyContext);
    }

    @Override
    public void markDirty() {
        super.markDirty();
        fileInfo.markDirty();
    }

    /**
     * Handle a construct of the form:
     *
     *   <xxforms:files>
     *     <parameter>
     *       <name>xforms-element-27</name>
     *       <filename>my-filename.jpg</filename>
     *       <content-type>image/jpeg</content-type>
     *       <content-length>33204</content-length>
     *       <value xmlns:request="http://orbeon.org/oxf/xml/request-private" xsi:type="xs:anyURI">file:/temp/upload_432dfead_11f1a983612__8000_00000107.tmp</value>
     *     </parameter>
     *     <parameter>
     *       ...
     *     </parameter>
     *   </xxforms:files>
     *
     * @param propertyContext       current context
     * @param containingDocument    containing document
     * @param filesElement          xxforms:files element
     * @param forControl            control to handle, null for all controls specified
     * @param handleTemporaryFiles  whether to set listeners for file deletion
     */
    public static void handleFileElement(PropertyContext propertyContext, XFormsContainingDocument containingDocument, Element filesElement, XFormsUploadControl forControl, boolean handleTemporaryFiles) {
        for (Object o: filesElement.elements()) {
            final Element parameterElement = (Element) o;
            final String name = parameterElement.element("name").getTextTrim();

            final XFormsUploadControl uploadControl = (XFormsUploadControl) containingDocument.getObjectByEffectiveId(name);

            // In case of xforms:repeat, the name of the template will not match an existing control
            // In addition, only set value on forControl control if specified
            if (uploadControl == null || forControl != null && forControl != uploadControl)
                continue;

            final Element valueElement = parameterElement.element("value");
            final String value = valueElement.getTextTrim();

            final String filename;
            {
                final Element filenameElement = parameterElement.element("filename");
                filename = (filenameElement != null) ? filenameElement.getTextTrim() : "";
            }
            final String mediatype;
            {
                final Element mediatypeElement = parameterElement.element("content-type");
                mediatype = (mediatypeElement != null) ? mediatypeElement.getTextTrim() : "";
            }
            final String size = parameterElement.element("content-length").getTextTrim();

            if (size.equals("0") && filename.equals("")) {
                // No file was selected in the UI
            } else {
                // A file was selected in the UI (note that the file may be empty)
                // TODO: should pass true?
                final String paramValueType = Dom4jUtils.qNameToExplodedQName(Dom4jUtils.extractAttributeValueQName(valueElement, XMLConstants.XSI_TYPE_QNAME, false));

                // Set value of uploaded file into the instance (will be xs:anyURI or xs:base64Binary)
                uploadControl.setExternalValue(propertyContext, value, paramValueType, handleTemporaryFiles);

                // Handle filename, mediatype and size if necessary
                uploadControl.setFilename(propertyContext, filename);
                uploadControl.setMediatype(propertyContext, mediatype);
                uploadControl.setSize(propertyContext, size);
            }
        }
    }

    @Override
    public void storeExternalValue(PropertyContext propertyContext, String value, String type, Element filesElement) {
        if (XFormsProperties.isNoscript(containingDocument) && filesElement != null) {
            // Must handle file elements
            XFormsUploadControl.handleFileElement(propertyContext, containingDocument, filesElement, this, true);// seems reasonable to set handleTemporaryFiles = true
        } else {
            // Set value and handle temporary files
            setExternalValue(propertyContext, value, type, true);

            // If the value is being cleared, also clear the metadata
            if (value.equals("")) {
                setFilename(propertyContext, "");
                setMediatype(propertyContext, "");
                setSize(propertyContext, "");
            }
        }
    }

    private void setExternalValue(PropertyContext propertyContext, String value, String type, boolean handleTemporaryFiles) {

        final String oldValue = getValue(propertyContext);

        if ((value == null || value.trim().equals("")) && !(oldValue == null || oldValue.trim().equals(""))) {
            // Consider that file got "deselected" in the UI
            getXBLContainer().dispatchEvent(propertyContext, new XFormsDeselectEvent(this));
        }

        try {
            final String newValue;
            if (handleTemporaryFiles) {
                // Try to delete temporary file if old value was temp URI and new value is different
                if (oldValue != null && NetUtils.urlHasProtocol(oldValue) && !oldValue.equals(value) && oldValue.startsWith("file:")) {
                    final File file = new File(new URI(oldValue));
                    if (file.exists()) {
                        final boolean success = file.delete();
                        try {
                            final String message = success ? "deleted temporary file upon upload" : "could not delete temporary file upon upload";
                            containingDocument.logDebug("upload", message, "path", file.getCanonicalPath());
                        } catch (IOException e) {
                            // NOP
                        }
                    }
                }

                if (XMLConstants.XS_ANYURI_EXPLODED_QNAME.equals(type) && value != null && NetUtils.urlHasProtocol(value)) {
                    // If we upload a new URI in the background, then don't delete the temporary file
                    final String newPath;
                    {
                        final File newFile = File.createTempFile("xforms_upload_", null);
                        newPath = newFile.getCanonicalPath();
                        newFile.delete();
                    }
                    final File oldFile = new File(new URI(value));
                    final File newFile = new File(newPath);
                    final boolean success = oldFile.renameTo(newFile);
                    try {
                        final String message = success ? "renamed temporary file upon upload" : "could not rename temporary file upon upload";
                        containingDocument.logDebug("upload", message, "from", oldFile.getCanonicalPath(), "to", newFile.getCanonicalPath());
                    } catch (IOException e) {
                        // NOP
                    }
                    // Try to delete the file on exit and on session termination
                    {
                        newFile.deleteOnExit();
                        final ExternalContext externalContext = (ExternalContext) propertyContext.getAttribute(PipelineContext.EXTERNAL_CONTEXT);
                        final ExternalContext.Session session = externalContext.getSession(false);
                        if (session != null) {
                            session.addListener(new ExternalContext.Session.SessionListener() {
                                public void sessionDestroyed() {
                                    final boolean success = newFile.delete();
                                    try {
                                        final String message = success ? "deleted temporary file upon session destruction" : "could not delete temporary file upon session destruction";
                                        containingDocument.logDebug("upload", message, "file", newFile.getCanonicalPath());
                                    } catch (IOException e) {
                                        // NOP
                                    }
                                }
                            });
                        } else {
                            containingDocument.logDebug("upload", "no existing session found so cannot register temporary file deletion upon session destruction",
                                    "file", newFile.getCanonicalPath());
                        }
                    }
                    newValue = newFile.toURI().toString();
                } else {
                    newValue = value;
                }
            } else {
                newValue = value;
            }

            // Call the super method
            super.storeExternalValue(propertyContext, newValue, type, null);
        } catch (Exception e) {
            throw new ValidationException(e, getLocationData());
        }
    }

    public String getState(PropertyContext propertyContext) {
        return fileInfo.getState(propertyContext);
    }

    public String getFileMediatype(PropertyContext propertyContext) {
        return fileInfo.getFileMediatype(propertyContext);
    }

    public String getFileName(PropertyContext propertyContext) {
        return fileInfo.getFileName(propertyContext);
    }

    public String getFileSize(PropertyContext propertyContext) {
        return fileInfo.getFileSize(propertyContext);
    }

    public void setMediatype(PropertyContext propertyContext, String mediatype) {
        fileInfo.setMediatype(propertyContext, mediatype);
    }

    public void setFilename(PropertyContext propertyContext, String filename) {
        fileInfo.setFilename(propertyContext, filename);
    }

    public void setSize(PropertyContext propertyContext, String size) {
        fileInfo.setSize(propertyContext, size);
    }

    @Override
    public boolean equalsExternal(PipelineContext pipelineContext, XFormsControl obj) {

        if (obj == null || !(obj instanceof XFormsUploadControl))
            return false;

        if (this == obj)
            return true;

        final XFormsUploadControl other = (XFormsUploadControl) obj;

        if (!XFormsUtils.compareStrings(getState(pipelineContext), other.getState(pipelineContext)))
            return false;
        if (!XFormsUtils.compareStrings(getFileMediatype(pipelineContext), other.getFileMediatype(pipelineContext)))
            return false;
        if (!XFormsUtils.compareStrings(getFileSize(pipelineContext), other.getFileSize(pipelineContext)))
            return false;
        if (!XFormsUtils.compareStrings(getFileName(pipelineContext), other.getFileName(pipelineContext)))
            return false;

        return super.equalsExternal(pipelineContext, obj);
    }

    @Override
    public boolean addAttributesDiffs(PipelineContext pipelineContext, XFormsSingleNodeControl other, AttributesImpl attributesImpl, boolean isNewRepeatIteration) {

        final XFormsUploadControl uploadControlInfo1 = (XFormsUploadControl) other;
        final XFormsUploadControl uploadControlInfo2 = this;

        boolean added = false;
        {
            // State
            final String stateValue1 = (uploadControlInfo1 == null) ? null : uploadControlInfo1.getState(pipelineContext);
            final String stateValue2 = uploadControlInfo2.getState(pipelineContext);

            if (!XFormsUtils.compareStrings(stateValue1, stateValue2)) {
                final String attributeValue = stateValue2 != null ? stateValue2 : "";
                added |= addAttributeIfNeeded(attributesImpl, "state", attributeValue, isNewRepeatIteration, attributeValue.equals(""));
            }
        }
        {
            // Mediatype
            final String mediatypeValue1 = (uploadControlInfo1 == null) ? null : uploadControlInfo1.getFileMediatype(pipelineContext);
            final String mediatypeValue2 = uploadControlInfo2.getFileMediatype(pipelineContext);

            if (!XFormsUtils.compareStrings(mediatypeValue1, mediatypeValue2)) {
                final String attributeValue = mediatypeValue2 != null ? mediatypeValue2 : "";
                added |= addAttributeIfNeeded(attributesImpl, "mediatype", attributeValue, isNewRepeatIteration, attributeValue.equals(""));
            }
        }
        {
            // Filename
            final String filenameValue1 = (uploadControlInfo1 == null) ? null : uploadControlInfo1.getFileName(pipelineContext);
            final String filenameValue2 = uploadControlInfo2.getFileName(pipelineContext);

            if (!XFormsUtils.compareStrings(filenameValue1, filenameValue2)) {
                final String attributeValue = filenameValue2 != null ? filenameValue2 : "";
                added |= addAttributeIfNeeded(attributesImpl, "filename", attributeValue, isNewRepeatIteration, attributeValue.equals(""));
            }
        }
        {
            // Size
            final String sizeValue1 = (uploadControlInfo1 == null) ? null : uploadControlInfo1.getFileSize(pipelineContext);
            final String sizeValue2 = uploadControlInfo2.getFileSize(pipelineContext);

            if (!XFormsUtils.compareStrings(sizeValue1, sizeValue2)) {
                final String attributeValue = sizeValue2 != null ? sizeValue2 : "";
                added |= addAttributeIfNeeded(attributesImpl, "size", attributeValue, isNewRepeatIteration, attributeValue.equals(""));
            }
        }

        return added;
    }

    public Object clone() {
        final XFormsUploadControl cloned = (XFormsUploadControl) super.clone();
        // NOTE: this keeps old refs to control/contextStack, is it ok?
        cloned.fileInfo = (FileInfo) fileInfo.clone();
        return cloned;
    }
}

/*
 * File information used e.g. by upload and output controls.
 */
class FileInfo implements Cloneable {

    private XFormsValueControl control;
    private XFormsContextStack contextStack;

    private Element mediatypeElement;
    private Element filenameElement;
    private Element sizeElement;

    private boolean isStateEvaluated;
    private String state;
    private boolean isMediatypeEvaluated;
    private String mediatype;
    private boolean isSizeEvaluated;
    private String size;
    private boolean isFilenameEvaluated;
    private String filename;

    FileInfo(XFormsValueControl control, XFormsContextStack contextStack, Element element) {
        this.control = control;
        this.contextStack =  contextStack;

        mediatypeElement = element.element(XFormsConstants.XFORMS_MEDIATYPE_QNAME);
        filenameElement = element.element(XFormsConstants.XFORMS_FILENAME_QNAME);
        sizeElement = element.element(XFormsConstants.XXFORMS_SIZE_QNAME);
    }

    public void markDirty() {
        isStateEvaluated = false;
        isMediatypeEvaluated = false;
        isSizeEvaluated = false;
        isFilenameEvaluated = false;
    }

    public String getState(PropertyContext propertyContext) {
        if (!isStateEvaluated) {
            final boolean isEmpty = control.getValue(propertyContext) == null || control.getValue(propertyContext).length() == 0;
            state = isEmpty ? "empty" : "file";
            isStateEvaluated = true;
        }
        return state;
    }

    public String getFileMediatype(PropertyContext propertyContext) {
        if (!isMediatypeEvaluated) {
            mediatype = (mediatypeElement == null) ? null : getInfoValue(propertyContext, mediatypeElement);
            isMediatypeEvaluated = true;
        }
        return mediatype;
    }

    public String getFileName(PropertyContext propertyContext) {
        if (!isFilenameEvaluated) {
            filename = (filenameElement == null) ? null : getInfoValue(propertyContext, filenameElement);
            isFilenameEvaluated = true;
        }
        return filename;
    }

    public String getFileSize(PropertyContext propertyContext) {
        if (!isSizeEvaluated) {
            size = (sizeElement == null) ? null : getInfoValue(propertyContext, sizeElement);
            isSizeEvaluated = true;
        }
        return size;
    }

    private String getInfoValue(PropertyContext propertyContext, Element element) {
        contextStack.setBinding(control);
        contextStack.pushBinding(propertyContext, element);
        final NodeInfo currentSingleNode = contextStack.getCurrentSingleNode();
        if (currentSingleNode == null) {
            return null;
        } else {
            final String value = XFormsInstance.getValueForNodeInfo(currentSingleNode);
            contextStack.popBinding();
            return value;
        }
    }

    public void setMediatype(PropertyContext propertyContext, String mediatype) {
        setInfoValue(propertyContext, mediatypeElement, mediatype);
    }

    public void setFilename(PropertyContext propertyContext, String filename) {
        // Depending on web browsers, the filename may contain a path or not.

        // Normalize below to just the file name.
        final String normalized = StringUtils.replace(filename, "\\", "/");
        final int index = normalized.lastIndexOf('/');
        final String justFileName = (index == -1) ? normalized : normalized.substring(index + 1);

        setInfoValue(propertyContext, filenameElement, justFileName);
    }

    public void setSize(PropertyContext propertyContext, String size) {
        setInfoValue(propertyContext, sizeElement, size);
    }

    private void setInfoValue(PropertyContext propertyContext, Element element, String value) {
        if (element == null || value == null)
            return;

        contextStack.setBinding(control);
        contextStack.pushBinding(propertyContext, element);
        final NodeInfo currentSingleNode = contextStack.getCurrentSingleNode();
        if (currentSingleNode != null) {
            XFormsSetvalueAction.doSetValue(propertyContext, control.getXBLContainer().getContainingDocument(), control, currentSingleNode, value, null, false);
            contextStack.popBinding();
        }
    }

    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException e) {
            throw new OXFException(e);
        }
    }
}