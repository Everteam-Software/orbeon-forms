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
package org.orbeon.oxf.resources.handler;

import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpConnectionManager;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.HttpState;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.NTCredentials;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.contrib.ssl.AuthSSLProtocolSocketFactory;
import org.apache.commons.httpclient.methods.DeleteMethod;
import org.apache.commons.httpclient.methods.EntityEnclosingMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.HeadMethod;
import org.apache.commons.httpclient.methods.OptionsMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.PutMethod;
import org.apache.commons.httpclient.methods.TraceMethod;
import org.apache.commons.httpclient.params.HttpConnectionManagerParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.orbeon.oxf.common.OXFException;
import org.orbeon.oxf.properties.Properties;
import org.orbeon.oxf.util.Connection;
import org.orbeon.oxf.util.StringUtils;

import pe.utils.IpAddressUtils;

import com.voliasoftware.transport.AuthSSLX509TrustManager;

public class HTTPURLConnection extends URLConnection {

    public static String PROXY_HOST_PROPERTY = "oxf.http.proxy.host";
    public static String PROXY_PORT_PROPERTY = "oxf.http.proxy.port";
	public static String PROXY_USERNAME_PROPERTY = "oxf.http.proxy.username";
	public static String PROXY_PASSWORD_PROPERTY = "oxf.http.proxy.password";
	public static String PROXY_NTLM_HOST_PROPERTY = "oxf.http.proxy.ntlm.host";
	public static String PROXY_NTLM_DOMAIN_PROPERTY = "oxf.http.proxy.ntlm.domain";

    // Use a single shared connection manager so we can have efficient connection pooling
    private static HttpConnectionManager connectionManager;
    private static Log logger = LogFactory.getLog(HTTPURLConnection.class);
    
    static {
        connectionManager = new MultiThreadedHttpConnectionManager();
        final HttpConnectionManagerParams params = new HttpConnectionManagerParams();
        params.setDefaultMaxConnectionsPerHost(Integer.MAX_VALUE);
        params.setMaxTotalConnections(Integer.MAX_VALUE);
        // The code commented below disables retries. By default HttpClient will try 3 times, and it is not clear
        // if this is a good thing or not in our case.
        //DefaultHttpMethodRetryHandler retryHandler = new DefaultHttpMethodRetryHandler(0, false);
        //params.setParameter(HttpMethodParams.RETRY_HANDLER, retryHandler);
        connectionManager.setParams(params);
        
        URL trustStore = HTTPURLConnection.class.getClassLoader().getResource("orbeon.jks");
        if(trustStore != null)
            setupSSL(trustStore, "peabb");
        else
            logger.warn("Default keystore \"orbeon.jks\" not found in classpath. SSL support disabled.");
    }

    private static void setupSSL(URL keystore, String storePass) {
        // This sets up the security providers for HTTPS communication
        Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());
        // This gives the ability to parse URLs with the HTTPS protocol. It is not needed by HttpClient
        System.setProperty("java.protocol.handler.pkgs", "com.sun.net.ssl.internal.www.protocol");

        // set up a secure socket factory, that will use a custom trust manager that trusts any certificate
        // found in its truststore
        final ProtocolSocketFactory authSSLHttpsSocketFactory =
                new AuthSSLProtocolSocketFactory(keystore, storePass, "SunX509", AuthSSLX509TrustManager.class);

        final Protocol authSSLHttpsProtocol = new Protocol("https", authSSLHttpsSocketFactory, 443);
        // register this as the default HTTPS handler
        Protocol.registerProtocol("https", authSSLHttpsProtocol);

        //Protocol.
        // set up a secure socket factory, that will trust anything, including expired certificates.
        // This will be used as a backup system when the AuthSSLX509TrustManager does not validate a certificate.
        // So, if a certificate ever expires in production, then the system will not come to a halt
        // This Trust Manager will write to the error log in case of expired certificates, so the appropriate
        // integration point can be contacted
    }
    
    private HttpState httpState;

    private URL url;
    private boolean connected = false;
    private HttpMethodBase method;
    private int responseCode;
    private byte[] requestBody;
    private Map<String, String[]> requestProperties = new LinkedHashMap<String, String[]>();    // LinkedHashMap<String lowercaseHeaderName, String[] headerValues>
    private HashMap<String, List<String>> responseHeaders;

    private String username;
    private String password;

    public HTTPURLConnection(URL url) {
        super(url);
        this.url = url;
    }

    public void setRequestMethod(String methodName) throws ProtocolException {
        if (connected)
            throw new ProtocolException("Can't reset method: already connected");

        if ("GET".equals(methodName)) method = new GetMethod(url.toString());
        else if ("POST".equals(methodName)) method = new PostMethod(url.toString());
        else if ("HEAD".equals(methodName)) method = new HeadMethod(url.toString());
        else if ("OPTIONS".equals(methodName)) method = new OptionsMethod(url.toString());
        else if ("PUT".equals(methodName)) method = new PutMethod(url.toString());
        else if ("DELETE".equals(methodName)) method = new DeleteMethod(url.toString());
        else if ("TRACE".equals(methodName)) method = new TraceMethod(url.toString());
        else throw new ProtocolException("Method " + methodName + " not supported");
    }

    public HttpState getHttpState() {
        return httpState;
    }

    public void setHttpState(HttpState httpState) {
        this.httpState = httpState;
    }

    public void connect() throws IOException {
        if (!connected) {
            final String userinfo = url.getUserInfo();
            final boolean isAuthenticationRequestedWithUsername = username != null && !username.equals("");

            // Create the HTTP client (this *should* be fairly lightweight)
            final HttpClient httpClient = new HttpClient(connectionManager);

            // Determine which state to use
            if (httpState != null) {
                // Use state provided by user
                httpClient.setState(httpState);
            } else {
                // Expose state created by HttpClient
                httpState = httpClient.getState();
            }

            // Make authentication preemptive
            if (userinfo != null || isAuthenticationRequestedWithUsername)
                httpClient.getParams().setAuthenticationPreemptive(true);

            // Set proxy if defined in properties
            final String proxyHost = Properties.instance().getPropertySet().getString(PROXY_HOST_PROPERTY);
            final Integer proxyPort = Properties.instance().getPropertySet().getInteger(PROXY_PORT_PROPERTY);
			if (proxyHost != null && proxyPort != null) {
                httpClient.getHostConfiguration().setProxy(proxyHost, proxyPort);

				// Proxy authentication
				final String proxyUsername = Properties.instance().getPropertySet().getString(PROXY_USERNAME_PROPERTY);
				final String proxyPassword = Properties.instance().getPropertySet().getString(PROXY_PASSWORD_PROPERTY);
				if (proxyUsername != null && proxyPassword != null) {
					final Credentials proxyCred;
					{
						final String ntlmHost = Properties.instance().getPropertySet().getString(PROXY_NTLM_HOST_PROPERTY);
						final String ntlmDomain = Properties.instance().getPropertySet().getString(PROXY_NTLM_DOMAIN_PROPERTY);
						if(ntlmHost != null && ntlmDomain != null){
							proxyCred = new NTCredentials(proxyUsername, proxyPassword,ntlmHost,ntlmDomain);
						}else{
							proxyCred = new UsernamePasswordCredentials(proxyUsername, proxyPassword);
						}

					}
					httpClient.getState().setProxyCredentials(AuthScope.ANY, proxyCred);
				}
			}

            if (userinfo != null) {
                // Set username and optional password specified on URL
                final int separatorPosition = userinfo.indexOf(":");
                String username = separatorPosition == -1 ? userinfo : userinfo.substring(0, separatorPosition);
                String password = separatorPosition == -1 ? "" : userinfo.substring(separatorPosition + 1);
                // If the username/password contain special character, those character will be encoded, since we
                // are getting this from a URL. Now do the decoding.
                username = URLDecoder.decode(username, "utf-8");
                password = URLDecoder.decode(password, "utf-8");
                httpClient.getState().setCredentials(
                    new AuthScope(url.getHost(), url.getPort()),
                    new UsernamePasswordCredentials(username, password)
                );
            } else if (isAuthenticationRequestedWithUsername) {
                // Set username and password specified externally
                httpClient.getState().setCredentials(
                    new AuthScope(url.getHost(), url.getPort()),
                    new UsernamePasswordCredentials(username, password == null ? "" : password)
                );
            }

            if(!skipProxy(url.toString()))
                setProxy(httpClient);
                
            // If method has not been set, use GET
            if (method == null)
                method = new GetMethod(url.toString());

            // Set all headers
            // NOTE: Do headers first so we can benefit from method.removeRequestHeader () and method.getRequestHeader() later
            for (Map.Entry<String, String[]> currentEntry: requestProperties.entrySet()) {
                final String currentHeaderName = currentEntry.getKey();
                final String[] currentHeaderValues = currentEntry.getValue();

                for (final String currentHeaderValue: currentHeaderValues) {
                	if (!"authorization".equalsIgnoreCase(currentHeaderName) || (userinfo == null && username == null))
                		method.addRequestHeader(currentHeaderName, currentHeaderValue);
                }
            }

            // If there is some user authentication specified so remove Authorization header if present
            if (userinfo != null || username != null) {
                method.removeRequestHeader(Connection.AUTHORIZATION_HEADER);// header names are case-insensitive for comparison
            }

            // Create request entity with body
            if (requestBody != null && method instanceof EntityEnclosingMethod) {
                final Header contentTypeHeader = method.getRequestHeader("Content-Type");// header names are case-insensitive for comparison
                if (contentTypeHeader == null)
                    throw new ProtocolException("Can't set request entity: Content-Type header is missing");
                final HandlerRequestEntity requestEntity = new HandlerRequestEntity(requestBody, contentTypeHeader.getValue());
                ((EntityEnclosingMethod) method).setRequestEntity(requestEntity);
            }

            // Handle authentication challenge
            method.setDoAuthentication(true);

            // Make request
            responseCode = httpClient.executeMethod(method);
            connected = true;
        }
    }

    private static boolean skipProxy(final String url) throws UnknownHostException {

        String skipProxy = System.getProperties().getProperty("http.skipProxy");

        return skipProxy != null && IpAddressUtils.isHostsContainsUrlHost(skipProxy.split(","), url);

    }

    private static void setProxy(final HttpClient httpClient) {

        java.util.Properties props = System.getProperties();

        String useProxy = props.getProperty("http.useProxy");
        if(Boolean.parseBoolean(useProxy)) {
            String proxyHost = props.getProperty("http.proxyHost");
            int proxyPort = Integer.parseInt(props.getProperty("http.proxyPort"));
            String proxyUser = props.getProperty("http.proxyUser");
            String proxyPassword = props.getProperty("http.proxyPassword");

            Credentials credentials = null;
            if (proxyUser != null && proxyUser.length() != 0) {
            	credentials = new UsernamePasswordCredentials(proxyUser, proxyPassword);
            }

            httpClient.getHostConfiguration().setProxy(proxyHost, proxyPort);
            httpClient.getState().setProxyCredentials(
                    new AuthScope(proxyHost, proxyPort, null),
                    credentials);
        }
    }
    public InputStream getInputStream() throws IOException {
        if (method == null) connect();
        return method.getResponseBodyAsStream();
    }

    public void setRequestBody(byte[] requestBody) throws IOException {
        this.requestBody = requestBody;
    }

    private void initResponseHeaders() {
        try {
            if (!connected)
                connect();
            if (responseHeaders == null) {
                responseHeaders = new HashMap<String, List<String>>();
                final Header[] headers = method.getResponseHeaders();
                for (int i = headers.length - 1; i >= 0; i--) {
                    responseHeaders.put(headers[i].getName().toLowerCase(), Collections.singletonList(headers[i].getValue()));

                    // HeaderElement does not contain what I thought it did and the code below doesn't work
//                    final HeaderElement[] elements = headers[i].getElements();
//                    if (elements.length == 1) {
//                        // Mosts common case
//                        responseHeaders.put(headers[i].getName().toLowerCase(), Collections.singletonList(elements[0].getValue()));
//                    } else {
//                        // General case
//                        final List<String> values = new ArrayList<String>(elements.length);
//                        for (HeaderElement element: elements) {
//                            values.add(element.getValue());
//                        }
//                        responseHeaders.put(headers[i].getName().toLowerCase(), values);
//                    }
                }
            }
        } catch (IOException e) {
            throw new OXFException(e);
        }
    }

    /**
     * This method will be called by URLConnection.getLastModified(), URLConnection.getContentLength(), etc.
     */
    @Override
    public String getHeaderField(String name) {
        initResponseHeaders();
        // We return the first header value only. This is not really right, is it? But it will work for the few calls
        // done by URLConnection.
        final List<String> values = responseHeaders.get(name);
        return (values != null) ? values.get(0) : null;
    }

    @Override
    public Map<String, List<String>> getHeaderFields() {
        initResponseHeaders();
        return responseHeaders;
    }

    @Override
    public void setRequestProperty(String key, String value) {
        super.setRequestProperty(key, value);
        requestProperties.put(key, new String[] { value });
    }

    @Override
    public void addRequestProperty(String key, String value) {
        super.addRequestProperty(key, value);
        StringUtils.addValueToStringArrayMap(requestProperties, key, value);
    }

    @Override
    public String getRequestProperty(String key) {
        // Not sure what should be returned so return the first value if any. But likely nobody is calling this method.
        final String[] values = requestProperties.get(key);
        return (values == null) ? null : values[0];
    }

    @Override
    public Map<String,List<String>> getRequestProperties() {
        return super.getRequestProperties();
    }

    public int getResponseCode() {
        return responseCode;
    }

    public void disconnect() {
        method.releaseConnection();
    }

    public void setUsername(String username) {
        this.username = username.trim();
    }

    public void setPassword(String password) {
        this.password = password.trim();
    }

    @Override
    public long getLastModified() {
        // Default implementation throws an exception if the header is not present, so optimize on calling side
        final String field = getHeaderField("last-modified");
        return (field != null) ? super.getLastModified() : 0;
    }
}
