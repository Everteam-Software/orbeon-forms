package com.voliasoftware.transport;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.lang.ArrayUtils;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * AuthSSLX509TrustManager makes decision is server (or client) trusted or not.
 *
 * @author Adapted for widely usage by Vitaliy Zadvornov
 */

public class AuthSSLX509TrustManager implements X509TrustManager {

    private static Log g_log = LogFactory.getLog(AuthSSLX509TrustManager.class);

    public static final String ERR_MSG_CERTIFIVATE_NOT_FOUND = "Certificate not found";
    public static final String ERR_MSG_NO_ONE_CERT_FOUND_IN_TRUSTED_ISSUERS =
            "No one certificate found in accepted issuers";
    /**
     * Default trust manager.
     */
    private X509TrustManager m_defaultTrustManager = null;

    /**
     * Default constructor.
     */
    public AuthSSLX509TrustManager() {

    }


    /**
     * Constructor for AuthSSLX509TrustManager.
     */
    public AuthSSLX509TrustManager(final X509TrustManager defaultTrustManager) {
        super();
        if (defaultTrustManager == null) {
            throw new IllegalArgumentException("Trust manager may not be null");
        }
        this.m_defaultTrustManager = defaultTrustManager;
    }


    public void checkClientTrusted(final X509Certificate[] certificates, final String string)
            throws CertificateException {
        applySimpleTrustMechanism(certificates);
    }

    public void checkServerTrusted(final X509Certificate[] certificates, final String string)
            throws CertificateException {
        applySimpleTrustMechanism(certificates);
    }

    /**
     * This method trying to find server/client certificates in own accepted issuers chain.
     * This method is trying to find at least one certificate from endpoint in local keystore (truststore),
     * if at least one of the certificates is matched, then endpoint is trusted, otherwise - not.      
     * @param certificates X.509 certificates
     * @throws CertificateException if no one of given server/client certificates
     *                              do not found in accepted list, otherwise all OK
     */
    private void applySimpleTrustMechanism(final X509Certificate[] certificates) throws CertificateException {
        if (certificates.length == 0) {
            throw new CertificateException(ERR_MSG_CERTIFIVATE_NOT_FOUND);
        }
        final X509Certificate[] acceptedIssuers = getAcceptedIssuers();
        boolean isAtLeasOneCertFoundInTrustedList = false;
        for (int i = 0; i < certificates.length; i++) {
            final X509Certificate certificate = certificates[i];
            certificate.checkValidity();
            if(ArrayUtils.contains(acceptedIssuers, certificate)){
                isAtLeasOneCertFoundInTrustedList = true;
                break;
            }
        }
        if(!isAtLeasOneCertFoundInTrustedList){
            throw new CertificateException(ERR_MSG_NO_ONE_CERT_FOUND_IN_TRUSTED_ISSUERS);
        }
    }


    public X509Certificate[] getAcceptedIssuers() {
        return m_defaultTrustManager.getAcceptedIssuers();
    }

    public boolean isClientTrusted(final X509Certificate[] x509Certificates) {
        try {
            checkClientTrusted(x509Certificates, "TLS");
            return true;
        } catch(CertificateException ce) {
            return false;
        }
    }

    public boolean isServerTrusted(final X509Certificate[] x509Certificates) {
        try {
            checkServerTrusted(x509Certificates, "TLS");
            return true;
        } catch(CertificateException ce) {
            return false;
        }
    }
}
