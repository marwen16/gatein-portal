package org.exoplatform.authentication.cert.x509;

import com.sun.net.ssl.TrustManagerFactory;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

/**
 * Created by eXo Platform MEA on 28/05/14.
 *
 * @author <a href="mailto:mtrabelsi@exoplatform.com">Marwen Trabelsi</a>
 */
public class X509CredentialExtractorServlet extends HttpServlet {

  private static final Log LOG = ExoLogger.getLogger("org.exoplatform.login.servlet.X509CredentialExtractorServlet");

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    resp.setContentType("text/html");
    PrintWriter out = resp.getWriter();

    String cipherSuite = (String) req.getAttribute("javax.servlet.request.cipher_suite");
    String remoteUser = req.getRemoteUser();

    if (cipherSuite != null) {
      out.write("Here is the certificate for \"" + remoteUser + "\" with following cipher_suite: \"" + cipherSuite + "\"<br/>");
      X509Certificate[] certChain = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
      if (certChain != null) {
        for (int i = 0; i < certChain.length; i++) {
          LOG.info("Client Certificate [" + i + "] = "
              + certChain[i].toString());
          out.println(certChain[i].getSubjectDN().getName() + "<br/>");
        }
      }
      if (certChain.length > 0) {
        X509Certificate userCert = certChain[0];
        String subjectDN = userCert.getSubjectDN().getName();
        String username = subjectDN.substring(subjectDN.lastIndexOf('=') +1 , subjectDN.length());
      }
    } else {
      LOG.warn("javax.servlet.request.cipher_suite IS NULL");
      out.write("You have to provide a valide certificate");
    }
  }

  protected boolean validateCredential(String alias, X509Certificate cert) throws NoSuchProviderException, KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException {
// truststore
    KeyStore ts = KeyStore.getInstance("JKS", "SUN");
    ts.load(X509CredentialExtractorServlet.class.getResourceAsStream("/usr/local/java/jdk1.6.0_45/jre/lib/security/cacerts"), "changeit".toCharArray());
// if you remove me, you've got 'javax.net.ssl.SSLPeerUnverifiedException: peer not authenticated' on missing truststore
    if (0 == ts.size()) throw new IOException("Error loading truststore");
// tmf
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(ts);
// keystore
    KeyStore ks = KeyStore.getInstance("PKCS12", "SunJSSE");
    ks.load(X509CredentialExtractorServlet.class.getResourceAsStream("usr/local/java/jdk1.6.0_45/jre/lib/security/cacerts"), "changeit".toCharArray());
// if you remove me, you've got 'javax.net.ssl.SSLPeerUnverifiedException: peer not authenticated' on missing keystore
    if (0 == ks.size()) throw new IOException("Error loading keystore");

/*    if( trace )
      log.trace("enter: validateCredentail(String, X509Certificate)");
    boolean isValid = false;

    // if we don't have a trust store, we'll just use the key store.
    KeyStore keyStore = null;
    KeyStore trustStore = null;
    if( domain != null )
    {
      if (domain instanceof SecurityDomain)
      {
        keyStore = ((SecurityDomain) domain).getKeyStore();
        trustStore = ((SecurityDomain) domain).getTrustStore();
      }
      else
      if (domain instanceof JSSESecurityDomain)
      {
        keyStore = ((JSSESecurityDomain) domain).getKeyStore();
        trustStore = ((JSSESecurityDomain) domain).getTrustStore();
      }
    }
    if( trustStore == null )
      trustStore = keyStore;

    if( verifier != null )
    {
      // Have the verifier validate the cert
      if( trace )
        log.trace("Validating cert using: "+verifier);
      isValid = verifier.verify(cert, alias, keyStore, trustStore);
    }
    else if (trustStore != null && cert != null)
    {
      // Look for the cert in the truststore using the alias
      X509Certificate storeCert = null;
      try
      {
        storeCert = (X509Certificate) trustStore.getCertificate(alias);
        if( trace )
        {
          StringBuffer buf = new StringBuffer("\n\tSupplied Credential: ");
          buf.append(cert.getSerialNumber().toString(16));
          buf.append("\n\t\t");
          buf.append(cert.getSubjectDN().getName());
          buf.append("\n\n\tExisting Credential: ");
          if( storeCert != null )
          {
            buf.append(storeCert.getSerialNumber().toString(16));
            buf.append("\n\t\t");
            buf.append(storeCert.getSubjectDN().getName());
            buf.append("\n");
          }
          else
          {
            ArrayList<String> aliases = new ArrayList<String>();
            Enumeration<String> en = trustStore.aliases();
            while (en.hasMoreElements())
            {
              aliases.add(en.nextElement());
            }
            buf.append("No match for alias: "+alias+", we have aliases " + aliases);
          }
          log.trace(buf.toString());
        }
      }
      catch (KeyStoreException e)
      {
        log.warn("failed to find the certificate for " + alias, e);
      }
      // Ensure that the two certs are equal
      if (cert.equals(storeCert))
        isValid = true;
    }
    else
    {
      log.warn("Domain, KeyStore, or cert is null. Unable to validate the certificate.");
    }

    if( trace )
    {
      log.trace("The supplied certificate "
          + (isValid ? "matched" : "DID NOT match")
          + " the certificate in the keystore.");

      log.trace("exit: validateCredentail(String, X509Certificate)");
    }
    return isValid;
  }*/
    return true;
  }
}
