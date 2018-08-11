import org.apache.commons.lang.StringUtils;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;

/**
 * Spnego auth module able to generate http header for Negotiate authorization.
 */
public class SpnegoAuth implements AutoCloseable {
  private static final Logger LOG = LoggerFactory.getLogger(SpnegoAuth.class);

  private static final String SPNEGO_OID = "1.3.6.1.5.5.2";
  private static final String KERBEROS_OID = "1.2.840.113554.1.2.2";

  public static final String NEGOTIATE_HEADER_NAME = "negotiate";

  private String krb5Conf;
  private String loginConf;
  private LoginContext loginContext;
  private byte[] latestToken;

  /**
   * Initializes the SpnegoAuth module, including logging into the LoginContext with the given Login context entry name.
   *
   * @param loginContextEntryName The name of the entry to use in the java.security.auth.login.config file.
   */
  public SpnegoAuth(String loginContextEntryName) throws LoginException {
    krb5Conf = System.getProperty("java.security.krb5.conf");
    loginConf = System.getProperty("java.security.auth.login.config");
    if (!isSpnegoConfigured()) {
      throw new LoginException("Login failed because JVM does not have required Java security system properties " +
          "\"java.security.krb5.conf\" and \"java.security.auth.login.config\".");
    }
    loginContext = new LoginContext(loginContextEntryName);
    loginContext.login();
    latestToken = new byte[0];
  }

  /**
   * True if both of the krb5 and the login.conf system properties are specified.
   *
   * @return
   */
  public boolean isSpnegoConfigured() {
    return StringUtils.isNotBlank(krb5Conf) && StringUtils.isNotBlank(loginConf);
  }

  /**
   * @param url The URL you want to auth against.
   * @return Auth token that can sent
   * @throws GSSException
   * @throws java.security.PrivilegedActionException
   */
  public String getAuthorizationHeader(String url) throws GSSException, java.security.PrivilegedActionException, URISyntaxException {
    URI uri = new URI(url);
    Oid negotiationOid = new Oid(SPNEGO_OID);

    GSSManager manager = GSSManager.getInstance();
    final PrivilegedExceptionAction<GSSCredential> action = () -> manager.createCredential(null,
        GSSCredential.INDEFINITE_LIFETIME, negotiationOid, GSSCredential.INITIATE_AND_ACCEPT);

    boolean tryKerberos = false;
    GSSContext gssContext = null;
    try {
      try {
        GSSName serverName = manager.createName("HTTP@" + uri.getHost(), GSSName.NT_HOSTBASED_SERVICE);
        gssContext = manager.createContext(serverName.canonicalize(negotiationOid),
            negotiationOid, Subject.doAs(loginContext.getSubject(), action), GSSContext.DEFAULT_LIFETIME);
        gssContext.requestMutualAuth(true);
        gssContext.requestCredDeleg(true);
      } catch (GSSException ex) {
        if (ex.getMajor() == GSSException.BAD_MECH) {
          LOG.debug("GSSException BAD_MECH, retrying with Kerberos MECH");
          tryKerberos = true;
        } else {
          throw ex;
        }
      }
      if (tryKerberos) {
        Oid kerbOid = new Oid(KERBEROS_OID);
        GSSName serverName = manager.createName("HTTP@" + uri.getHost(), GSSName.NT_HOSTBASED_SERVICE);
        gssContext = manager.createContext(serverName.canonicalize(kerbOid), kerbOid, Subject.doAs(loginContext.getSubject(), action),
            GSSContext.DEFAULT_LIFETIME);
        gssContext.requestMutualAuth(true);
        gssContext.requestCredDeleg(true);
      }

      latestToken = gssContext.initSecContext(latestToken, 0, latestToken.length);

      return convertTokenToAuthorizationHeader(latestToken);
    } finally {
      try {
        if (gssContext != null) {
          gssContext.dispose();
        }
      } catch (GSSException e) {
        // ignore
      }
    }
  }

  private String convertTokenToAuthorizationHeader(byte[] token) {
    return "Negotiate" + " " + Base64.getEncoder().encodeToString(token);
  }

  @Override
  public void close() {
    if (loginContext != null) {
      try {
        loginContext.logout();
      } catch (LoginException e) {
        // Ignore
      }
    }
  }
}
