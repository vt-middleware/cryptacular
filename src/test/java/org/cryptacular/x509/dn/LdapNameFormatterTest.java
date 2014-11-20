/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import javax.security.auth.x500.X500Principal;
import org.cryptacular.util.CertUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link LdapNameFormatter} class.
 *
 * @author  Middleware Services
 */
public class LdapNameFormatterTest
{
  private static final String CRT_PATH = "src/test/resources/certs/";

  @DataProvider(name = "distinguished-names")
  public Object[][] getDistinguishedNames()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt")
            .getSubjectX500Principal(),
          "C=US,DC=vt,DC=edu,O=Virginia Polytechnic Institute and State " +
            "University,CN=Marvin S Addison,UID=1145718",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt")
            .getIssuerX500Principal(),
          "SERIALNUMBER=12,CN=DEV Virginia Tech Class 1 Server CA,O=Virginia " +
            "Polytechnic Institute and State University,C=US,DC=vt,DC=edu",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "glider.cc.vt.edu.crt")
            .getSubjectX500Principal(),
          "C=US,DC=edu,DC=vt,ST=Virginia,L=Blacksburg," +
            "O=Virginia Polytechnic Institute and State University," +
            "OU=Middleware-Client,OU=SETI,SERIALNUMBER=1248110657961," +
            "CN=glider.cc.vt.edu",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "glider.cc.vt.edu.crt")
            .getIssuerX500Principal(),
          "CN=Virginia Tech Middleware CA,O=Virginia Polytechnic Institute " +
            "and State University,C=US,DC=vt,DC=edu",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "multi-value-rdn-1.crt")
            .getSubjectX500Principal(),
          "CN=b.foo.com,CN=a.foo.com,DC=ldaptive,DC=org",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "multi-value-rdn-2.crt")
            .getSubjectX500Principal(),
          "DC=org,DC=ldaptive,CN=a.foo.com+CN=b.foo.com",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "needs-escaping-1.crt")
            .getSubjectX500Principal(),
          "CN=DC=example\\, DC=com,O=VPI&SU,L=Blacksburg,ST=Virginia," +
            "C=US,DC=vt,DC=edu",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "needs-escaping-2.crt")
            .getSubjectX500Principal(),
          "CN=\\#DEADBEEF,O=VPI&SU,L=Blacksburg,ST=Virginia,C=US,DC=vt,DC=edu",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "needs-escaping-3.crt")
            .getSubjectX500Principal(),
          "CN=\\ space,O=VPI&SU,L=Blacksburg,ST=Virginia,C=US,DC=vt,DC=edu",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "needs-escaping-4.crt")
            .getSubjectX500Principal(),
          "CN=space2 \\ ,O=VPI&SU,L=Blacksburg,ST=Virginia,C=US,DC=vt,DC=edu",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "unknown-dn-attr.crt")
            .getSubjectX500Principal(),
          "DC=org,DC=example,1.2.3.4.5=#6e6f6e73656e7365,CN=marzipan",
        },
      };
  }


  @Test(dataProvider = "distinguished-names")
  public void testFormat(final X500Principal dn, final String expected)
    throws Exception
  {
    assertEquals(new LdapNameFormatter().format(dn), expected);
  }
}
