/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import java.security.cert.X509Certificate;
import org.cryptacular.FailListener;
import org.cryptacular.util.CertUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link NameReader}.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class NameReaderTest
{
  private static final String CRT_PATH = "src/test/resources/certs/";

  @DataProvider(name = "subjects")
  public Object[][] getSubjects()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
          "UID=1145718, CN=Marvin S Addison, O=Virginia Polytechnic " +
            "Institute and State University, DC=edu, DC=vt, C=US",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "glider.cc.vt.edu.crt"),
          "CN=glider.cc.vt.edu, SERIALNUMBER=1248110657961, OU=SETI, " +
            "OU=Middleware-Client, O=Virginia Polytechnic Institute and " +
            "State University, L=Blacksburg, ST=Virginia, DC=vt, DC=edu, C=US",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "multi-value-rdn-1.crt"),
          "DC=org, DC=ldaptive, CN=a.foo.com, CN=b.foo.com",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "multi-value-rdn-2.crt"),
          "CN=a.foo.com, CN=b.foo.com, DC=ldaptive, DC=org",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "scantor-dn-description.crt"),
          "DESCRIPTION=6MtpJS1dcC7t254v, CN=cantor.2@osu.edu, EMAILADDRESS=cantor.2@osu.edu",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "unknown-dn-attr.crt"),
          "CN=marzipan, 1.2.3.4.5=nonsense, DC=example, DC=org",
        },
      };
  }

  @DataProvider(name = "issuers")
  public Object[][] getIssuers()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
          "DC=edu, DC=vt, C=US, O=Virginia Polytechnic Institute and State " +
            "University, CN=DEV Virginia Tech Class 1 Server CA, SERIALNUMBER=12",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "glider.cc.vt.edu.crt"),
          "DC=edu, DC=vt, C=US, O=Virginia Polytechnic Institute and State University, CN=Virginia Tech Middleware CA",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "multi-value-rdn-1.crt"),
          "DC=org, DC=ldaptive, CN=a.foo.com, CN=b.foo.com",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "multi-value-rdn-2.crt"),
          "CN=a.foo.com, CN=b.foo.com, DC=ldaptive, DC=org",
        },
      };
  }

  @Test(dataProvider = "subjects")
  public void testReadSubject(final X509Certificate cert, final String expected)
    throws Exception
  {
    final RDNSequence sequence = new NameReader(cert).readSubject();
    assertThat(sequence.toString()).isEqualTo(expected);
  }

  @Test(dataProvider = "issuers")
  public void testReadIssuer(final X509Certificate cert, final String expected)
    throws Exception
  {
    final RDNSequence sequence = new NameReader(cert).readIssuer();
    assertThat(sequence.toString()).isEqualTo(expected);
  }
}
