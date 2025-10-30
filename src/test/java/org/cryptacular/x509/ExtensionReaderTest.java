/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509;

import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.cryptacular.FailListener;
import org.cryptacular.util.CertUtil;
import org.cryptacular.util.CodecUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link ExtensionReader}.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class ExtensionReaderTest
{
  private static final String CRT_PATH = "src/test/resources/certs/";

  @DataProvider(name = "subject-alt-name")
  public Object[][] getSubjectAltNames()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
          new String[] {"eprov@vt.edu"},
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "ed.middleware.vt.edu.crt"),
          new String[] {
            "ed.middleware.vt.edu",
            "directory.vt.edu",
            "id.directory.vt.edu",
            "authn.directory.vt.edu",
            "ldap.vt.edu",
          },
        },
      };
  }

  @DataProvider(name = "issuer-alt-name")
  public Object[][] getIssuerAltNames()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "test.example.com.crt"),
          new String[] {"snake-1.example.com", "snake-2.example.com"},
        },
      };
  }

  @DataProvider(name = "basic-constraints")
  public Object[][] getBasicConstraints()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "thawte-premium-server-ca.crt"),
          true,
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "login.live.com.crt"),
          false,
        },
      };
  }

  @DataProvider(name = "certificate-policies")
  public Object[][] getCertificatePolicies()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
          new PolicyInformation[] {
            new PolicyInformation(new ASN1ObjectIdentifier("1.3.6.1.4.1.6760.5.2.2.2.1")),
            new PolicyInformation(new ASN1ObjectIdentifier("1.3.6.1.4.1.6760.5.2.2.1.1")),
            new PolicyInformation(
              new ASN1ObjectIdentifier("1.3.6.1.4.1.6760.5.2.2.4.1"),
              new DERSequence(new PolicyQualifierInfo("http://www.pki.vt.edu/vtuca/cps/index.html"))),
            new PolicyInformation(new ASN1ObjectIdentifier("1.3.6.1.4.1.6760.5.2.2.3.1")),
          },
        },
      };
  }

  @DataProvider(name = "subject-key-id")
  public Object[][] getSubjectKeyIds()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
          "25:48:2F:28:EC:5D:19:BB:1D:25:AE:94:93:B1:7B:B5:35:96:24:66",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "login.live.com.crt"),
          "31:AE:F1:7C:98:67:E9:1F:19:69:A2:A7:84:1E:67:5C:AA:C3:6B:75",
        },
      };
  }

  @DataProvider(name = "authority-key-id")
  public Object[][] getAuthorityKeyIds()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
          "38:E0:6F:AE:48:ED:5E:23:F6:22:9B:1E:E7:9C:19:16:47:B8:7E:92",
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "login.live.com.crt"),
          "FC:8A:50:BA:9E:B9:25:5A:7B:55:85:4F:95:00:63:8F:E9:58:6B:43",
        },
      };
  }

  @DataProvider(name = "key-usage")
  public Object[][] getKeyUsage()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
          KeyUsageBits.usage(KeyUsageBits.DigitalSignature, KeyUsageBits.NonRepudiation),
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "login.live.com.crt"),
          KeyUsageBits.usage(KeyUsageBits.DigitalSignature, KeyUsageBits.KeyEncipherment),
        },
      };
  }

  @DataProvider(name = "extended-key-usage")
  public Object[][] getExtendedKeyUsage()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
          new KeyPurposeId[] {
            KeyPurposeId.id_kp_clientAuth,
            KeyPurposeId.id_kp_emailProtection,
            KeyPurposeId.id_kp_smartcardlogon,
          },
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "login.live.com.crt"),
          new KeyPurposeId[] {
            KeyPurposeId.id_kp_serverAuth,
            KeyPurposeId.id_kp_clientAuth,
          },
        },
      };
  }

  @DataProvider(name = "crl-distribution-points")
  public Object[][] getCrlDistributionPoints()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "login.live.com.crt"),
          new DistributionPoint[] {
            new DistributionPoint(
              new DistributionPointName(new GeneralNames(uri("http://EVSecure-crl.verisign.com/EVSecure2006.crl"))),
              null,
              null),
          },
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "glider.cc.vt.edu.crt"),
          new DistributionPoint[] {
            new DistributionPoint(
              new DistributionPointName(
                new GeneralNames(
                  uri(
                    "http://vtca-p.eprov.seti.vt.edu:8080/ejbca/publicweb/" +
                    "webdist/certdist?cmd=crl&" +
                    "issuer=CN=Virginia+Tech+Middleware+CA,O=Virginia+" +
                    "Polytechnic+Institute+and+State+University," +
                    "DC=vt,DC=edu,C=US"))),
              null,
              new GeneralNames(
                dirName(
                  "CN=Virginia Tech Middleware CA,O=Virginia Polytechnic " +
                  "Institute and State University,DC=vt,DC=edu,C=US"))),
          },
        },
      };
  }

  @DataProvider(name = "authority-information-access")
  public Object[][] getAuthorityInformationAccess()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "login.live.com.crt"),
          new AccessDescription[] {
            new AccessDescription(AccessDescription.id_ad_ocsp, uri("http://EVSecure-ocsp.verisign.com")),
            new AccessDescription(
              AccessDescription.id_ad_caIssuers,
              uri("http://EVSecure-aia.verisign.com/EVSecure2006.cer")),
          },
        },
      };
  }


  @Test(dataProvider = "subject-alt-name")
  public void testReadSubjectAlternativeName(final X509Certificate cert, final String[] expected)
    throws Exception
  {
    final GeneralNames names = new ExtensionReader(cert).readSubjectAlternativeName();
    assertThat(names.getNames().length).isEqualTo(expected.length);
    for (int i = 0; i < expected.length; i++) {
      assertThat(names.getNames()[i].getName().toString()).isEqualTo(expected[i]);
    }
  }

  @Test(dataProvider = "issuer-alt-name")
  public void testReadIssuerAlternativeName(final X509Certificate cert, final String[] expected)
    throws Exception
  {
    final GeneralNames names = new ExtensionReader(cert).readIssuerAlternativeName();
    assertThat(names.getNames().length).isEqualTo(expected.length);
    for (int i = 0; i < expected.length; i++) {
      assertThat(names.getNames()[i].getName().toString()).isEqualTo(expected[i]);
    }
  }

  @Test(dataProvider = "basic-constraints")
  public void testReadBasicConstraints(final X509Certificate cert, final boolean expected)
    throws Exception
  {
    assertThat(new ExtensionReader(cert).readBasicConstraints().isCA()).isEqualTo(expected);
  }

  @Test(dataProvider = "certificate-policies")
  public void testReadCertificatePolicies(final X509Certificate cert, final PolicyInformation[] expected)
    throws Exception
  {
    final List<PolicyInformation> policies = new ExtensionReader(cert).readCertificatePolicies();
    assertThat(policies.size()).isEqualTo(expected.length);

    PolicyInformation current;
    for (int i = 0; i < expected.length; i++) {
      current = policies.get(i);
      assertThat(current.getPolicyIdentifier()).isEqualTo(expected[i].getPolicyIdentifier());
      if (expected[i].getPolicyQualifiers() != null) {
        for (int j = 0; j < expected[i].getPolicyQualifiers().size(); j++) {
          assertThat(current.getPolicyQualifiers().getObjectAt(j))
            .isEqualTo(expected[i].getPolicyQualifiers().getObjectAt(j));
        }
      }
    }
  }

  @Test(dataProvider = "subject-key-id")
  public void testReadSubjectKeyIdentifier(final X509Certificate cert, final String expected)
    throws Exception
  {
    final SubjectKeyIdentifier keyId = new ExtensionReader(cert).readSubjectKeyIdentifier();
    assertThat(CodecUtil.hex(keyId.getKeyIdentifier(), true).toUpperCase()).isEqualTo(expected);
  }

  @Test(dataProvider = "authority-key-id")
  public void testReadAuthorityKeyIdentifier(final X509Certificate cert, final String expected)
    throws Exception
  {
    final AuthorityKeyIdentifier keyId = new ExtensionReader(cert).readAuthorityKeyIdentifier();
    assertThat(CodecUtil.hex(keyId.getKeyIdentifierOctets(), true).toUpperCase()).isEqualTo(expected);
  }

  @Test(dataProvider = "key-usage")
  public void testReadKeyUsage(final X509Certificate cert, final int expected)
    throws Exception
  {
    final KeyUsage usage = new ExtensionReader(cert).readKeyUsage();
    final byte[] bytes = usage.getBytes();
    final int result;
    if (bytes.length == 1) {
      result = bytes[0] & 0xff;
    } else {
      result = (bytes[1] & 0xff) << 8 | (bytes[0] & 0xff);
    }
    assertThat(result).isEqualTo(expected);
  }

  @Test(dataProvider = "extended-key-usage")
  public void testReadExtendedKeyUsage(final X509Certificate cert, final KeyPurposeId[] expected)
    throws Exception
  {
    final List<KeyPurposeId> purposes = new ExtensionReader(cert).readExtendedKeyUsage();
    assertThat(purposes.size()).isEqualTo(expected.length);
    for (int i = 0; i < expected.length; i++) {
      assertThat(purposes.get(i)).isEqualTo(expected[i]);
    }
  }

  @Test(dataProvider = "crl-distribution-points")
  public void testReadCRLDistributionPoints(final X509Certificate cert, final DistributionPoint[] expected)
    throws Exception
  {
    final List<DistributionPoint> points = new ExtensionReader(cert).readCRLDistributionPoints();
    assertThat(points.size()).isEqualTo(expected.length);
    for (int i = 0; i < expected.length; i++) {
      assertThat(points.get(i)).isEqualTo(expected[i]);
    }
  }

  @Test(dataProvider = "authority-information-access")
  public void testReadAuthorityInformationAccess(final X509Certificate cert, final AccessDescription[] expected)
    throws Exception
  {
    final List<AccessDescription> descriptions = new ExtensionReader(cert).readAuthorityInformationAccess();
    assertThat(descriptions.size()).isEqualTo(expected.length);
    for (int i = 0; i < expected.length; i++) {
      assertThat(descriptions.get(i)).isEqualTo(expected[i]);
    }
  }

  private GeneralName uri(final String uri)
  {
    return new GeneralName(GeneralName.uniformResourceIdentifier, uri);
  }

  private GeneralName dirName(final String dn)
  {
    return new GeneralName(GeneralName.directoryName, dn);
  }
}
