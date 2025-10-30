/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.cryptacular.FailListener;
import org.cryptacular.generator.KeyPairGenerator;
import org.cryptacular.x509.GeneralNameType;
import org.cryptacular.x509.KeyUsageBits;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link CertUtil} class.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class CertUtilTest
{
  private static final String CRT_PATH = "src/test/resources/certs/";

  @DataProvider(name = "subject-cn")
  public Object[][] getSubjectCommonNames()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "ed.middleware.vt.edu.crt"),
          "ed.middleware.vt.edu",
        },
      };
  }

  @DataProvider(name = "subject-dn")
  public Object[][] getSubjectDN()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "ed.middleware.vt.edu.crt"),
          "C=US,DC=edu,DC=vt,ST=Virginia,L=Blacksburg,O=Virginia Polytechnic Institute and State University," +
            "OU=Middleware-Server-with-saltr,OU=Middleware Services,CN=ed.middleware.vt.edu",
        },
      };
  }

  @DataProvider(name = "subject-dn-spaces")
  public Object[][] getSubjectDNWithSpaces()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "ed.middleware.vt.edu.crt"),
          "C=US, DC=edu, DC=vt, ST=Virginia, L=Blacksburg, O=Virginia Polytechnic Institute and State University, " +
            "OU=Middleware-Server-with-saltr, OU=Middleware Services, CN=ed.middleware.vt.edu",
        },
      };
  }


  @DataProvider(name = "encode-cert-p7")
  public Object[][] getP7EncodedCert() throws Exception
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "ed.middleware.vt.edu.crt"),
          new String(Files.readAllBytes(new File(CRT_PATH + "ed.middleware.vt.edu.p7b").toPath())),
        },
      };
  }

  @DataProvider(name = "encode-cert-x509")
  public Object[][] getX509Cert() throws Exception
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "ed.middleware.vt.edu.crt"),
          new String(Files.readAllBytes(new File(CRT_PATH + "ed.middleware.vt.edu.crt").toPath())),
        },
      };
  }

  @DataProvider(name = "encode-cert-der")
  public Object[][] getDERCert() throws Exception
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "ed.middleware.vt.edu.crt"),
          Files.readAllBytes(new File(CRT_PATH + "ed.middleware.vt.edu.der").toPath()),
        },
      };
  }

  @DataProvider(name = "subject-alt-names")
  public Object[][] getSubjectAltNames()
  {
    return
      new Object[][] {
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

  @DataProvider(name = "subject-alt-names-by-type")
  public Object[][] getSubjectAltNamesByType()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "ed.middleware.vt.edu.crt"),
          new GeneralNameType[] {GeneralNameType.DNSName},
          new String[] {
            "ed.middleware.vt.edu",
            "directory.vt.edu",
            "id.directory.vt.edu",
            "authn.directory.vt.edu",
            "ldap.vt.edu",
          },
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "ed.middleware.vt.edu.crt"),
          new GeneralNameType[] {GeneralNameType.RFC822Name},
          new String[0],
        },
      };
  }

  @DataProvider(name = "subject-names")
  public Object[][] getSubjectNames()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
          new String[] {"Marvin S Addison", "eprov@vt.edu"},
        },
      };
  }

  @DataProvider(name = "subject-names-by-type")
  public Object[][] getSubjectNamesByType()
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
          new GeneralNameType[] {GeneralNameType.RFC822Name},
          new String[] {"Marvin S Addison", "eprov@vt.edu"},
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
          new GeneralNameType[] {GeneralNameType.OtherName},
          new String[] {"Marvin S Addison"},
        },
      };
  }

  @DataProvider(name = "entity-certificate")
  public Object[][] getEntityCertificates()
    throws Exception
  {
    return
      new Object[][] {
        new Object[] {
          KeyPairUtil.readPrivateKey(CRT_PATH + "entity.key"),
          new X509Certificate[] {
            CertUtil.readCertificate(CRT_PATH + "glider.cc.vt.edu.crt"),
            CertUtil.readCertificate(CRT_PATH + "login.live.com.crt"),
            CertUtil.readCertificate(CRT_PATH + "entity.crt"),
          },
          CertUtil.readCertificate(CRT_PATH + "entity.crt"),
        },
      };
  }

  @DataProvider(name = "basic-usage")
  public Object[][] getBasicUsage()
    throws Exception
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
          new KeyUsageBits[] {
            KeyUsageBits.DigitalSignature,
            KeyUsageBits.NonRepudiation,
          },
        },
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "login.live.com.crt"),
          new KeyUsageBits[] {
            KeyUsageBits.DigitalSignature,
            KeyUsageBits.KeyEncipherment,
          },
        },
      };
  }

  @DataProvider(name = "extended-usage")
  public Object[][] getExtendedUsage()
    throws Exception
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
            KeyPurposeId.id_kp_clientAuth,
            KeyPurposeId.id_kp_serverAuth,
          },
        },
      };
  }

  @DataProvider(name = "has-policies")
  public Object[][] getHasPolicies()
    throws Exception
  {
    return
      new Object[][] {
        new Object[] {
          CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
          new String[] {
            "1.3.6.1.4.1.6760.5.2.2.1.1",
            "1.3.6.1.4.1.6760.5.2.2.2.1",
            "1.3.6.1.4.1.6760.5.2.2.3.1",
            "1.3.6.1.4.1.6760.5.2.2.4.1",
          },
        },
      };
  }

  @DataProvider(name = "subject-keyid")
  public Object[][] getSubjectKeyId()
    throws Exception
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

  @DataProvider(name = "authority-keyid")
  public Object[][] getAuthorityKeyId()
    throws Exception
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

  @DataProvider(name = "cert-chains")
  public Object[][] getCertificateChains()
    throws Exception
  {
    return new Object[][] {
        {CRT_PATH + "vtgsca_chain.pem", 4},
        {CRT_PATH + "vtuca_chain.p7b", 2},
      };
  }


  @Test(dataProvider = "subject-cn")
  public void testSubjectCN(final X509Certificate cert, final String expected)
  {
    assertThat(CertUtil.subjectCN(cert)).isEqualTo(expected);
  }

  @Test(dataProvider = "subject-alt-names")
  public void testSubjectAltNames(final X509Certificate cert, final String[] expected)
    throws Exception
  {
    final GeneralNames names = CertUtil.subjectAltNames(cert);
    if (expected.length == 0) {
      assertThat(names).isNull();
      return;
    }
    assertThat(names.getNames().length).isEqualTo(expected.length);
    for (int i = 0; i < expected.length; i++) {
      assertThat(names.getNames()[i].getName().toString()).isEqualTo(expected[i]);
    }
  }

  @Test(dataProvider = "subject-alt-names-by-type")
  public void testSubjectAltNamesByType(
    final X509Certificate cert,
    final GeneralNameType[] types,
    final String[] expected)
    throws Exception
  {
    final GeneralNames names = CertUtil.subjectAltNames(cert, types);
    if (expected.length == 0) {
      assertThat(names).isNull();
      return;
    }
    assertThat(names.getNames().length).isEqualTo(expected.length);
    for (int i = 0; i < expected.length; i++) {
      assertThat(names.getNames()[i].getName().toString()).isEqualTo(expected[i]);
    }
  }

  @Test(dataProvider = "subject-names")
  public void testSubjectNames(final X509Certificate cert, final String[] expected)
    throws Exception
  {
    final List<String> names = CertUtil.subjectNames(cert);
    assertThat(names.size()).isEqualTo(expected.length);
    for (int i = 0; i < expected.length; i++) {
      assertThat(names.get(i)).isEqualTo(expected[i]);
    }
  }

  @Test(dataProvider = "subject-names-by-type")
  public void testSubjectNamesByType(final X509Certificate cert, final GeneralNameType[] types, final String[] expected)
    throws Exception
  {
    final List<String> names = CertUtil.subjectNames(cert, types);
    assertThat(names.size()).isEqualTo(expected.length);
    for (int i = 0; i < expected.length; i++) {
      assertThat(names.get(i)).isEqualTo(expected[i]);
    }
  }

  @Test(dataProvider = "entity-certificate")
  public void testFindEntityCertificate(
    final PrivateKey key,
    final X509Certificate[] candidates,
    final X509Certificate expected)
    throws Exception
  {
    assertThat(CertUtil.findEntityCertificate(key, candidates)).isEqualTo(expected);
  }

  @Test(dataProvider = "basic-usage")
  public void testAllowsBasicUsage(final X509Certificate cert, final KeyUsageBits[] expectedUses)
    throws Exception
  {
    assertThat(CertUtil.allowsUsage(cert, expectedUses)).isTrue();
  }

  @Test(dataProvider = "extended-usage")
  public void testAllowsExtendedUsage(final X509Certificate cert, final KeyPurposeId[] expectedPurposes)
    throws Exception
  {
    assertThat(CertUtil.allowsUsage(cert, expectedPurposes)).isTrue();
  }

  @Test(dataProvider = "has-policies")
  public void testHasPolicies(final X509Certificate cert, final String[] expectedPolicies)
    throws Exception
  {
    assertThat(CertUtil.hasPolicies(cert, expectedPolicies)).isTrue();
  }

  @Test(dataProvider = "subject-keyid")
  public void testSubjectKeyId(final X509Certificate cert, final String expectedKeyId)
    throws Exception
  {
    assertThat(CertUtil.subjectKeyId(cert).toUpperCase()).isEqualTo(expectedKeyId);
  }

  @Test(dataProvider = "authority-keyid")
  public void testAuthorityKeyId(final X509Certificate cert, final String expectedKeyId)
    throws Exception
  {
    assertThat(CertUtil.authorityKeyId(cert).toUpperCase()).isEqualTo(expectedKeyId);
  }


  @Test(dataProvider = "cert-chains")
  public void testReadCertificateChains(final String path, final int expectedCount)
    throws Exception
  {
    assertThat(CertUtil.readCertificateChain(path).length).isEqualTo(expectedCount);
  }

  @Test(dataProvider = "encode-cert-p7")
  public void certEncodedAsPkcs7(final X509Certificate certificate, final String expectedEncodedCert)
  {
    final String actualEncodedCertString = CertUtil.encodeCert(certificate, CertUtil.EncodeType.PKCS7);
    final X509Certificate decodedCert = CertUtil.decodeCertificate(CertUtil.encodeCert(certificate,
      CertUtil.EncodeType.PKCS7).getBytes());
    assertThat(actualEncodedCertString).isEqualTo(expectedEncodedCert);
    assertThat(certificate).isEqualTo(decodedCert);
  }

  @Test(dataProvider = "encode-cert-x509")
  public void certEncodedAsX509(final X509Certificate certificate, final String x509Cert)
  {
    final String encodedCert = CertUtil.encodeCert(certificate, CertUtil.EncodeType.X509);
    assertThat(encodedCert).isEqualTo(x509Cert);
  }

  @Test(dataProvider = "encode-cert-der")
  public void certEncodedAsDER(final X509Certificate certificate, final byte[] derCert)
  {
    final byte[] encodedCert = CertUtil.encodeCert(certificate, CertUtil.EncodeType.DER);
    assertThat(encodedCert).isEqualTo(derCert);
  }

  @Test(dataProvider = "subject-dn")
  public void testSubjectDN(final X509Certificate certificate, final String expectedResponse)
  {
    assertThat(CertUtil.subjectDN(certificate, CertUtil.X500PrincipalFormat.RFC2253)).isEqualTo(expectedResponse);
  }

  @Test(dataProvider = "subject-dn-spaces")
  public void testSubjectDNWithSpaces(final X509Certificate certificate, final String expectedResponse)
  {
    assertThat(CertUtil.subjectDN(certificate, CertUtil.X500PrincipalFormat.READABLE)).isEqualTo(expectedResponse);
  }

  @Test
  public void testGenX509()
  {
    final KeyPair keyPair = KeyPairGenerator.generateRSA(new SecureRandom(), 2048);
    final String dn = "C=US, DC=edu, DC=vt, ST=Virginia, " +
      "L=Blacksburg, O=Virginia Polytechnic Institute and State University, OU=Middleware-Server-with-saltr, " +
      "OU=Middleware Services, CN=ed.middleware.vt.edu";

    final Instant expectedNotBefore = Instant.now();
    final Instant expectedNotAfter = Instant.now().plus(Duration.ofDays(365));

    final X509Certificate x509Certificate = CertUtil.generateX509Certificate(keyPair, dn,
      Date.from(expectedNotBefore), Date.from(expectedNotAfter), "SHA256WithRSA");

    assertThat(truncateToSeconds(x509Certificate.getNotBefore().toInstant()))
      .isEqualTo(truncateToSeconds(expectedNotBefore));
    assertThat(truncateToSeconds(x509Certificate.getNotAfter().toInstant()))
      .isEqualTo(truncateToSeconds(expectedNotAfter));
  }

  @Test(expectedExceptions = RuntimeException.class,
    expectedExceptionsMessageRegExp = "Unknown signature type requested: UNSUPPORTEDALGO")
  public void testGenX509UnSupportedAlgo()
  {
    final KeyPair keyPair = KeyPairGenerator.generateRSA(new SecureRandom(), 2048);
    final String dn = "C=US, DC=edu, DC=vt, ST=Virginia, " +
      "L=Blacksburg, O=Virginia Polytechnic Institute and State University, OU=Middleware-Server-with-saltr, " +
      "OU=Middleware Services, CN=ed.middleware.vt.edu";

    final Instant expectedNotBefore = Instant.now();
    final Instant expectedNotAfter = Instant.now().plus(Duration.ofDays(365));

    CertUtil.generateX509Certificate(keyPair, dn,
        Date.from(expectedNotBefore), Date.from(expectedNotAfter), "UNSUPPORTEDALGO");
  }


  private OffsetDateTime truncateToSeconds(final Instant instant)
  {
    return instant.atOffset(ZoneOffset.UTC).withNano(0);
  }
}
