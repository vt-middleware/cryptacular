package org.cryptosis.util;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.GeneralNames;
import org.cryptosis.x509.GeneralNameType;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

/**
 * Unit test for {@link CertUtil} class.
 *
 * @author Marvin S. Addison
 */
public class CertUtilTest
{
  private static final String CRT_PATH = "src/test/resources/certs/";

  @DataProvider(name = "subject-cn")
  public Object[][] getSubjectCommonNames()
  {
    return new Object[][] {
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "ed.middleware.vt.edu.crt"),
        "ed.middleware.vt.edu"
      },
    };
  }

  @DataProvider(name = "subject-alt-names")
  public Object[][] getSubjectAltNames()
  {
    return new Object[][] {
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "ed.middleware.vt.edu.crt"),
        new String[] {
          "ed.middleware.vt.edu",
          "directory.vt.edu",
          "id.directory.vt.edu",
          "authn.directory.vt.edu",
          "ldap.vt.edu"
        },
      }
    };
  }

  @DataProvider(name = "subject-alt-names-by-type")
  public Object[][] getSubjectAltNamesByType()
  {
    return new Object[][] {
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "ed.middleware.vt.edu.crt"),
        new GeneralNameType[] { GeneralNameType.DNSName },
        new String[] {
          "ed.middleware.vt.edu",
          "directory.vt.edu",
          "id.directory.vt.edu",
          "authn.directory.vt.edu",
          "ldap.vt.edu"
        },
      },
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "ed.middleware.vt.edu.crt"),
        new GeneralNameType[] { GeneralNameType.RFC822Name },
        new String[0],
      },
    };
  }

  @DataProvider(name = "subject-names")
  public Object[][] getSubjectNames()
  {
    return new Object[][] {
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
        new String[] { "Marvin S Addison", "eprov@vt.edu" },
      }
    };
  }

  @DataProvider(name = "subject-names-by-type")
  public Object[][] getSubjectNamesByType()
  {
    return new Object[][] {
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
        new GeneralNameType[] { GeneralNameType.RFC822Name },
        new String[] { "Marvin S Addison", "eprov@vt.edu" },
      },
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
        new GeneralNameType[] { GeneralNameType.OtherName },
        new String[] { "Marvin S Addison" },
      },
    };
  }

  @DataProvider(name = "entity-certificate")
  public Object[][] getEntityCertificates()
  {
    return new Object[][] {
      new Object[] {
        null,
        //TODO: Provide private key
        //KeyUtil.readKey(CRT_PATH + "entity.key");
        new X509Certificate[] {
          CertUtil.readCertificate(CRT_PATH + "glider.cc.vt.edu.crt"),
          CertUtil.readCertificate(CRT_PATH + "login.live.com.crt"),
          CertUtil.readCertificate(CRT_PATH + "entity.crt"),
        },
        CertUtil.readCertificate(CRT_PATH + "entity.crt"),
      },
    };
  }


  @Test(dataProvider = "subject-cn")
  public void testSubjectCN(final X509Certificate cert, final String expected)
  {
    assertEquals(CertUtil.subjectCN(cert), expected);
  }

  @Test(dataProvider = "subject-alt-names")
  public void testSubjectAltNames(final X509Certificate cert, final String[] expected) throws Exception
  {
    final GeneralNames names = CertUtil.subjectAltNames(cert);
    if (expected.length == 0) {
      assertNull(names);
      return;
    }
    assertEquals(names.getNames().length, expected.length);
    for (int i = 0; i < expected.length; i++) {
      assertEquals(names.getNames()[i].getName().toString(), expected[i]);
    }
  }

  @Test(dataProvider = "subject-alt-names-by-type")
  public void testSubjectAltNamesByType(
    final X509Certificate cert, final GeneralNameType[] types, final String[] expected) throws Exception
  {
    final GeneralNames names = CertUtil.subjectAltNames(cert, types);
    if (expected.length == 0) {
      assertNull(names);
      return;
    }
    assertEquals(names.getNames().length, expected.length);
    for (int i = 0; i < expected.length; i++) {
      assertEquals(names.getNames()[i].getName().toString(), expected[i]);
    }
  }

  @Test(dataProvider = "subject-names")
  public void testSubjectNames(final X509Certificate cert, final String[] expected) throws Exception
  {
    final List<String> names = CertUtil.subjectNames(cert);
    assertEquals(names.size(), expected.length);
    for (int i = 0; i < expected.length; i++) {
      assertEquals(names.get(i), expected[i]);
    }
  }

  @Test(dataProvider = "subject-names-by-type")
  public void testSubjectNamesByType(
    final X509Certificate cert, final GeneralNameType[] types, final String[] expected) throws Exception
  {
    final List<String> names = CertUtil.subjectNames(cert, types);
    assertEquals(names.size(), expected.length);
    for (int i = 0; i < expected.length; i++) {
      assertEquals(names.get(i), expected[i]);
    }
  }

  //TODO: enable this test
  //@Test(dataProvider = "entity-certificate")
  public void testFindEntityCertificate(
    final PrivateKey key, final X509Certificate[] candidates, final X509Certificate expected) throws Exception
  {
    assertEquals(CertUtil.findEntityCertificate(key, candidates), expected);
  }

  @Test
  public void testAllowsBasicUsage() throws Exception
  {

  }

  @Test
  public void testAllowsExtendedUsage() throws Exception
  {

  }

  @Test
  public void testHasPolicies() throws Exception
  {

  }

  @Test
  public void testSubjectKeyId() throws Exception
  {

  }

  @Test
  public void testAuthorityKeyId() throws Exception
  {

  }
}
