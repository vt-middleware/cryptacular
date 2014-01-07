/*
 * Licensed to Virginia Tech under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Virginia Tech licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.cryptacular.util;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.cryptacular.x509.GeneralNameType;
import org.cryptacular.x509.KeyUsageBits;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

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
        "ed.middleware.vt.edu",
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
          "ldap.vt.edu",
        },
      },
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
          "ldap.vt.edu",
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
      },
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
  public Object[][] getEntityCertificates() throws Exception
  {
    return new Object[][] {
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
  public Object[][] getBasicUsage() throws Exception
  {
    return new Object[][] {
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
        new KeyUsageBits[] { KeyUsageBits.DigitalSignature, KeyUsageBits.NonRepudiation },
      },
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "login.live.com.crt"),
        new KeyUsageBits[] { KeyUsageBits.DigitalSignature, KeyUsageBits.KeyEncipherment },
      },
    };
  }

  @DataProvider(name = "extended-usage")
  public Object[][] getExtendedUsage() throws Exception
  {
    return new Object[][] {
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
        new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth },
      },
    };
  }

  @DataProvider(name = "has-policies")
  public Object[][] getHasPolicies() throws Exception
  {
    return new Object[][] {
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
  public Object[][] getSubjectKeyId() throws Exception
  {
    return new Object[][] {
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
  public Object[][] getAuthorityKeyId() throws Exception
  {
    return new Object[][] {
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

  @Test(dataProvider = "entity-certificate")
  public void testFindEntityCertificate(
    final PrivateKey key, final X509Certificate[] candidates, final X509Certificate expected) throws Exception
  {
    assertEquals(CertUtil.findEntityCertificate(key, candidates), expected);
  }

  @Test(dataProvider = "basic-usage")
  public void testAllowsBasicUsage(final X509Certificate cert, final KeyUsageBits[] expectedUses) throws Exception
  {
    assertTrue(CertUtil.allowsUsage(cert, expectedUses));
  }

  @Test(dataProvider = "extended-usage")
  public void testAllowsExtendedUsage(
      final X509Certificate cert, final KeyPurposeId[] expectedPurposes) throws Exception
  {
    assertTrue(CertUtil.allowsUsage(cert, expectedPurposes));
  }

  @Test(dataProvider = "has-policies")
  public void testHasPolicies(final X509Certificate cert, final String[] expectedPolicies) throws Exception
  {
    assertTrue(CertUtil.hasPolicies(cert, expectedPolicies));
  }

  @Test(dataProvider = "subject-keyid")
  public void testSubjectKeyId(final X509Certificate cert, final String expectedKeyId) throws Exception
  {
    assertEquals(CertUtil.subjectKeyId(cert).toUpperCase(), expectedKeyId);
  }

  @Test(dataProvider = "authority-keyid")
  public void testAuthorityKeyId(final X509Certificate cert, final String expectedKeyId) throws Exception
  {
    assertEquals(CertUtil.authorityKeyId(cert).toUpperCase(), expectedKeyId);
  }
}
