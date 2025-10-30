/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Test class for {@link CsrUtil}.
 *
 * @author Marvin S. Addison
 */
public class CsrUtilTest
{

  @DataProvider(name = "csr-files")
  public Object[][] getCsrFiles()
  {
    return new Object[][] {
      new Object[] {"/csrs/simple-ec-prime256v1.csr"},
      new Object[] {"/csrs/simple-ec-secp384r1.csr"},
      new Object[] {"/csrs/simple-rsa-1024.csr"},
      new Object[] {"/csrs/with-sans-rsa-2048.csr"},
    };
  }

  @DataProvider(name = "key-lengths")
  public Object[][] getKeyLengths()
  {
    return new Object[][] {
      new Object[] {"/csrs/simple-ec-prime256v1.csr", 256},
      new Object[] {"/csrs/simple-ec-secp384r1.csr", 384},
      new Object[] {"/csrs/simple-rsa-1024.csr", 1024},
      new Object[] {"/csrs/with-sans-rsa-2048.csr", 2048},
    };
  }

  @DataProvider(name = "sig-alg-names")
  public Object[][] getSigAlgNames()
  {
    return new Object[][] {
      new Object[] {"/csrs/simple-ec-secp384r1.csr", "SHA256withECDSA"},
      new Object[] {"/csrs/simple-ec-prime256v1.csr", "SHA256withECDSA"},
      new Object[] {"/csrs/simple-rsa-1024.csr", "SHA256withRSA"},
      new Object[] {"/csrs/with-sans-rsa-2048.csr", "SHA256withRSA"},
    };
  }

  @DataProvider(name = "names")
  public Object[][] getNames()
  {
    return new Object[][] {
      new Object[] {"/csrs/simple-ec-prime256v1.csr", "simple.example.com"},
      new Object[] {"/csrs/simple-ec-secp384r1.csr", "simple.example.com"},
      new Object[] {"/csrs/simple-rsa-1024.csr", "simple.example.com"},
      new Object[] {
        "/csrs/with-sans-rsa-2048.csr",
        "host.example.com",
        "dev.host.example.com",
        "pprd.host.example.com",
      },
    };
  }

  @DataProvider(name = "key-algs")
  public Object[][] getKeyAlgs()
  {
    return new Object[][] {
      new Object[] {"RSA"},
      new Object[] {"EC"},
    };
  }

  @Test(dataProvider = "csr-files")
  public void testEncodeCsr(final String classPath) throws IOException
  {
    final CertificationRequest csr1 = CsrUtil.readCsr(getClass().getResourceAsStream(classPath));
    final String encoded = CsrUtil.encodeCsr(new PKCS10CertificationRequest(csr1));
    final CertificationRequest csr2 = CsrUtil.decodeCsr(encoded);
    assertThat(csr1.getEncoded()).isEqualTo(csr2.getEncoded());
  }

  @Test(dataProvider = "names")
  public void testNames(final String classPath, final String... names)
  {
    final CertificationRequest csr = CsrUtil.readCsr(getClass().getResourceAsStream(classPath));
    assertThat(CsrUtil.commonNames(csr).get(0)).isEqualTo(names[0]);
    final List<String> sans = CsrUtil.subjectAltNames(csr);
    for (int i = 1; i < names.length; i++) {
      assertThat(sans.get(i - 1)).isEqualTo(names[i]);
    }
  }

  @Test(dataProvider = "key-lengths")
  public void testKeyLength(final String classPath, final int length)
  {
    final CertificationRequest csr = CsrUtil.readCsr(getClass().getResourceAsStream(classPath));
    assertThat(CsrUtil.keyLength(csr)).isEqualTo(length);
  }

  @Test(dataProvider = "sig-alg-names")
  public void testSigAlgName(final String classPath, final String sigAlgName)
  {
    final CertificationRequest csr = CsrUtil.readCsr(getClass().getResourceAsStream(classPath));
    assertThat(CsrUtil.sigAlgName(csr)).isEqualTo(sigAlgName);
  }

  @Test(dataProvider = "key-algs")
  public void testGenerateCsr(final String keyAlg) throws Exception
  {
    final KeyPair keyPair = KeyPairGenerator.getInstance(keyAlg).generateKeyPair();
    final String hostname = keyAlg.toLowerCase() + ".example.org";
    final String dn = "CN=" + hostname + ",DC=example,DC=org";
    final String[] sans = {"dev." + hostname, "pprd." + hostname};
    final CertificationRequest csr = CsrUtil.generateCsr(keyPair, dn, sans).toASN1Structure();
    assertThat(CsrUtil.commonNames(csr).get(0)).isEqualTo(hostname);
    assertThat(CsrUtil.subjectAltNames(csr)).isEqualTo(Arrays.asList(sans));
  }
}
