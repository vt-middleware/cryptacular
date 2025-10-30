/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.cryptacular.bean.KeyStoreFactoryBean;
import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.FileResource;
import org.cryptacular.io.Resource;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link AESP12Generator} class.
 *
 * @author Marvin S. Addison
 */
public class AESP12GeneratorTest
{
  @DataProvider(name = "p12-params")
  public Object[][] getP12Params()
  {
    return new Object[][] {
      new Object[] {"aes256-sha256-2048", "/keystores/alpha.p12", NISTObjectIdentifiers.id_sha256, 2048},
      new Object[] {"aes256-sha512-4196", "/keystores/alpha.p12", NISTObjectIdentifiers.id_sha512, 4196},
    };
  }

  @Test(dataProvider = "p12-params")
  public void testGenerate(
    final String testCaseName,
    final String keystorePath,
    final ASN1ObjectIdentifier digestAlgId,
    final int iterations) throws Exception
  {
    final String password = "vtcrypt";
    final char[] passwordChars = password.toCharArray();
    final KeyStore keyStore = loadP12KeyStore(new ClassPathResource(keystorePath), password);
    final RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey("1", passwordChars);
    final X509Certificate cert = (X509Certificate) keyStore.getCertificate("1");
    final AESP12Generator generator = new AESP12Generator(digestAlgId, iterations);
    final PKCS12PfxPdu p12 = generator.generate(passwordChars, privateKey, cert);
    assertThat(p12.getContentInfos().length).isEqualTo(2);
    // Encrypted bag (certificate)
    assertThat(p12.getContentInfos()[0].getContentType().toString()).isEqualTo("1.2.840.113549.1.7.6");
    // Shrouded bag (key)
    assertThat(p12.getContentInfos()[1].getContentType().toString()).isEqualTo("1.2.840.113549.1.7.1");
    final File outFile = new File("target/keystores/" + testCaseName + ".p12");
    outFile.getParentFile().mkdirs();
    try (FileOutputStream out = new FileOutputStream(outFile)) {
      out.write(p12.getEncoded());
    }
    final KeyStore generated = loadP12KeyStore(new FileResource(outFile), password);
    final RSAPrivateKey genKey = (RSAPrivateKey) generated.getKey("end-entity-cert", passwordChars);
    assertThat(genKey.getPrivateExponent()).isEqualTo(privateKey.getPrivateExponent());
    final X509Certificate genCert = (X509Certificate) generated.getCertificate("end-entity-cert");
    assertThat(genCert.getSubjectX500Principal()).isEqualTo(cert.getSubjectX500Principal());
  }

  private KeyStore loadP12KeyStore(final Resource resource, final String password)
  {
    final KeyStoreFactoryBean factory = new KeyStoreFactoryBean(resource, "PKCS12", password);
    return factory.newInstance();
  }
}
