/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.cryptacular.bean.KeyStoreFactoryBean;
import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.Resource;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Unit test for {@link LegacyP12Generator}.
 *
 * @author Marvin S. Addison
 */
public class LegacyP12GeneratorTest
{
  @DataProvider(name = "p12-params")
  public Object[][] getP12Params()
  {
    return new Object[][] {
      new Object[] {"legacy-1024", "/keystores/alpha.p12", 1024},
      new Object[] {"legacy-2048", "/keystores/alpha.p12", 2048},
    };
  }

  @Test(dataProvider = "p12-params")
  public void testGenerate(
    final String testCaseName,
    final String keystorePath,
    final int iterations) throws Exception
  {
    final String password = "vtcrypt";
    final char[] passwordChars = password.toCharArray();
    final KeyStore keyStore = loadP12KeyStore(new ClassPathResource(keystorePath), password);
    final RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey("1", passwordChars);
    final X509Certificate cert = (X509Certificate) keyStore.getCertificate("1");
    final LegacyP12Generator generator = new LegacyP12Generator(iterations);
    final PKCS12PfxPdu p12 = generator.generate(passwordChars, privateKey, cert);
    Assert.assertEquals(p12.getContentInfos().length, 2);
    // Encrypted bag (certificate)
    Assert.assertEquals(p12.getContentInfos()[0].getContentType().toString(), "1.2.840.113549.1.7.6");
    // Shrouded bag (key)
    Assert.assertEquals(p12.getContentInfos()[1].getContentType().toString(), "1.2.840.113549.1.7.1");
    final File outFile = new File("target/keystores/" + testCaseName + ".p12");
    outFile.getParentFile().mkdirs();
    try (FileOutputStream out = new FileOutputStream(outFile)) {
      out.write(p12.getEncoded());
    }
  }

  private KeyStore loadP12KeyStore(final Resource resource, final String password)
  {
    final KeyStoreFactoryBean factory = new KeyStoreFactoryBean();
    factory.setResource(resource);
    factory.setType("PKCS12");
    factory.setPassword(password);
    return factory.newInstance();
  }
}
