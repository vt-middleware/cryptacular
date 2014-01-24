/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.File;
import javax.crypto.SecretKey;
import org.cryptacular.io.FileResource;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link KeyStoreBasedSecretKeyFactoryBean}.
 *
 * @author  Middleware Services
 */
public class KeyStoreBasedSecretKeyFactoryBeanTest
{
  private static final String KS_PATH = "src/test/resources/keystores/";

  @DataProvider(name = "keys")
  public Object[][] getKeys()
  {
    return
      new Object[][] {
        new Object[] {
          KS_PATH + "factory-bean.jceks",
          "JCEKS",
          "aes256",
          "AES",
          32,
        },
      };
  }


  @Test(dataProvider = "keys")
  public void testNewInstance(
    final String keyStorePath,
    final String keyStoreType,
    final String alias,
    final String expectedAlg,
    final int expectedSize)
    throws Exception
  {
    final KeyStoreFactoryBean keyStoreFactory = new KeyStoreFactoryBean();
    keyStoreFactory.setResource(new FileResource(new File(keyStorePath)));
    keyStoreFactory.setPassword("vtcrypt");
    keyStoreFactory.setType(keyStoreType);

    final KeyStoreBasedSecretKeyFactoryBean secretKeyFactory =
      new KeyStoreBasedSecretKeyFactoryBean();
    secretKeyFactory.setKeyStore(keyStoreFactory.newInstance());
    secretKeyFactory.setAlias(alias);
    secretKeyFactory.setPassword("vtcrypt");

    final SecretKey key = secretKeyFactory.newInstance();
    assertEquals(key.getAlgorithm(), expectedAlg);
    assertEquals(key.getEncoded().length, expectedSize);
  }
}
