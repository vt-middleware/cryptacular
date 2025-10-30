/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.File;
import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import javax.crypto.SecretKey;
import org.cryptacular.FailListener;
import org.cryptacular.io.FileResource;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link KeyStoreBasedKeyFactoryBean}.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class KeyStoreBasedKeyFactoryBeanTest
{
  private static final String KS_PATH = "src/test/resources/keystores/";

  @DataProvider(name = "keys")
  public Object[][] getKeys()
  {
    return
      new Object[][] {
        {
          KS_PATH + "factory-bean.jceks",
          "JCEKS",
          "aes256",
          "AES",
          32,
        },
        {
          KS_PATH + "factory-bean.jceks",
          "JCEKS",
          "rsa2048",
          "RSA",
          2048,
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
    final KeyStoreFactoryBean keyStoreFactory = new KeyStoreFactoryBean(
      new FileResource(new File(keyStorePath)),  keyStoreType, "vtcrypt");

    final KeyStoreBasedKeyFactoryBean<? extends Key> secretKeyFactory = new KeyStoreBasedKeyFactoryBean<>(
      keyStoreFactory.newInstance(), alias, "vtcrypt");

    final Key key = secretKeyFactory.newInstance();
    assertThat(key.getAlgorithm()).isEqualTo(expectedAlg);
    if (key instanceof SecretKey) {
      assertThat(key.getEncoded().length).isEqualTo(expectedSize);
    } else if (key instanceof RSAPrivateKey) {
      assertThat(((RSAPrivateKey) key).getModulus().bitLength()).isEqualTo(expectedSize);
    }
  }
}
