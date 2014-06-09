/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.File;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;

import org.cryptacular.io.FileResource;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link KeyStoreBasedKeyPairFactoryBean}.
 */
public class KeyStoreBasedKeyPairFactoryBeanTest
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
    final KeyStoreFactoryBean keyStoreFactory = new KeyStoreFactoryBean();
    keyStoreFactory.setResource(new FileResource(new File(keyStorePath)));
    keyStoreFactory.setPassword("vtcrypt");
    keyStoreFactory.setType(keyStoreType);

    final KeyStoreBasedKeyPairFactoryBean keyPairFactory =
        new KeyStoreBasedKeyPairFactoryBean();
    keyPairFactory.setKeyStore(keyStoreFactory.newInstance());
    keyPairFactory.setAlias(alias);
    keyPairFactory.setPassword("vtcrypt");

    final KeyPair pair = keyPairFactory.newInstance();
    assertEquals(pair.getPrivate().getAlgorithm(), expectedAlg);
    assertEquals(pair.getPublic().getAlgorithm(), expectedAlg);
    if ("RSA".equals(expectedAlg)) {
      assertEquals(
          ((RSAPrivateKey) pair.getPrivate()).getModulus().bitLength(),
          expectedSize);
    }
  }
}
