package org.cryptosis.util;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.cryptosis.KeyPairGenerator;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link KeyPairUtil} class.
 *
 * @author Marvin S. Addison
 */
public class KeyPairUtilTest
{
  private final SecureRandom random = new SecureRandom();

  private final KeyPair rsa512 = KeyPairGenerator.generateRSA(random, 512);

  private final KeyPair dsa1024 = KeyPairGenerator.generateDSA(random, 1024);

  private final KeyPair ec256 = KeyPairGenerator.generateEC(random, 256);

  private final KeyPair ec224 = KeyPairGenerator.generateEC(random, "P-224");


  @DataProvider(name = "public-keys")
  public Object[][] getPublicKeys()
  {
    return new Object[][] {
      new Object[] { dsa1024.getPublic(), 1024 },
      new Object[] { rsa512.getPublic(), 512 },
      new Object[] { ec256.getPublic(), 256 },
    };
  }

  @DataProvider(name = "private-keys")
  public Object[][] getPrivateKeys()
  {
    return new Object[][] {
      new Object[] { dsa1024.getPrivate(), 160 },
      new Object[] { rsa512.getPrivate(), 512 },
      new Object[] { ec224.getPrivate(), 224 },
    };
  }

  @DataProvider(name = "key-pairs")
  public Object[][] getKeyPairs()
  {
    final KeyPair rsa512_2 = KeyPairGenerator.generateRSA(random, 512);
    return new Object[][] {
      new Object[] { rsa512.getPublic(), rsa512.getPrivate(), true },
      new Object[] { rsa512_2.getPublic(), rsa512_2.getPrivate(), true },
      new Object[] { rsa512.getPublic(), rsa512_2.getPrivate(), false },
    };
  }

  @Test(dataProvider = "public-keys")
  public void testLengthPublicKey(final PublicKey key, final int expectedLength) throws Exception
  {
    assertEquals(KeyPairUtil.length(key), expectedLength);
  }

  @Test(dataProvider = "private-keys")
  public void testLengthPrivateKey(final PrivateKey key, final int expectedLength) throws Exception
  {
    assertEquals(KeyPairUtil.length(key), expectedLength);
  }

  @Test(dataProvider = "key-pairs")
  public void testIsKeyPair(final PublicKey pubKey, final PrivateKey privKey, final boolean expected) throws Exception
  {
    assertEquals(KeyPairUtil.isKeyPair(pubKey, privKey), expected);
  }
}
