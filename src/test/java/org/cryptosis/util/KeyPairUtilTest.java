package org.cryptosis.util;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.cryptosis.KeyPairGenerator;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit test for {@link KeyPairUtil} class.
 *
 * @author Marvin S. Addison
 */
public class KeyPairUtilTest
{
  private static final String KEY_PATH = "src/test/resources/keys/";

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

  @DataProvider(name = "private-key-files")
  public Object[][] getPrivateKeyFiles()
  {
    return new Object[][] {
      new Object[] { KEY_PATH + "dsa-openssl-nopass.der", DSAPrivateKey.class },
      new Object[] { KEY_PATH + "dsa-openssl-nopass.pem", DSAPrivateKey.class },
      new Object[] { KEY_PATH + "rsa-openssl-nopass.der", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "rsa-openssl-nopass.pem", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "ec-openssl-prime256v1-named-nopass.der", ECPrivateKey.class },
      new Object[] { KEY_PATH + "ec-openssl-secp224k1-explicit-nopass.der", ECPrivateKey.class  },
      new Object[] { KEY_PATH + "ec-openssl-secp224k1-explicit-nopass.pem", ECPrivateKey.class  },
      new Object[] { KEY_PATH + "ec-openssl-sect571r1-explicit-nopass.der", ECPrivateKey.class  },
      new Object[] { KEY_PATH + "ec-openssl-sect571r1-explicit-nopass.pem", ECPrivateKey.class  },
      new Object[] { KEY_PATH + "dsa-pkcs8-nopass.der", DSAPrivateKey.class },
      new Object[] { KEY_PATH + "dsa-pkcs8-nopass.pem", DSAPrivateKey.class },
      new Object[] { KEY_PATH + "rsa-pkcs8-nopass.der", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "rsa-pkcs8-nopass.pem", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "rsa-pkcs8-nopass-noheader.pem", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "ec-pkcs8-secp224k1-explicit-nopass.der", ECPrivateKey.class  },
      new Object[] { KEY_PATH + "ec-pkcs8-secp224k1-explicit-nopass.pem", ECPrivateKey.class  },
    };
  }

  @DataProvider(name = "encrypted-private-key-files")
  public Object[][] getEncryptedPrivateKeyFiles()
  {
    return new Object[][] {
//      new Object[] { KEY_PATH + "dsa-openssl-des3.pem", "vtcrypt", DSAPrivateKey.class },
      new Object[] { KEY_PATH + "rsa-openssl-des.pem", "vtcrypt", RSAPrivateCrtKey.class },
//      new Object[] { KEY_PATH + "rsa-openssl-des3.pem", "vtcrypt", DSAPrivateKey.class },
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

  @Test(dataProvider = "private-key-files")
  public void testReadPrivateKey(final String path, final Class<?> expectedType) throws Exception
  {
    final PrivateKey key = KeyPairUtil.readPrivateKey(path);
    assertNotNull(key);
    assertTrue(expectedType.isAssignableFrom(key.getClass()));
  }


  @Test(dataProvider = "encrypted-private-key-files")
  public void testReadEncryptedPrivateKey(final String path, final String password, final Class<?> expectedType) throws Exception
  {
    final PrivateKey key = KeyPairUtil.readPrivateKey(path, password.toCharArray());
    assertNotNull(key);
    assertTrue(expectedType.isAssignableFrom(key.getClass()));
  }
}
