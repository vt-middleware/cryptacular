/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import org.cryptacular.FailListener;
import org.cryptacular.generator.KeyPairGenerator;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link KeyPairUtil} class.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
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
    return
      new Object[][] {
        new Object[] {dsa1024.getPublic(), 1024},
        new Object[] {rsa512.getPublic(), 512},
        new Object[] {ec256.getPublic(), 256},
      };
  }

  @DataProvider(name = "private-keys")
  public Object[][] getPrivateKeys()
  {
    return
      new Object[][] {
        new Object[] {dsa1024.getPrivate(), 160},
        new Object[] {rsa512.getPrivate(), 512},
        new Object[] {ec224.getPrivate(), 224},
      };
  }

  @DataProvider(name = "key-pairs")
  public Object[][] getKeyPairs()
  {
    final KeyPair rsa512p2 = KeyPairGenerator.generateRSA(random, 512);
    return
      new Object[][] {
        new Object[] {rsa512.getPublic(), rsa512.getPrivate(), true},
        new Object[] {rsa512p2.getPublic(), rsa512p2.getPrivate(), true},
        new Object[] {rsa512.getPublic(), rsa512p2.getPrivate(), false},
        new Object[] {ec256.getPublic(), ec256.getPrivate(), true},
        new Object[] {ec224.getPublic(), ec224.getPrivate(), true},
        new Object[] {
          KeyPairUtil.readPublicKey(KEY_PATH + "ec-openssl-prime256v1-named-pub.pem"),
          KeyPairUtil.readPrivateKey(KEY_PATH + "ec-openssl-prime256v1-named-nopass.pem"),
          true,
        },
        new Object[] {
          KeyPairUtil.readPublicKey(KEY_PATH + "ec-openssl-secp112r1-named-pub.pem"),
          KeyPairUtil.readPrivateKey(KEY_PATH + "ec-openssl-secp112r1-named-nopass.pem"),
          true,
        },
        new Object[] {
          KeyPairUtil.readPublicKey(KEY_PATH + "ec-openssl-secp224k1-explicit-pub.pem"),
          KeyPairUtil.readPrivateKey(KEY_PATH + "ec-openssl-secp224k1-explicit-nopass.pem"),
          true,
        },
        new Object[] {
          KeyPairUtil.readPublicKey(KEY_PATH + "ec-openssl-secp256k1-explicit-pub.pem"),
          KeyPairUtil.readPrivateKey(KEY_PATH + "ec-openssl-secp256k1-explicit-nopass.pem"),
          true,
        },
        new Object[] {
          KeyPairUtil.readPublicKey(KEY_PATH + "ec-openssl-sect409k1-named-pub.pem"),
          KeyPairUtil.readPrivateKey(KEY_PATH + "ec-openssl-sect409k1-named-nopass.pem"),
          true,
        },
        new Object[] {
          KeyPairUtil.readPublicKey(KEY_PATH + "ec-openssl-sect571r1-explicit-pub.pem"),
          KeyPairUtil.readPrivateKey(KEY_PATH + "ec-openssl-sect571r1-explicit-nopass.pem"),
          true,
        },
        new Object[] {
          KeyPairUtil.readPublicKey(KEY_PATH + "ec-openssl-sect571r1-explicit-pub.pem"),
          KeyPairUtil.readPrivateKey(KEY_PATH + "ec-openssl-sect571r1-explicit-nopass.pem"),
          true,
        },
      };
  }

  @DataProvider(name = "private-key-files")
  public Object[][] getPrivateKeyFiles()
  {
    return
      new Object[][] {
        new Object[] {KEY_PATH + "dsa-openssl-nopass.der", DSAPrivateKey.class},
        new Object[] {KEY_PATH + "dsa-openssl-nopass.pem", DSAPrivateKey.class},
        new Object[] {
          KEY_PATH + "rsa-openssl-nopass.der",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "rsa-openssl-nopass.pem",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-openssl-prime256v1-named-nopass.der",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-openssl-prime256v1-named-nopass.pem",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-openssl-secp112r1-named-nopass.der",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-openssl-secp112r1-named-nopass.pem",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-openssl-secp224k1-explicit-nopass.der",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-openssl-secp224k1-explicit-nopass.pem",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-openssl-sect571r1-explicit-nopass.der",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-openssl-sect571r1-explicit-nopass.pem",
          ECPrivateKey.class,
        },
        new Object[] {KEY_PATH + "dsa-pkcs8-nopass.der", DSAPrivateKey.class},
        new Object[] {KEY_PATH + "dsa-pkcs8-nopass.pem", DSAPrivateKey.class},
        new Object[] {
          KEY_PATH + "rsa-pkcs8-nopass.der",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "rsa-pkcs8-nopass.pem",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "rsa-pkcs8-nopass-noheader.pem",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-pkcs8-secp224k1-explicit-nopass.der",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-pkcs8-secp224k1-explicit-nopass.pem",
          ECPrivateKey.class,
        },
      };
  }

  @DataProvider(name = "encrypted-private-key-files")
  public Object[][] getEncryptedPrivateKeyFiles()
  {
    return
      new Object[][] {
        new Object[] {
          KEY_PATH + "dsa-openssl-des3.pem",
          "vtcrypt",
          DSAPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "rsa-openssl-des.pem",
          "vtcrypt",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "rsa-openssl-des-noheader.pem",
          "vtcrypt",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "rsa-openssl-des3.pem",
          "vtcrypt",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-openssl-secp224k1-explicit-des.pem",
          "vtcrypt",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-openssl-sect571r1-explicit-des.pem",
          "vtcrypt",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "dsa-pkcs8-priv.der",
          "vtcrypt",
          DSAPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "dsa-pkcs8-priv.pem",
          "vtcrypt",
          DSAPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "dsa-pkcs8-v2-des3.der",
          "vtcrypt",
          DSAPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "dsa-pkcs8-v2-des3.pem",
          "vtcrypt",
          DSAPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "rsa-pkcs8-v1-md5-des.der",
          "vtcrypt",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "rsa-pkcs8-v1-md5-des.pem",
          "vtcrypt",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "rsa-pkcs8-v1-md5-rc2-64.der",
          "vtcrypt",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "rsa-pkcs8-v2-aes256.der",
          "vtcrypt",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "rsa-pkcs8-v2-aes256.pem",
          "vtcrypt",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "rsa-pkcs8-v2-aes256-noheader.pem",
          "vtcrypt",
          RSAPrivateCrtKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-pkcs8-secp224k1-explicit-sha1-rc4-128.der",
          "vtcrypt",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-pkcs8-secp224k1-explicit-v1-sha1-rc2-64.der",
          "vtcrypt",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-pkcs8-secp224k1-explicit-v2-des3.pem",
          "vtcrypt",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-pkcs8-sect571r1-explicit-v2-aes128.pem",
          "vtcrypt",
          ECPrivateKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-pkcs8-sect571r1-named-v1-sha1-rc2-64.der",
          "vtcrypt",
          ECPrivateKey.class,
        },
      };
  }

  @DataProvider(name = "public-key-files")
  public Object[][] getPublicKeyFiles()
  {
    return
      new Object[][] {
        new Object[] {KEY_PATH + "dsa-pub.der", DSAPublicKey.class},
        new Object[] {KEY_PATH + "dsa-pub.pem", DSAPublicKey.class},
        new Object[] {
          KEY_PATH + "ec-secp224k1-explicit-pub.der",
          ECPublicKey.class,
        },
        new Object[] {
          KEY_PATH + "ec-secp224k1-explicit-pub.pem",
          ECPublicKey.class,
        },
        new Object[] {KEY_PATH + "rsa-pub.der", RSAPublicKey.class},
        new Object[] {KEY_PATH + "rsa-pub.pem", RSAPublicKey.class},
      };
  }


  @Test(dataProvider = "public-keys")
  public void testLengthPublicKey(final PublicKey key, final int expectedLength)
    throws Exception
  {
    assertThat(KeyPairUtil.length(key)).isEqualTo(expectedLength);
  }

  @Test(dataProvider = "private-keys")
  public void testLengthPrivateKey(final PrivateKey key, final int expectedLength)
    throws Exception
  {
    assertThat(KeyPairUtil.length(key)).isEqualTo(expectedLength);
  }

  @Test(dataProvider = "key-pairs")
  public void testIsKeyPair(final PublicKey pubKey, final PrivateKey privKey, final boolean expected)
    throws Exception
  {
    assertThat(KeyPairUtil.isKeyPair(pubKey, privKey)).isEqualTo(expected);
  }

  @Test(dataProvider = "private-key-files")
  public void testReadPrivateKey(final String path, final Class<?> expectedType)
    throws Exception
  {
    final PrivateKey key = KeyPairUtil.readPrivateKey(path);
    assertThat(key).isNotNull();
    assertThat(expectedType.isAssignableFrom(key.getClass())).isTrue();
  }

  @Test(dataProvider = "encrypted-private-key-files")
  public void testReadEncryptedPrivateKey(final String path, final String password, final Class<?> expectedType)
    throws Exception
  {
    final PrivateKey key = KeyPairUtil.readPrivateKey(path, password.toCharArray());
    assertThat(key).isNotNull();
    assertThat(expectedType.isAssignableFrom(key.getClass())).isTrue();
  }

  @Test(dataProvider = "public-key-files")
  public void testReadPublicKey(final String path, final Class<?> expectedType)
    throws Exception
  {
    final PublicKey key = KeyPairUtil.readPublicKey(path);
    assertThat(key).isNotNull();
    assertThat(expectedType.isAssignableFrom(key.getClass())).isTrue();
  }

  @Test(dataProvider = "private-key-files")
  public void testClosePrivateKey(final String path, final Class<?> expectedType)
    throws Exception
  {
    final TestableFileInputStream is = new TestableFileInputStream(path);
    final PrivateKey key = KeyPairUtil.readPrivateKey(is);
    assertThat(key).isNotNull();
    assertThat(is.isClosed()).isTrue();
  }

  @Test(dataProvider = "public-key-files")
  public void testClosePublicKey(final String path, final Class<?> expectedType)
    throws Exception
  {
    final TestableFileInputStream is = new TestableFileInputStream(path);
    final PublicKey key = KeyPairUtil.readPublicKey(is);
    assertThat(key).isNotNull();
    assertThat(is.isClosed()).isTrue();
  }


  /**
   * Class for testing usage of {@link FileInputStream}.
   */
  private static class TestableFileInputStream extends FileInputStream
  {

    /** Whether {@link #close()} has been invoked. */
    private boolean isClosed;

    /**
     * Default constructor.
     *
     * @param  name  of the file to open
     *
     * @throws  FileNotFoundException  if an error occurs
     */
    TestableFileInputStream(final String name)
      throws FileNotFoundException
    {
      super(name);
    }

    @Override
    public void close()
      throws IOException
    {
      super.close();
      isClosed = true;
    }

    /**
     * Returns whether {@link #close()} has been invoked.
     *
     * @return  whether {@link #close()} has been invoked
     */
    public boolean isClosed()
    {
      return isClosed;
    }
  }
}
