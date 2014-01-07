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

package org.cryptosis.util;

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

import org.cryptosis.generator.KeyPairGenerator;
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
    final KeyPair rsa512p2 = KeyPairGenerator.generateRSA(random, 512);
    return new Object[][] {
      new Object[] { rsa512.getPublic(), rsa512.getPrivate(), true },
      new Object[] { rsa512p2.getPublic(), rsa512p2.getPrivate(), true },
      new Object[] { rsa512.getPublic(), rsa512p2.getPrivate(), false },
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
      new Object[] { KEY_PATH + "dsa-openssl-des3.pem", "vtcrypt", DSAPrivateKey.class },
      new Object[] { KEY_PATH + "rsa-openssl-des.pem", "vtcrypt", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "rsa-openssl-des-noheader.pem", "vtcrypt", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "rsa-openssl-des3.pem", "vtcrypt", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "ec-openssl-secp224k1-explicit-des.pem", "vtcrypt", ECPrivateKey.class },
      new Object[] { KEY_PATH + "ec-openssl-sect571r1-explicit-des.pem", "vtcrypt", ECPrivateKey.class },
      new Object[] { KEY_PATH + "dsa-pkcs8-priv.der", "vtcrypt", DSAPrivateKey.class },
      new Object[] { KEY_PATH + "dsa-pkcs8-priv.pem", "vtcrypt", DSAPrivateKey.class },
      new Object[] { KEY_PATH + "dsa-pkcs8-v2-des3.der", "vtcrypt", DSAPrivateKey.class },
      new Object[] { KEY_PATH + "dsa-pkcs8-v2-des3.pem", "vtcrypt", DSAPrivateKey.class },
      new Object[] { KEY_PATH + "rsa-pkcs8-v1-md5-des.der", "vtcrypt", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "rsa-pkcs8-v1-md5-des.pem", "vtcrypt", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "rsa-pkcs8-v1-md5-rc2-64.der", "vtcrypt", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "rsa-pkcs8-v2-aes256.der", "vtcrypt", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "rsa-pkcs8-v2-aes256.pem", "vtcrypt", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "rsa-pkcs8-v2-aes256-noheader.pem", "vtcrypt", RSAPrivateCrtKey.class },
      new Object[] { KEY_PATH + "ec-pkcs8-secp224k1-explicit-sha1-rc4-128.der", "vtcrypt", ECPrivateKey.class },
      new Object[] { KEY_PATH + "ec-pkcs8-secp224k1-explicit-v1-sha1-rc2-64.der", "vtcrypt", ECPrivateKey.class },
      new Object[] { KEY_PATH + "ec-pkcs8-secp224k1-explicit-v2-des3.pem", "vtcrypt", ECPrivateKey.class },
      new Object[] { KEY_PATH + "ec-pkcs8-sect571r1-explicit-v2-aes128.pem", "vtcrypt", ECPrivateKey.class },
      new Object[] { KEY_PATH + "ec-pkcs8-sect571r1-named-v1-sha1-rc2-64.der", "vtcrypt", ECPrivateKey.class },
    };
  }

  @DataProvider(name = "public-key-files")
  public Object[][] getPublicKeyFiles()
  {
    return new Object[][] {
      new Object[] { KEY_PATH + "dsa-pub.der", DSAPublicKey.class },
      new Object[] { KEY_PATH + "dsa-pub.pem", DSAPublicKey.class },
      new Object[] { KEY_PATH + "ec-secp224k1-explicit-pub.der", ECPublicKey.class },
      new Object[] { KEY_PATH + "ec-secp224k1-explicit-pub.pem", ECPublicKey.class },
      new Object[] { KEY_PATH + "rsa-pub.der", RSAPublicKey.class },
      new Object[] { KEY_PATH + "rsa-pub.pem", RSAPublicKey.class },
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
  public void testReadEncryptedPrivateKey(
    final String path, final String password, final Class<?> expectedType) throws Exception
  {
    final PrivateKey key = KeyPairUtil.readPrivateKey(path, password.toCharArray());
    assertNotNull(key);
    assertTrue(expectedType.isAssignableFrom(key.getClass()));
  }

  @Test(dataProvider = "public-key-files")
  public void testReadPublicKey(final String path, final Class<?> expectedType) throws Exception
  {
    final PublicKey key = KeyPairUtil.readPublicKey(path);
    assertNotNull(key);
    assertTrue(expectedType.isAssignableFrom(key.getClass()));
  }
}
