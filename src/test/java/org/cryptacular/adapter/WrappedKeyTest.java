/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.cryptacular.util.KeyPairUtil;
import org.cryptacular.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Test for {@link AbstractWrappedKey} classes.
 *
 * @author Marvin S. Addison
 */
public class WrappedKeyTest
{
  private static final String KEY_PATH = "src/test/resources/keys/";

  @DataProvider(name = "keypairs")
  public Object[][] getKeyPairs()
  {
    return new Object[][] {
        {
            "DSA",
            KEY_PATH + "dsa-pub.der",
            KEY_PATH + "dsa-pkcs8-nopass.der",
        },
        {
            "RSA",
            KEY_PATH + "rsa-pub.der",
            KEY_PATH + "rsa-pkcs8-nopass.der",
        },
        {
            "EC",
            KEY_PATH + "ec-prime256v1-named-pub.der",
            KEY_PATH + "ec-pkcs8-prime256v1-named-nopass.der",
        },
    };
  }


  @Test(dataProvider = "keypairs")
  public void testKeyEquivalence(
      final String algorithm,
      final String pubKeyPath,
      final String privKeyPath) throws Exception
  {
    final KeyPair wrappedPair = new KeyPair(
        KeyPairUtil.readPublicKey(pubKeyPath),
        KeyPairUtil.readPrivateKey(privKeyPath));
    final KeyPair jcePair = readJCEKeyPair(
        algorithm, pubKeyPath, privKeyPath);

    assertEquals(
        wrappedPair.getPrivate().getAlgorithm(),
        jcePair.getPrivate().getAlgorithm());
    assertEquals(
        wrappedPair.getPublic().getAlgorithm(),
        jcePair.getPublic().getAlgorithm());
    assertEquals(
        wrappedPair.getPrivate().getEncoded(),
        jcePair.getPrivate().getEncoded());
    assertEquals(
        wrappedPair.getPublic().getEncoded(),
        jcePair.getPublic().getEncoded());
  }


  private KeyPair readJCEKeyPair(
      final String algorithm,
      final String pubKeyPath,
      final String privKeyPath) throws Exception
  {
    final PKCS8EncodedKeySpec privSpec =
        new PKCS8EncodedKeySpec(StreamUtil.readAll(privKeyPath));
    final X509EncodedKeySpec pubSpec =
        new X509EncodedKeySpec(StreamUtil.readAll(pubKeyPath));
    final KeyFactory factory = KeyFactory.getInstance(algorithm);
    return new KeyPair(
        factory.generatePublic(pubSpec),
        factory.generatePrivate(privSpec));
  }
}
