/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.cryptacular.FailListener;
import org.cryptacular.util.KeyPairUtil;
import org.cryptacular.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.testng.AssertJUnit.assertTrue;

/**
 * Test for {@link AbstractWrappedKey} classes.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class WrappedKeyTest
{
  private static final String KEY_PATH = "src/test/resources/keys/";

  @DataProvider(name = "keypairs")
  public Object[][] getKeyPairs()
  {
    return
      new Object[][] {
        {"DSA", KEY_PATH + "dsa-pub.der", KEY_PATH + "dsa-pkcs8-nopass.der", },
        {"RSA", KEY_PATH + "rsa-pub.der", KEY_PATH + "rsa-pkcs8-nopass.der", },
        // TODO: enable once BC gets support for writing EC named curves
        // As of bcprov 1.50 only raw EC params can be written
        // SunJCE only understands named curves
        // {
        // "EC",
        // KEY_PATH + "ec-prime256v1-named-pub.der",
        // KEY_PATH + "ec-pkcs8-prime256v1-named-nopass.der",
        // },
      };
  }


  @Test(dataProvider = "keypairs")
  public void testKeyEquivalence(final String algorithm, final String pubKeyPath, final String privKeyPath)
    throws Exception
  {
    final KeyPair wrappedPair = new KeyPair(
      KeyPairUtil.readPublicKey(pubKeyPath),
      KeyPairUtil.readPrivateKey(privKeyPath));
    final String bcPubKeyPath = String.format("target/%s-%s.key", algorithm, "pub");
    final String bcPrivKeyPath = String.format("target/%s-%s.key", algorithm, "priv");
    writeFile(bcPubKeyPath, wrappedPair.getPublic().getEncoded());
    writeFile(bcPrivKeyPath, wrappedPair.getPrivate().getEncoded());

    final KeyPair jcePair = readJCEKeyPair(algorithm, bcPubKeyPath, bcPrivKeyPath);

    assertTrue(KeyPairUtil.isKeyPair(wrappedPair.getPublic(), jcePair.getPrivate()));
    assertTrue(KeyPairUtil.isKeyPair(jcePair.getPublic(), wrappedPair.getPrivate()));
  }


  private static void writeFile(final String path, final byte[] data)
    throws IOException
  {
    try (FileOutputStream out = new FileOutputStream(path)) {
      out.write(data);
    }
  }

  private static KeyPair readJCEKeyPair(final String algorithm, final String pubKeyPath, final String privKeyPath)
    throws Exception
  {
    final PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(StreamUtil.readAll(privKeyPath));
    final X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(StreamUtil.readAll(pubKeyPath));
    final KeyFactory factory = KeyFactory.getInstance(algorithm);
    return new KeyPair(factory.generatePublic(pubSpec), factory.generatePrivate(privSpec));
  }
}
