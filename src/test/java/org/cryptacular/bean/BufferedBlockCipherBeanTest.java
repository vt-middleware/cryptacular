/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.KeyStore;
import org.cryptacular.FailListener;
import org.cryptacular.generator.Nonce;
import org.cryptacular.generator.sp80038a.BigIntegerCounterNonce;
import org.cryptacular.generator.sp80038a.LongCounterNonce;
import org.cryptacular.generator.sp80038a.RBGNonce;
import org.cryptacular.io.FileResource;
import org.cryptacular.spec.BufferedBlockCipherSpec;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link BufferedBlockCipherBean}.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class BufferedBlockCipherBeanTest
{
  @DataProvider(name = "test-arrays")
  public Object[][] getTestArrays()
  {
    return
      new Object[][] {
        new Object[] {
          // Plaintext is NOT multiple of block size
          "Able was I ere I saw elba.",
          "AES/CBC/PKCS5",
          new RBGNonce(16),
        },
        // Plaintext is multiple of block size
        new Object[] {
          "Four score and seven years ago, our forefathers ",
          "Blowfish/CBC/None",
          new RBGNonce(8),
        },
        // OFB
        new Object[] {
          "Have you passed through this night?",
          "Blowfish/OFB/PKCS5Padding",
          new LongCounterNonce(),
        },
        // CFB
        new Object[] {
          "I went to the woods because I wished to live deliberately, to front only the essential facts of life",
          "AES/CFB/PKCS5Padding",
          new RBGNonce(16),
        },
      };
  }

  @DataProvider(name = "test-streams")
  public Object[][] getTestStreams()
  {
    return
      new Object[][] {
        new Object[] {
          "src/test/resources/plaintexts/lorem-5000.txt",
          "AES/CBC/PKCS7",
          new RBGNonce(16),
        },
        new Object[] {
          "src/test/resources/plaintexts/lorem-1200.txt",
          "Twofish/OFB/NULL",
          new BigIntegerCounterNonce(BigInteger.ONE, 16),
        },
        new Object[] {
          "src/test/resources/plaintexts/lorem-1200.txt",
          "AES/CFB/PKCS5",
          new RBGNonce(16),
        },
        new Object[] {
          "src/test/resources/plaintexts/lorem-1200.txt",
          "AES/ECB/PKCS5",
          new RBGNonce(16),
        },
      };
  }


  @Test(dataProvider = "test-arrays")
  public void testEncryptDecryptArray(final String input, final String cipherSpecString, final Nonce nonce)
    throws Exception
  {
    final BufferedBlockCipherBean cipherBean = new BufferedBlockCipherBean();
    final BufferedBlockCipherSpec cipherSpec = BufferedBlockCipherSpec.parse(cipherSpecString);
    cipherBean.setNonce(nonce);
    cipherBean.setKeyAlias("vtcrypt");
    cipherBean.setKeyPassword("vtcrypt");
    cipherBean.setKeyStore(getTestKeyStore());
    cipherBean.setBlockCipherSpec(cipherSpec);

    final byte[] ciphertext = cipherBean.encrypt(ByteUtil.toBytes(input));
    assertEquals(ByteUtil.toString(cipherBean.decrypt(ciphertext)), input);
  }


  @Test(dataProvider = "test-streams")
  public void testEncryptDecryptStream(final String path, final String cipherSpecString, final Nonce nonce)
    throws Exception
  {
    final BufferedBlockCipherBean cipherBean = new BufferedBlockCipherBean();
    final BufferedBlockCipherSpec cipherSpec = BufferedBlockCipherSpec.parse(cipherSpecString);
    cipherBean.setNonce(nonce);
    cipherBean.setKeyAlias("vtcrypt");
    cipherBean.setKeyPassword("vtcrypt");
    cipherBean.setKeyStore(getTestKeyStore());
    cipherBean.setBlockCipherSpec(cipherSpec);

    final ByteArrayOutputStream tempOut = new ByteArrayOutputStream(8192);
    cipherBean.encrypt(StreamUtil.makeStream(new File(path)), tempOut);

    final ByteArrayInputStream tempIn = new ByteArrayInputStream(tempOut.toByteArray());
    final ByteArrayOutputStream finalOut = new ByteArrayOutputStream(8192);
    cipherBean.decrypt(tempIn, finalOut);
    assertEquals(ByteUtil.toString(finalOut.toByteArray()), ByteUtil.toString(StreamUtil.readAll(path)));
  }

  private static KeyStore getTestKeyStore()
  {
    final KeyStoreFactoryBean bean = new KeyStoreFactoryBean();
    bean.setPassword("vtcrypt");
    bean.setResource(new FileResource(new File("src/test/resources/keystores/cipher-bean.jceks")));
    bean.setType("JCEKS");
    return bean.newInstance();
  }
}
