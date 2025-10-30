/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.cryptacular.FailListener;
import org.cryptacular.bean.KeyStoreBasedKeyFactoryBean;
import org.cryptacular.bean.KeyStoreFactoryBean;
import org.cryptacular.generator.Nonce;
import org.cryptacular.generator.SecretKeyGenerator;
import org.cryptacular.generator.sp80038a.LongCounterNonce;
import org.cryptacular.generator.sp80038a.RBGNonce;
import org.cryptacular.generator.sp80038d.CounterNonce;
import org.cryptacular.io.FileResource;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link CipherUtil} class.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class CipherUtilTest
{
  /** Static key derived from keystore on resource classpath. */
  private static final SecretKey STATIC_KEY;

  static
  {
    final KeyStoreFactoryBean keyStoreFactory = new KeyStoreFactoryBean(
      new FileResource(new File("src/test/resources/keystores/cipher-bean.jceks")), "JCEKS", "vtcrypt");
    final KeyStoreBasedKeyFactoryBean<SecretKey> keyFactory = new KeyStoreBasedKeyFactoryBean<>(
      keyStoreFactory.newInstance(), "vtcrypt", "vtcrypt");
    STATIC_KEY = keyFactory.newInstance();
  }

  @DataProvider(name = "block-cipher")
  public Object[][] getBlockCipherData()
  {
    return
      new Object[][] {
        new Object[] {
          // Plaintext is NOT multiple of block size
          "Able was I ere I saw elba.",
          CBCBlockCipher.newInstance(AESEngine.newInstance()),
          new RBGNonce(16),
        },
        // Plaintext is multiple of block size
        new Object[] {
          "Four score and seven years ago, our forefathers ",
          CBCBlockCipher.newInstance(new BlowfishEngine()),
          new RBGNonce(8),
        },
        // OFB
        new Object[] {
          "Have you passed through this night?",
          new OFBBlockCipher(new BlowfishEngine(), 64),
          new LongCounterNonce(),
        },
        // CFB
        new Object[] {
          "I went to the woods because I wished to live deliberately, to front only the essential facts of life",
          CFBBlockCipher.newInstance(AESEngine.newInstance(), 128),
          new RBGNonce(16),
        },
      };
  }


  @DataProvider(name = "aead-block-cipher")
  public Object[][] getAeadBlockCipherData()
  {
    return
      new Object[][] {
        new Object[] {
          // Plaintext is NOT multiple of block size
          "I never picked cotton like my mother did",
          GCMBlockCipher.newInstance(AESEngine.newInstance()),
        },
        new Object[] {
          // Plaintext is multiple of block size
          "Cogito ergo sum.",
          GCMBlockCipher.newInstance(AESEngine.newInstance()),
        },
        // CCM
        new Object[] {
          "Thousands of candles can be lit from a single candle and the life of the candle will not be shortened.",
          CCMBlockCipher.newInstance(new TwofishEngine()),
        },
        // OCB
        new Object[] {
          "I slept and dreamt life was joy. I awoke and saw that life was service. " +
            "I acted and behold: service was joy.",
          new OCBBlockCipher(AESEngine.newInstance(), AESEngine.newInstance()),
        },
      };
  }


  @DataProvider(name = "plaintext-files")
  public Object[][] getPlaintextFiles()
  {
    return
      new Object[][] {
        new Object[] {"src/test/resources/plaintexts/lorem-1200.txt"},
        new Object[] {"src/test/resources/plaintexts/lorem-5000.txt"},
      };
  }


  @Test(dataProvider = "block-cipher")
  public void testBlockCipherEncryptDecrypt(final String plaintext, final BlockCipher cipher, final Nonce nonce)
  {
    final SecretKey key = SecretKeyGenerator.generate(cipher);
    final byte[] ciphertext = CipherUtil.encrypt(cipher, key, nonce, plaintext.getBytes());
    final byte[] result = CipherUtil.decrypt(cipher, key, ciphertext);
    assertThat(new String(result)).isEqualTo(plaintext);
  }


  @Test(dataProvider = "aead-block-cipher")
  public void testAeadBlockCipherEncryptDecrypt(final String plaintext, final AEADBlockCipher cipher)
  {
    final BlockCipher under = cipher.getUnderlyingCipher();
    final SecretKey key = SecretKeyGenerator.generate(under);
    final byte[] ciphertext = CipherUtil.encrypt(cipher, key, new RBGNonce(12), plaintext.getBytes());
    final byte[] result = CipherUtil.decrypt(cipher, key, ciphertext);
    assertThat(new String(result)).isEqualTo(plaintext);
  }


  @Test(dataProvider = "plaintext-files")
  public void testBlockCipherEncryptDecryptStream(final String path)
    throws Exception
  {
    final BlockCipher cipher = CBCBlockCipher.newInstance(AESEngine.newInstance());
    final SecretKey key = SecretKeyGenerator.generate(cipher);
    final Nonce nonce = new CounterNonce("vt-crypt", 1);
    final File file = new File(path);
    final String expected = new String(StreamUtil.readAll(file));
    final ByteArrayOutputStream tempOut = new ByteArrayOutputStream();
    CipherUtil.encrypt(cipher, key, nonce, StreamUtil.makeStream(file), tempOut);

    final ByteArrayInputStream tempIn = new ByteArrayInputStream(tempOut.toByteArray());
    final ByteArrayOutputStream actual = new ByteArrayOutputStream();
    CipherUtil.decrypt(cipher, key, tempIn, actual);
    assertThat(actual.toString()).isEqualTo(expected);
  }


  @Test(dataProvider = "plaintext-files")
  public void testAeadBlockCipherEncryptDecryptStream(final String path)
    throws Exception
  {
    final AEADBlockCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
    final SecretKey key = SecretKeyGenerator.generate(cipher.getUnderlyingCipher());
    final File file = new File(path);
    final String expected = new String(StreamUtil.readAll(file));
    final ByteArrayOutputStream tempOut = new ByteArrayOutputStream();
    CipherUtil.encrypt(cipher, key, new RBGNonce(), StreamUtil.makeStream(file), tempOut);

    final ByteArrayInputStream tempIn = new ByteArrayInputStream(tempOut.toByteArray());
    final ByteArrayOutputStream actual = new ByteArrayOutputStream();
    CipherUtil.decrypt(cipher, key, tempIn, actual);
    assertThat(actual.toString()).isEqualTo(expected);
  }


  @Test(enabled = false)
  public void testDecryptArrayBackwardCompatibleHeader()
  {
    final AEADBlockCipher cipher = new OCBBlockCipher(new TwofishEngine(), new TwofishEngine());
    final String expected = "Have you passed through this night?";
    final String v1CiphertextHex =
      "0000001f0000000c76746d770002ba17043672d900000007767463727970745a38dee735266e3f5f7aafec8d1c9ed8a0830a2ff9" +
        "c3a46c25f89e69b6eb39dbb82fd13da50e32b2544a73f1a4476677b377e6";
    final byte[] plaintext = CipherUtil.decrypt(cipher, STATIC_KEY, CodecUtil.hex(v1CiphertextHex));
    assertThat(ByteUtil.toString(plaintext)).isEqualTo(expected);
  }


  @Test(enabled = false)
  public void testDecryptStreamBackwardCompatibleHeader()
  {
    final AEADBlockCipher cipher = new OCBBlockCipher(new TwofishEngine(), new TwofishEngine());
    final String expected = "Have you passed through this night?";
    final String v1CiphertextHex =
      "0000001f0000000c76746d770002ba17043672d900000007767463727970745a38dee735266e3f5f7aafec8d1c9ed8a0830a2ff9" +
        "c3a46c25f89e69b6eb39dbb82fd13da50e32b2544a73f1a4476677b377e6";
    final ByteArrayInputStream in = new ByteArrayInputStream(CodecUtil.hex(v1CiphertextHex));
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    CipherUtil.decrypt(cipher, STATIC_KEY, in, out);
    assertThat(ByteUtil.toString(out.toByteArray())).isEqualTo(expected);
  }
}
