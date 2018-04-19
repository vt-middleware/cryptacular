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
import org.cryptacular.generator.Nonce;
import org.cryptacular.generator.SecretKeyGenerator;
import org.cryptacular.generator.sp80038a.LongCounterNonce;
import org.cryptacular.generator.sp80038a.RBGNonce;
import org.cryptacular.generator.sp80038d.CounterNonce;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link CipherUtil} class.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class CipherUtilTest
{
  @DataProvider(name = "block-cipher")
  public Object[][] getBlockCipherData()
  {
    return
      new Object[][] {
        new Object[] {
          // Plaintext is NOT multiple of block size
          "Able was I ere I saw elba.",
          new CBCBlockCipher(new AESEngine()),
          new RBGNonce(16),
        },
        // Plaintext is multiple of block size
        new Object[] {
          "Four score and seven years ago, our forefathers ",
          new CBCBlockCipher(new BlowfishEngine()),
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
          new CFBBlockCipher(new AESEngine(), 128),
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
          new GCMBlockCipher(new AESEngine()),
        },
        new Object[] {
          // Plaintext is multiple of block size
          "Cogito ergo sum.",
          new GCMBlockCipher(new AESEngine()),
        },
        // CCM
        new Object[] {
          "Thousands of candles can be lit from a single candle and the life of the candle will not be shortened.",
          new CCMBlockCipher(new TwofishEngine()),
        },
        // OCB
        new Object[] {
          "I slept and dreamt life was joy. I awoke and saw that life was service. " +
            "I acted and behold: service was joy.",
          new OCBBlockCipher(new AESEngine(), new AESEngine()),
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
    assertEquals(new String(result), plaintext);
  }


  @Test(dataProvider = "aead-block-cipher")
  public void testAeadBlockCipherEncryptDecrypt(final String plaintext, final AEADBlockCipher cipher)
  {
    final BlockCipher under = cipher.getUnderlyingCipher();
    final SecretKey key = SecretKeyGenerator.generate(under);
    final byte[] ciphertext = CipherUtil.encrypt(cipher, key, new RBGNonce(12), plaintext.getBytes());
    final byte[] result = CipherUtil.decrypt(cipher, key, ciphertext);
    assertEquals(new String(result), plaintext);
  }


  @Test(dataProvider = "plaintext-files")
  public void testBlockCipherEncryptDecryptStream(final String path)
    throws Exception
  {
    final BlockCipher cipher = new CBCBlockCipher(new AESEngine());
    final SecretKey key = SecretKeyGenerator.generate(cipher);
    final Nonce nonce = new CounterNonce("vt-crypt", 1);
    final File file = new File(path);
    final String expected = new String(StreamUtil.readAll(file));
    final ByteArrayOutputStream tempOut = new ByteArrayOutputStream();
    CipherUtil.encrypt(cipher, key, nonce, StreamUtil.makeStream(file), tempOut);

    final ByteArrayInputStream tempIn = new ByteArrayInputStream(tempOut.toByteArray());
    final ByteArrayOutputStream actual = new ByteArrayOutputStream();
    CipherUtil.decrypt(cipher, key, tempIn, actual);
    assertEquals(new String(actual.toByteArray()), expected);
  }


  @Test(dataProvider = "plaintext-files")
  public void testAeadBlockCipherEncryptDecryptStream(final String path)
    throws Exception
  {
    final AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine());
    final SecretKey key = SecretKeyGenerator.generate(cipher.getUnderlyingCipher());
    final File file = new File(path);
    final String expected = new String(StreamUtil.readAll(file));
    final ByteArrayOutputStream tempOut = new ByteArrayOutputStream();
    CipherUtil.encrypt(cipher, key, new RBGNonce(), StreamUtil.makeStream(file), tempOut);

    final ByteArrayInputStream tempIn = new ByteArrayInputStream(tempOut.toByteArray());
    final ByteArrayOutputStream actual = new ByteArrayOutputStream();
    CipherUtil.decrypt(cipher, key, tempIn, actual);
    assertEquals(new String(actual.toByteArray()), expected);
  }
}
