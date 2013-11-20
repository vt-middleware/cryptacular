package org.cryptosis;

import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link CipherUtil} class.
 *
 * @author Marvin S. Addison
 */
public class CipherUtilTest
{
  @DataProvider(name = "block-cipher")
  public Object[][] getBlockCipherData()
  {
    return new Object[][] {
      new Object[] {
        // Plaintext is NOT multiple of block size
        "Able was I ere I saw elba.",
        new CBCBlockCipher(new AESEngine())
      },
      // Plaintext is multiple of block size
      new Object[] {
        "Four score and seven years ago, our forefathers ",
        new CBCBlockCipher(new BlowfishEngine())
      },
      // OFB
      new Object[] {
        "Have you passed through this night?",
        new OFBBlockCipher(new BlowfishEngine(), 64)
      },
      // CFB
      new Object[] {
        "I went to the woods because I wished to live deliberately, to front only the essential facts of life",
        new CFBBlockCipher(new AESEngine(), 128)
      },
    };
  }


  @DataProvider(name = "aead-block-cipher")
  public Object[][] getAeadBlockCipherData()
  {
    return new Object[][] {
      new Object[] {
        // Plaintext is NOT multiple of block size
        "I never picked cotton like my mother did",
        new GCMBlockCipher(new AESEngine())
      },
      new Object[] {
        // Plaintext is multiple of block size
        "Cogito ergo sum.",
        new GCMBlockCipher(new AESEngine())
      },
      // CCM
      new Object[] {
        "Thousands of candles can be lit from a single candle and the life of the candle will not be shortened.",
        new CCMBlockCipher(new TwofishEngine())
      },
      // OCB
      new Object[] {
        "I slept and dreamt life was joy. I awoke and saw that life was service. I acted and behold: service was joy.",
        new OCBBlockCipher(new AESEngine(), new AESEngine())
      },
    };
  }


  @Test(dataProvider = "block-cipher")
  public void testBlockCipherEncryptDecrypt(final String plaintext, final BlockCipher cipher)
  {
    final byte[] keyBytes = new byte[cipher.getBlockSize()];
    new SecureRandom().nextBytes(keyBytes);
    final SecretKey key = new SecretKeySpec(keyBytes, cipher.getAlgorithmName());
    final byte[] ciphertext = CipherUtil.encrypt(cipher, key, plaintext.getBytes());
    final byte[] result = CipherUtil.decrypt(cipher, key, ciphertext);
    assertEquals(new String(result), plaintext);
  }


  @Test(dataProvider = "aead-block-cipher")
  public void testAeadBlockCipherEncryptDecrypt(final String plaintext, final AEADBlockCipher cipher)
  {
    final BlockCipher under = cipher.getUnderlyingCipher();
    final byte[] keyBytes = new byte[under.getBlockSize()];
    new SecureRandom().nextBytes(keyBytes);
    final SecretKey key = new SecretKeySpec(keyBytes, under.getAlgorithmName());
    final byte[] ciphertext = CipherUtil.encrypt(cipher, key, plaintext.getBytes());
    final byte[] result = CipherUtil.decrypt(cipher, key, ciphertext);
    assertEquals(new String(result), plaintext);
  }
}
