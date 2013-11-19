package org.cryptosis;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.SecretKey;

/**
 * Utility class that performs encryption and decryption operations using a block cipher.
 *
 * @author Marvin S. Addison
 */
public final class CipherUtil
{
  /** Default nonce size in bytes. */
  private static final int DEFAULT_NONCE_SIZE = 16;

  /** GCM mac size in bits. */
  private static final int GMAC_SIZE_BITS = 256;

  /** GCM mac size in bytes. */
  private static final int GMAC_SIZE_BYTES = GMAC_SIZE_BITS / 8;

  /** Private constructor of utility class. */
  private CipherUtil() {}

  public static byte[] encrypt(final BlockCipher cipher, final SecretKey key, final byte[] data)
  {
    final GCMBlockCipher c = new GCMBlockCipher(cipher);
    final byte[] nonce = NonceUtil.rfc5116Nonce(DEFAULT_NONCE_SIZE);
    final byte[] header = new CiphertextHeader(nonce).encode();
    final int outSize = header.length + data.length + data.length % 16 + GMAC_SIZE_BYTES;
    final byte[] result = new byte[outSize];
    c.init(true, new AEADParameters(new KeyParameter(key.getEncoded()), GMAC_SIZE_BITS, nonce, header));
    System.arraycopy(header, 0, result, 0, header.length);
    final int offset = c.processBytes(data, 0, data.length, result, header.length);
    try {
      c.doFinal(result, offset);
    } catch (InvalidCipherTextException e) {
      throw new RuntimeException("Encryption failed", e);
    }
    return result;
  }

  public static byte[] decrypt(final BlockCipher cipher, final SecretKey key, final byte[] data)
  {
    final CiphertextHeader header = CiphertextHeader.decode(data);
    final GCMBlockCipher c = new GCMBlockCipher(cipher);
    final int outSize = data.length - header.getNonce().length - GMAC_SIZE_BYTES;
    byte[] result = new byte[outSize];
    c.init(false, new AEADParameters(new KeyParameter(key.getEncoded()), GMAC_SIZE_BITS, header.getNonce()));
    int length = c.processBytes(data, 0, data.length, result, header.getLength());
    try {
      length += c.doFinal(result, length);
    } catch (InvalidCipherTextException e) {
      throw new RuntimeException("Encryption failed", e);
    }
    if (length < result.length) {
      final byte[] temp = new byte[length];
      System.arraycopy(result, 0, temp, 0, length);
      result = temp;
    }
    return result;
  }

}
