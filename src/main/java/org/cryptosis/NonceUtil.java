package org.cryptosis;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.SP800SecureRandom;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;

import javax.crypto.SecretKey;
import java.lang.reflect.Method;
import java.nio.charset.Charset;

/**
 * Utility class for generating secure nonce and initialization vectors.
 *
 * @author Marvin S. Addison
 */
public final class NonceUtil
{
  /** Private constructor of utility class. */
  private NonceUtil() {}


  /**
   * Generates a nonce of the given size by repetitively concatenating system timestamps
   * (i.e. {@link System#nanoTime()}) up to the required size.
   *
   * @param length  Positive number of bytes in nonce.
   *
   * @return  Nonce bytes.
   */
  public static byte[] timestampNonce(final int length)
  {
    if (length <= 0) {
      throw new IllegalArgumentException(length + " is invalid. Length must be positive.");
    }
    final byte[] nonce = new byte[length];
    int count = 0;
    long timestamp;
    while (count < length) {
      timestamp = System.nanoTime();
      for (int i = 0; i < 8 && count < length; i++) {
        nonce[count++] = (byte)(timestamp & 0xFF);
        timestamp >>= 8;
      }
    }
    return nonce;
  }


  /**
   * Generates a nonce/IV using the strategy described in
   * <a href="http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf">NIST SP 800-38d</a>, section 8.2.2,
   * "RBG-based Construction". Uses a DRBG based on a SHA-256 digest. This nonce generation strategy is suitable for
   * GCM ciphers.
   *
   * @param  length  Number of bytes in nonce; MUST be 12 or more.
   *
   * @return  Nonce bytes.
   */
  public static byte[] nist80038d(final int length)
  {
    if (length < 12) {
      throw new IllegalArgumentException("Length must be at least 12 bytes (96 bits).");
    }
    final byte[] nonce = timestampNonce(length);
    return nist80063a(
      new SP800SecureRandomBuilder().buildHash(new SHA256Digest(), nonce, false),
      length);
  }


  /**
   * Generates a random IV according to
   * <a href="http://goo.gl/S9z8qF">NIST SP 800-63a</a>, appendix C, method 1 (encrypted nonce),
   * suitable for use with any block cipher mode described in that standard.
   *
   * @param  cipher  Block cipher.
   *
   * @param  key  Encryption key intended for use with IV.
   *
   * @return  Cipher block size number of random bytes.
   */
  public static byte[] nist80063a(final BlockCipher cipher, final SecretKey key)
  {
    BlockCipher raw = cipher;
    // Get the underlying cipher if there is one
    final Method method = ReflectUtil.getMethod(cipher.getClass(), "getUnderlyingCipher");
    if (method != null) {
      raw = (BlockCipher) ReflectUtil.invoke(cipher, method);
    }
    raw.init(true, new KeyParameter(key.getEncoded()));

    final byte[] result = new byte[raw.getBlockSize()];
    final byte[] nonce = timestampNonce(raw.getBlockSize());
    raw.processBlock(nonce, 0, result, 0);
    raw.reset();
    return result;
  }


  /**
   * Generates a random IV according to
   * <a href="http://goo.gl/S9z8qF">NIST SP 800-63a</a>, appendix C, method 2 (pseudorandom),
   * suitable for use with any block cipher mode described in that standard.
   *
   * @param  prng  NIST SP800-63a approved pseudorandom number generator.
   * @param  blockSize  Cipher block size in bytes.
   *
   * @return  Cipher block size number of random bytes.
   */
  public static byte[] nist80063a(final SP800SecureRandom prng, final int blockSize)
  {
    prng.setSeed(System.nanoTime());
    final byte[] iv = new byte[blockSize];
    prng.nextBytes(iv);
    return iv;
  }


  /**
   * Generates a random IV according to
   * <a href="http://goo.gl/S9z8qF">NIST SP 800-63a</a>, appendix C, method 2 (pseudorandom),
   * suitable for use with any block cipher mode described in that standard.
   * This method uses a hash DRBG based on a SHA-256 digest function.
   *
   * @param  cipher  Block cipher.
   *
   * @return  Cipher block size number of random bytes.
   */
  public static byte[] nist80063a(final BlockCipher cipher)
  {
    final byte[] nonce = timestampNonce(cipher.getBlockSize());
    return nist80063a(
        new SP800SecureRandomBuilder().buildHash(new SHA256Digest(), nonce, false),
        cipher.getBlockSize());
  }
}
