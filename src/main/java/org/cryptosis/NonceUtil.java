package org.cryptosis;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.SP800SecureRandom;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;

import javax.crypto.SecretKey;
import java.nio.charset.Charset;

/**
 * Utility class for generating secure nonce and initialization vectors.
 *
 * @author Marvin S. Addison
 */
public final class NonceUtil
{
  /** Fixed part of nonce described in http://tools.ietf.org/html/rfc5116#section-3.2. */
  private static final byte[] FIXED_NONCE_PART = "cryptosis.org.NonceUtils".getBytes(Charset.forName("ASCII"));


  /** Private constructor of utility class. */
  private NonceUtil() {}


  /**
   * Generates a nonce using the strategy described in RFC-5116, section 3.2,
   * <a href="http://tools.ietf.org/html/rfc5116#section-3.2">http://tools.ietf.org/html/rfc5116#section-3.2</a>,
   * where nonce is composed of a fixed part and a sequential part. The sequential part is provided by a timestamp
   * with nanosecond resolution, i.e. {@link System#nanoTime()}.
   *
   * @param  length  Number of bytes in nonce, in the range 12-32.
   *
   * @return  Nonce bytes.
   */
  public static byte[] rfc5116Nonce(final int length)
  {
    if (length < 12 || length > 32) {
      throw new IllegalArgumentException("Nonce must be 12 - 32 bytes.");
    }
    final byte[] nonce = new byte[length];
    System.arraycopy(FIXED_NONCE_PART, 0, nonce, 0, length - 8);
    long timestamp = System.nanoTime();
    for (int i = length - 8; i > 0; i--) {
      nonce[i] = (byte)(timestamp & 0xFF);
      timestamp >>= 8;
    }
    return nonce;
  }


  /**
   * Generates a random IV according to method 1 (encrypted nonce) in NIST SP800-63a, appendix C,
   * <a href="http://goo.gl/S9z8qF">http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf</a>,
   * suitable for use with any block cipher mode described in that standard.
   *
   * @param  cipher  Block cipher.
   *
   * @param  key  Encryption key intended for use with IV.
   *
   * @return  Cipher block size number of random bytes.
   */
  public static byte[] nist800IV(final BlockCipher cipher, final SecretKey key)
  {
    cipher.init(true, new KeyParameter(key.getEncoded()));
    final byte[] result = new byte[cipher.getBlockSize()];
    cipher.processBlock(rfc5116Nonce(cipher.getBlockSize()), 0, result, 0);
    cipher.reset();
    return result;
  }


  /**
   * Generates a random IV according to method 2 (pseudorandom) in NIST SP800-63a, appendix C,
   * <a href="http://goo.gl/S9z8qF">http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf</a>,
   * suitable for use with any block cipher mode described in that standard.
   *
   * @param  prng  NIST SP800-63a approved pseudorandom number generator.
   * @param  blockSize  Cipher block size in bytes.
   *
   * @return  Cipher block size number of random bytes.
   */
  public static byte[] nist800IV(final SP800SecureRandom prng, final int blockSize)
  {
    prng.setSeed(System.nanoTime());
    final byte[] iv = new byte[blockSize];
    prng.nextBytes(iv);
    return iv;
  }


  /**
   * Generates a random IV according to method 2 (pseudorandom) in NIST SP800-63a, appendix C,
   * <a href="http://goo.gl/S9z8qF">http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf</a>,
   * suitable for use with any block cipher mode described in that standard. This method uses a hash DRBG
   * based on a SHA-256 digest function.
   *
   * @param  cipher  Block cipher.
   *
   * @return  Cipher block size number of random bytes.
   */
  public static byte[] nist800IV(final BlockCipher cipher)
  {
    final byte[] nonce = rfc5116Nonce(cipher.getBlockSize());
    return nist800IV(
        new SP800SecureRandomBuilder().buildHash(new SHA256Digest(), nonce, false),
        cipher.getBlockSize());
  }
}
