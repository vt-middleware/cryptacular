/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.lang.reflect.Method;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.SP800SecureRandom;
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
import org.cryptacular.generator.sp80038a.EncryptedNonce;
import org.cryptacular.generator.sp80038d.RBGNonce;

/**
 * Utility class for generating secure nonce and initialization vectors.
 *
 * @author  Middleware Services
 */
public final class NonceUtil
{
  /** Class-wide random source. */
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  /** Seed random source. */
  static
  {
    SECURE_RANDOM.setSeed(SECURE_RANDOM.generateSeed(16));
  }

  /** Private constructor of utility class. */
  private NonceUtil() {}


  /**
   * Generates a nonce of the given size by repetitively concatenating system timestamps (i.e. {@link
   * System#nanoTime()}) up to the required size.
   *
   * @param  length  Positive number of bytes in nonce.
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
        nonce[count++] = (byte) (timestamp & 0xFF);
        timestamp >>= 8;
      }
    }
    return nonce;
  }


  /**
   * Generates a random nonce of the given length in bytes.
   *
   * @param  length  Positive number of bytes in nonce.
   *
   * @return  Nonce bytes.
   */
  public static byte[] randomNonce(final int length)
  {
    if (length <= 0) {
      throw new IllegalArgumentException(length + " is invalid. Length must be positive.");
    }
    final byte[] nonce = new byte[length];
    SECURE_RANDOM.nextBytes(nonce);
    return nonce;
  }


  /**
   * Creates a new entropy source that wraps a {@link SecureRandom} to produce random bytes.
   *
   * @param length Size of entropy blocks.
   *
   * @return New random entropy source.
   */
  public static EntropySource randomEntropySource(final int length)
  {
    return new EntropySource() {
      @Override
      public boolean isPredictionResistant()
      {
        return true;
      }

      @Override
      public byte[] getEntropy()
      {
        final byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
      }

      @Override
      public int entropySize()
      {
        return length;
      }
    };
  }


  /**
   * Generates a nonce/IV using the strategy described in NIST <a
   * href="http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf">SP-800-38d</a>, section 8.2.2, "RBG-based
   * Construction". The implementation uses a hash-based DRBG based on a SHA-256 digest, and uses random data for all
   * bits of the nonce; that is, the fixed field is null.
   *
   * <p>This nonce generation strategy is suitable for GCM ciphers.</p>
   *
   * @param  length  Number of bytes in nonce; MUST be 12 or more.
   *
   * @return  Nonce bytes.
   */
  public static byte[] nist80038d(final int length)
  {
    return new RBGNonce(length).generate();
  }


  /**
   * Generates a random IV according to NIST <a href="http://goo.gl/S9z8qF">SP-800-63a</a>, appendix C, method 1
   * (encrypted nonce), suitable for use with any block cipher mode described in that standard. This method uses an
   * instance of {@link EncryptedNonce} for the implementation.
   *
   * @param  cipher  Block cipher.
   * @param  key  Encryption key intended for use with IV.
   *
   * @return  Cipher block size number of random bytes.
   *
   * @see  EncryptedNonce
   */
  public static byte[] nist80063a(final BlockCipher cipher, final SecretKey key)
  {
    BlockCipher raw = cipher;
    // Get the underlying cipher if there is one
    final Method method = ReflectUtil.getMethod(cipher.getClass(), "getUnderlyingCipher");
    if (method != null) {
      raw = (BlockCipher) ReflectUtil.invoke(cipher, method);
    }
    return new EncryptedNonce(raw, key).generate();
  }


  /**
   * Generates a random IV according to NIST <a href="http://goo.gl/S9z8qF">SP-800-63a</a>, appendix C, method 2
   * (pseudorandom), suitable for use with any block cipher mode described in that standard.
   *
   * @param  prng  NIST SP800-63a approved pseudorandom number generator.
   * @param  blockSize  Cipher block size in bytes.
   *
   * @return  Cipher block size number of random bytes.
   */
  public static byte[] nist80063a(final SP800SecureRandom prng, final int blockSize)
  {
    prng.setSeed(randomNonce(blockSize));

    final byte[] iv = new byte[blockSize];
    prng.nextBytes(iv);
    return iv;
  }


  /**
   * Generates a random IV according to NIST <a href="http://goo.gl/S9z8qF">SP-800-63a</a>, appendix C, method 2
   * (pseudorandom), suitable for use with any block cipher mode described in that standard. Uses an instance of {@link
   * RBGNonce} internally with length equal to block size of given cipher.
   *
   * @param  cipher  Block cipher.
   *
   * @return  Cipher block size number of random bytes.
   *
   * @see  RBGNonce
   */
  public static byte[] nist80063a(final BlockCipher cipher)
  {
    return new RBGNonce(cipher.getBlockSize()).generate();
  }


  /**
   * Creates a new DRBG instance based on a SHA-256 digest.
   *
   * @param  length  Length in bits of values to be produced by DRBG instance.
   *
   * @return  New DRGB instance.
   */
  public static SP80090DRBG newRBG(final int length)
  {
    return newRBG(new SHA256Digest(), length);
  }


  /**
   * Creates a new hash-based DRBG instance that uses the given digest as the pseudorandom source.
   *
   * @param  digest  Digest algorithm.
   * @param  length  Length in bits of values to be produced by DRBG instance.
   *
   * @return  New DRGB instance.
   */
  public static SP80090DRBG newRBG(final Digest digest, final int length)
  {
    return newRBG(digest, length, randomEntropySource(length));
  }

  /**
   * Creates a new hash-based DRBG instance that uses the given digest as the pseudorandom source.
   *
   * @param  digest  Digest algorithm.
   * @param  length  Length in bits of values to be produced by DRBG instance.
   * @param  es  Entropy source.
   *
   * @return  New DRGB instance.
   */
  public static SP80090DRBG newRBG(final Digest digest, final int length, final EntropySource es)
  {
    return new HashSP800DRBG(
        digest, length, es, Thread.currentThread().getName().getBytes(), NonceUtil.timestampNonce(8));
  }
}
