/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.cryptacular.util.NonceUtil;

/**
 * Factory class with static methods for generating {@link SecretKey}s.
 *
 * @author  Middleware Services
 */
public final class SecretKeyGenerator
{

  /** Private constructor of static class. */
  private SecretKeyGenerator() {}


  /**
   * Generates a symmetric encryption key whose size is equal to the cipher
   * block size.
   *
   * @param  cipher  Cipher with with key will be used.
   *
   * @return  Symmetric encryption key.
   */
  public static SecretKey generate(final BlockCipher cipher)
  {
    return generate(cipher.getBlockSize() * 8, cipher);
  }


  /**
   * Generates a symmetric encryption key of the given length.
   *
   * @param  bitLength  Desired key length in bits.
   * @param  cipher  Cipher with with key will be used.
   *
   * @return  Symmetric encryption key.
   */
  public static SecretKey generate(
    final int bitLength,
    final BlockCipher cipher)
  {
    // Want as much nonce data as key bits
    final byte[] nonce = NonceUtil.timestampNonce((bitLength + 7) / 8);
    return
      generate(
        bitLength,
        cipher,
        new SP800SecureRandomBuilder().buildHash(
          new SHA256Digest(),
          nonce,
          false));
  }


  /**
   * Generates a symmetric encryption key of the given length.
   *
   * @param  bitLength  Desired key length in bits.
   * @param  cipher  Cipher with with key will be used.
   * @param  random  Randomness provider for key generation.
   *
   * @return  Symmetric encryption key.
   */
  public static SecretKey generate(
    final int bitLength,
    final BlockCipher cipher,
    final SecureRandom random)
  {
    // Round up for bit lengths that are not a multiple of 8
    final byte[] key = new byte[(bitLength + 7) / 8];
    random.nextBytes(key);
    return new SecretKeySpec(key, cipher.getAlgorithmName());
  }
}
