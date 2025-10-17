/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

import org.cryptacular.codec.Encoder;
import org.cryptacular.util.CodecUtil;

/**
 * Container for the output of a salted hash operation that includes both the digest output and salt value.
 *
 * @author  Middleware Services
 */
public class SaltedHash
{

  /** Maximum salt length in bytes. */
  private static final int MAX_SALT_LENGTH = CryptUtil.parseInt(
    System.getProperty("org.cryptacular.maxSaltLength", "128"), i -> i > 0, 128);

  /** Digest output. */
  private final byte[] hash;

  /** Salt value. */
  private final byte[] salt;


  /**
   * Creates a new instance with digest and salt data.
   *
   * @param  hash  Digest output.
   * @param  salt  Salt value used to compute salt.
   */
  public SaltedHash(final byte[] hash, final byte[] salt)
  {
    this.hash = CryptUtil.assertNotNullArg(hash, "Hash cannot be null");
    this.salt = CryptUtil.assertNotNullArg(salt, "Salt cannot be null");
  }


  /**
   * Creates a new instance from byte input that contains the concatenation of digest output and salt.
   *
   * @param  hashWithSalt  Concatenation of hash and salt.
   * @param  digestLength  Number of bytes in digest output.
   * @param  toEnd  True if salt is appended to end of hash, false if salt is prepended to hash.
   */
  public SaltedHash(final byte[] hashWithSalt, final int digestLength, final boolean toEnd)
  {
    CryptUtil.assertNotNullArg(hashWithSalt, "Hash with salt cannot be null");
    if (digestLength < 0 || digestLength > MAX_SALT_LENGTH) {
      throw new IllegalArgumentException("Digest length must be positive and cannot exceed " + MAX_SALT_LENGTH);
    }
    if (hashWithSalt.length <= digestLength) {
      throw new IllegalArgumentException("Hash with salt length must be greater than digest length");
    }
    this.hash = new byte[digestLength];
    this.salt = new byte[hashWithSalt.length - digestLength];
    if (toEnd) {
      System.arraycopy(hashWithSalt, 0, hash, 0, hash.length);
      System.arraycopy(hashWithSalt, hash.length, salt, 0, salt.length);
    } else {
      System.arraycopy(hashWithSalt, 0, salt, 0, salt.length);
      System.arraycopy(hashWithSalt, salt.length, hash, 0, hash.length);
    }
  }


  /** @return  Digest output. */
  public byte[] getHash()
  {
    return hash;
  }


  /** @return  Salt value. */
  public byte[] getSalt()
  {
    return salt;
  }

  /**
   * Gets N bytes of salt.
   *
   * @param n Number of bytes of salt; must be less than or equal to salt size.
   *
   * @return First N bytes of salt.
   */
  public byte[] getSalt(final int n)
  {
    if (n > salt.length) {
      throw new IllegalArgumentException("Requested size exceeded length: " + n + ">" + salt.length);
    }
    final byte[] bytes = new byte[n];
    System.arraycopy(salt, 0, bytes, 0, n);
    return bytes;
  }


  /**
   * Gets an encoded string of the concatenation of digest output and salt.
   *
   * @param  toEnd  True to append salt to end of hash, false to prefix hash with salt.
   * @param  encoder  Encodes concatenated bytes to a string.
   *
   * @return  Salt concatenated to hash encoded as a string.
   */
  public String concatenateSalt(final boolean toEnd, final Encoder encoder)
  {
    return CodecUtil.encode(encoder, concatenateSalt(toEnd));
  }


  /**
   * Gets a byte array containing the concatenation of digest output and salt.
   *
   * @param  toEnd  True to append salt to end of hash, false to prefix hash with salt.
   *
   * @return  Salt concatenated to hash.
   */
  public byte[] concatenateSalt(final boolean toEnd)
  {
    final byte[] output = new byte[hash.length + salt.length];
    if (toEnd) {
      System.arraycopy(hash, 0, output, 0, hash.length);
      System.arraycopy(salt, 0, output, hash.length, salt.length);
    } else {
      System.arraycopy(salt, 0, output, 0, salt.length);
      System.arraycopy(hash, 0, output, salt.length, hash.length);
    }
    return output;
  }
}
