package org.cryptosis;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;

/**
 * Utility class for computing cryptographic hashes.
 *
 * @author  Marvin S. Addison
 */
public final class HashUtil
{
  /** Private constructor of utility class. */
  private HashUtil() {}

  /**
   * Computes the hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  data  Cleartext data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] hash(final Digest digest, final byte[] data)
  {
    final byte[] result = new byte[digest.getDigestSize()];
    digest.update(data, 0, data.length);
    digest.doFinal(result, 0);
    digest.reset();
    return result;
  }


  /**
   * Computes the salted hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  data  Cleartext data to hash.
   * @param  saltSize  Number of bytes of random salt to append to digest.
   *
   * @return  Hash bytes with appended salt that completely fill returned byte array.
   */
  public static byte[] hash(final Digest digest, final byte[] data, final int saltSize)
  {
    final DigestRandomGenerator rng = new DigestRandomGenerator(digest);
    rng.addSeedMaterial(NonceUtil.timestampNonce(saltSize));
    final byte[] salt = new byte[saltSize];
    rng.nextBytes(salt);
    digest.reset();
    return hash(digest, data, salt, 1);
  }


  /**
   * Computes the salted hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  data  Cleartext data to hash.
   * @param  salt  Salt to append to hash.
   *
   * @return  Hash bytes with appended salt that completely fill returned byte array.
   */
  public static byte[] hash(final Digest digest, final byte[] data, final byte[] salt)
  {
    return hash(digest, data, salt, 1);
  }


  /**
   * Computes an iterated, salted hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  data  Cleartext data to hash.
   * @param  salt  Salt to append to hash.
   * @param  iterations  Number of hash iterations to perform on input data.
   *
   * @return  Hash bytes with appended salt that completely fill returned byte array.
   */
  public static byte[] hash(final Digest digest, final byte[] data, final byte[] salt, final int iterations)
  {
    digest.update(data, 0, data.length);
    final int outSize;
    if (salt != null) {
      digest.update(salt, 0, salt.length);
      outSize = digest.getDigestSize() + salt.length;
    } else {
      outSize = digest.getDigestSize();
    }
    final byte[] result = new byte[outSize];
    int offset = digest.doFinal(result, 0);
    for (int i = 1; i < iterations; i++) {
      digest.reset();
      digest.update(result, 0, offset);
      offset = digest.doFinal(result, 0);
    }
    digest.reset();
    if (salt != null) {
      System.arraycopy(salt, 0, result, offset, salt.length);
    }
    return result;
  }


  /**
   * Produces the SHA-1 hash of the given data.
   *
   * @param  data  Data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha1Hash(final byte[] data)
  {
    return hash(new SHA1Digest(), data);
  }


  /**
   * Produces the SHA-256 hash of the given data.
   *
   * @param  data  Data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha256Hash(final byte[] data)
  {
    return hash(new SHA256Digest(), data);
  }


  /**
   * Produces the SHA-384 hash of the given data.
   *
   * @param  data  Data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha384Hash(final byte[] data)
  {
    return hash(new SHA384Digest(), data);
  }


  /**
   * Produces the SHA-512 hash of the given data.
   *
   * @param  data  Data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha512Hash(final byte[] data)
  {
    return hash(new SHA512Digest(), data);
  }


  /**
   * Produces the SHA-3 hash of the given data.
   *
   * @param  data  Data to hash.
   * @param  bitLength  Desired size in bits.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha3Hash(final byte[] data, final int bitLength)
  {
    return hash(new SHA3Digest(bitLength), data);
  }
}
