/*
 * Licensed to Virginia Tech under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Virginia Tech licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.cryptosis.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
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
   * @param  data  Data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] hash(final Digest digest, final byte[] data)
  {
    return hashInternal(digest, data, null);
  }


  /**
   * Computes the hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Input stream containing data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] hash(final Digest digest, final InputStream input)
  {
    return hashInternal(digest, input, null);
  }


  /**
   * Computes the salted hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  data  Data to hash.
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
    return hash(digest, data, salt);
  }


  /**
   * Computes the salted hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Input stream containing data to hash.
   * @param  saltSize  Number of bytes of random salt to append to digest.
   *
   * @return  Hash bytes with appended salt that completely fill returned byte array.
   */
  public static byte[] hash(final Digest digest, final InputStream input, final int saltSize)
  {
    final DigestRandomGenerator rng = new DigestRandomGenerator(digest);
    rng.addSeedMaterial(NonceUtil.timestampNonce(saltSize));
    final byte[] salt = new byte[saltSize];
    rng.nextBytes(salt);
    return hash(digest, input, salt);
  }


  /**
   * Computes the salted hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  data  Data to hash.
   * @param  salt  Salt to append to hash.
   *
   * @return  Hash bytes with appended salt that completely fill returned byte array.
   */
  public static byte[] hash(final Digest digest, final byte[] data, final byte[] salt)
  {
    final byte[] output = hashInternal(digest, data, salt);
    if (salt != null) {
      System.arraycopy(salt, 0, output, digest.getDigestSize(), salt.length);
    }
    return output;
  }


  /**
   * Computes the salted hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Input stream containing data to hash.
   * @param  salt  Salt to append to hash.
   *
   * @return  Hash bytes with appended salt that completely fill returned byte array.
   */
  public static byte[] hash(final Digest digest, final InputStream input, final byte[] salt)
  {
    final byte[] output = hashInternal(digest, input, salt);
    if (salt != null) {
      System.arraycopy(salt, 0, output, digest.getDigestSize(), salt.length);
    }
    return output;
  }


  /**
   * Computes an iterated, salted hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  data  Data to hash.
   * @param  salt  Salt to append to hash.
   * @param  iterations  Number of hash iterations to perform on input data.
   *
   * @return  Hash bytes with appended salt that completely fill returned byte array.
   */
  public static byte[] hash(final Digest digest, final byte[] data, final byte[] salt, final int iterations)
  {
    final byte[] result = hashInternal(digest, data, salt);
    iterate(digest, result, iterations);
    if (salt != null) {
      System.arraycopy(salt, 0, result, digest.getDigestSize(), salt.length);
    }
    return result;
  }


  /**
   * Computes an iterated, salted hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Input stream containing data to hash.
   * @param  salt  Salt to append to hash.
   * @param  iterations  Number of hash iterations to perform on input data.
   *
   * @return  Hash bytes with appended salt that completely fill returned byte array.
   */
  public static byte[] hash(final Digest digest, final InputStream input, final byte[] salt, final int iterations)
  {
    final byte[] result = hashInternal(digest, input, salt);
    iterate(digest, result, iterations);
    if (salt != null) {
      System.arraycopy(salt, 0, result, digest.getDigestSize(), salt.length);
    }
    return result;
  }


  /**
   * Determines whether the hash of the given input equals a known value.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Data to hash.
   * @param  hash  Hash to compare with.
   *
   * @return  True if the hash of the data under the given digest is equal to the hash, false otherwise.
   */
  public static boolean compareHash(final Digest digest, final byte[] input, final byte[] hash)
  {
    return Arrays.equals(hash(digest, input), hash);
  }


  /**
   * Determines whether the hash of the given input equals a known value.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Input stream containing data to hash.
   * @param  hash  Hash to compare with.
   *
   * @return  True if the hash of the data under the given digest is equal to the hash, false otherwise.
   */
  public static boolean compareHash(final Digest digest, final InputStream input, final byte[] hash)
  {
    return Arrays.equals(hash(digest, input), hash);
  }


  /**
   * Determines whether the salted hash of the given input equals a known hash. The hash value is assumed to contain
   * the salt appended to the hash output.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Input to hash.
   * @param  iterations  Number of hash rounds.
   * @param  saltedHash  Hash to compare with of the form <code>DIGEST+SALT</code>, that is, where the salt is appended
   *                     to the digest output bytes.
   *
   * @return  True if the hash of the data under the given digest is equal to the hash, false otherwise.
   */
  public static boolean compareSaltedHash(
    final Digest digest, final byte[] input, final int iterations, final byte[] saltedHash)
  {
    final byte[] salt = new byte[saltedHash.length - digest.getDigestSize()];
    System.arraycopy(saltedHash, digest.getDigestSize(), salt, 0, salt.length);
    return Arrays.equals(hash(digest, input, salt, iterations), saltedHash);
  }


  /**
   * Determines whether the salted hash of the given input equals a known hash. The hash value is assumed to contain
   * the salt appended to the hash output.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Input stream containing data to hash.
   * @param  iterations  Number of hash rounds.
   * @param  saltedHash  Hash to compare with of the form <code>DIGEST+SALT</code>, that is, where the salt is appended
   *                     to the digest output bytes.
   *
   * @return  True if the hash of the data under the given digest is equal to the hash, false otherwise.
   */
  public static boolean compareSaltedHash(
    final Digest digest, final InputStream input, final int iterations, final byte[] saltedHash)
  {
    final byte[] salt = new byte[saltedHash.length - digest.getDigestSize()];
    System.arraycopy(saltedHash, digest.getDigestSize(), salt, 0, salt.length);
    return Arrays.equals(hash(digest, input, salt, iterations), saltedHash);
  }


  /**
   * Produces the SHA-1 hash of the given data.
   *
   * @param  data  Data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha1(final byte[] data)
  {
    return hash(new SHA1Digest(), data);
  }


  /**
   * Produces the SHA-1 hash of the given data.
   *
   * @param  input  Input stream containing data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha1(final InputStream input)
  {
    return hash(new SHA1Digest(), input);
  }


  /**
   * Produces the SHA-256 hash of the given data.
   *
   * @param  data  Data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha256(final byte[] data)
  {
    return hash(new SHA256Digest(), data);
  }


  /**
   * Produces the SHA-256 hash of the given data.
   *
   * @param  input  Input stream containing data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha256(final InputStream input)
  {
    return hash(new SHA256Digest(), input);
  }


  /**
   * Produces the SHA-512 hash of the given data.
   *
   * @param  data  Data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha512(final byte[] data)
  {
    return hash(new SHA512Digest(), data);
  }


  /**
   * Produces the SHA-512 hash of the given data.
   *
   * @param  input  Input stream containing data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha512(final InputStream input)
  {
    return hash(new SHA512Digest(), input);
  }


  /**
   * Produces the SHA-3 hash of the given data.
   *
   * @param  data  Data to hash.
   * @param  bitLength  Desired size in bits.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha3(final byte[] data, final int bitLength)
  {
    return hash(new SHA3Digest(bitLength), data);
  }


  /**
   * Produces the SHA-3 hash of the given data.
   *
   * @param  input  Input stream containing data to hash.
   * @param  bitLength  Desired size in bits.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha3(final InputStream input, final int bitLength)
  {
    return hash(new SHA3Digest(bitLength), input);
  }


  /**
   * Computes a salted hash but does not concatenate the salt to the hash bytes.
   *
   * @param  digest  Digest algorithm.
   * @param  data  Data to hash.
   * @param  salt  Optional salt.
   *
   * @return  Byte array of length equal to digest + salt filled with digest bytes only.
   */
  private static byte[] hashInternal(final Digest digest, final byte[] data, final byte[] salt)
  {
    final int outSize;
    if (salt != null) {
      digest.update(salt, 0, salt.length);
      outSize = digest.getDigestSize() + salt.length;
    } else {
      outSize = digest.getDigestSize();
    }
    digest.update(data, 0, data.length);
    final byte[] output = new byte[outSize];
    digest.doFinal(output, 0);
    return output;
  }


  /**
   * Computes a salted hash but does not concatenate the salt to the hash bytes.
   *
   * @param  digest  Digest algorithm.
   * @param  in  Input stream containing data to hash.
   * @param  salt  Optional salt.
   *
   * @return  Byte array of length equal to digest + salt filled with digest bytes only.
   */
  private static byte[] hashInternal(final Digest digest, final InputStream in, final byte[] salt)
  {
    final byte[] buffer = new byte[StreamUtil.CHUNK_SIZE];
    final int outSize;
    if (salt != null) {
      digest.update(salt, 0, salt.length);
      outSize = digest.getDigestSize() + salt.length;
    } else {
      outSize = digest.getDigestSize();
    }
    final byte[] output = new byte[outSize];
    int length;
    try {
      while ((length = in.read(buffer)) > 0) {
        digest.update(buffer, 0, length);
      }
    } catch (IOException e) {
      throw new RuntimeException("Error reading stream", e);
    }
    digest.doFinal(output, 0);
    return output;
  }


  /**
   * Computes the given number of iterations on a hash.
   *
   * @param  digest  Digest algorithm.
   * @param  hash  Initial hash output (i.e. first iteration).
   * @param  iterations  Number of iterations to compute. Actual number is one less than this value since it expects
   *                     a hash to have been performed to produce the hash parameter.
   */
  private static void iterate(final Digest digest, final byte[] hash, final int iterations)
  {
    final int size = digest.getDigestSize();
    for (int i = 1; i < iterations; i++) {
      digest.update(hash, 0, size);
      digest.doFinal(hash, 0);
    }
  }
}
