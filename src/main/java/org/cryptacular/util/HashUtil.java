/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.cryptacular.SaltedHash;
import org.cryptacular.io.Resource;

/**
 * Utility class for computing cryptographic hashes.
 *
 * @author  Middleware Services
 */
public final class HashUtil
{

  /** Private constructor of utility class. */
  private HashUtil() {}


  /**
   * Computes the hash of the given data using the given algorithm. A salted hash may be produced as follows:
   *
   * <pre>
       // data is a byte array containing raw data to digest
       final byte[] salt = new RBGNonce(16).generate();
       final byte[] hash = HashUtil.hash(new SHA1Digest(), data, salt);
   * </pre>
   *
   * @param  digest  Hash algorithm.
   * @param  data  Data to hash. Supported types are <code>byte[]</code>, {@link CharSequence} ,{@link InputStream}, and
   *               {@link Resource}. Character data is processed in the <code>UTF-8</code> character set; if another
   *               character set is desired, the caller should convert to <code>byte[]</code> and provide the resulting
   *               bytes.
   *
   * @return  Byte array of length {@link Digest#getDigestSize()} containing hash output.
   */
  public static byte[] hash(final Digest digest, final Object... data)
  {
    for (Object o : data) {
      if (o instanceof byte[]) {
        final byte[] bytes = (byte[]) o;
        digest.update(bytes, 0, bytes.length);
      } else if (o instanceof String) {
        final byte[] bytes = ByteUtil.toBytes((String) o);
        digest.update(bytes, 0, bytes.length);
      } else if (o instanceof InputStream) {
        hashStream(digest, (InputStream) o);
      } else if (o instanceof Resource) {
        final InputStream in;
        try {
          in = ((Resource) o).getInputStream();
        } catch (IOException e) {
          throw new IllegalArgumentException("Error getting input stream from " + o);
        }
        hashStream(digest, in);
      } else {
        throw new IllegalArgumentException("Invalid input data type " + o);
      }
    }

    final byte[] output = new byte[digest.getDigestSize()];
    digest.doFinal(output, 0);
    return output;
  }


  /**
   * Computes the iterated hash of the given data using the given algorithm. The following example demonstrates a
   * typical usage pattern, a salted hash with 10 rounds:
   *
   * <pre>
       // data is a byte array containing raw data to digest
       final byte[] salt = new RBGNonce(16).generate();
       final byte[] hash = HashUtil.hash(new SHA1Digest(), 10, data, salt);
   * </pre>
   *
   * @param  digest  Hash algorithm.
   * @param  iterations  Number of hash rounds. Must be positive value.
   * @param  data  Data to hash. Supported types are <code>byte[]</code>, {@link CharSequence} ,{@link InputStream}, and
   *               {@link Resource}. Character data is processed in the <code>UTF-8</code> character set; if another
   *               character set is desired, the caller should convert to <code>byte[]</code> and provide the resulting
   *               bytes.
   *
   * @return  Byte array of length {@link Digest#getDigestSize()} containing hash output.
   */
  public static byte[] hash(final Digest digest, final int iterations, final Object... data)
  {
    if (iterations < 1) {
      throw new IllegalArgumentException("Iterations must be positive");
    }

    final byte[] output = hash(digest, data);
    for (int i = 1; i < iterations; i++) {
      digest.update(output, 0, output.length);
      digest.doFinal(output, 0);
    }
    return output;
  }


  /**
   * Determines whether the hash of the given input equals a known value.
   *
   * @param  digest  Hash algorithm.
   * @param  hash  Hash to compare with. If the length of the array is greater than the length of the digest output,
   *               anything beyond the digest length is considered salt data that is hashed <strong>after</strong> the
   *               input data.
   * @param  iterations  Number of hash rounds.
   * @param  data  Data to hash.
   *
   * @return  True if the hash of the data under the given digest is equal to the hash, false otherwise.
   */
  public static boolean compareHash(final Digest digest, final byte[] hash, final int iterations, final Object... data)
  {
    if (hash.length > digest.getDigestSize()) {
      final byte[] hashPart = Arrays.copyOfRange(hash, 0, digest.getDigestSize());
      final byte[] saltPart = Arrays.copyOfRange(hash, digest.getDigestSize(), hash.length);
      final Object[] dataWithSalt = Arrays.copyOf(data, data.length + 1);
      dataWithSalt[data.length] = saltPart;
      return Arrays.equals(hash(digest, iterations, dataWithSalt), hashPart);
    }
    return Arrays.equals(hash(digest, iterations, data), hash);
  }


  /**
   * Determines whether the salted hash of the given input equals a known hash value.
   *
   * @param  digest  Hash algorithm.
   * @param  hash  Salted hash data.
   * @param  iterations  Number of hash rounds.
   * @param  saltAfterData  True to apply salt after data, false to apply salt before data.
   * @param  data  Data to hash, which should NOT include the salt value.
   *
   * @return  True if the hash of the data under the given digest is equal to the hash, false otherwise.
   */
  public static boolean compareHash(
    final Digest digest,
    final SaltedHash hash,
    final int iterations,
    final boolean saltAfterData,
    final Object... data)
  {
    final Object[] dataWithSalt;
    if (saltAfterData) {
      dataWithSalt = Arrays.copyOf(data, data.length + 1);
      dataWithSalt[data.length] = hash.getSalt();
    } else {
      dataWithSalt = new Object[data.length + 1];
      dataWithSalt[0] = hash.getSalt();
      System.arraycopy(data, 0, dataWithSalt, 1, data.length);
    }
    return Arrays.equals(hash(digest, iterations, dataWithSalt), hash.getHash());
  }


  /**
   * Produces the SHA-1 hash of the given data.
   *
   * @param  data  Data to hash. See {@link #hash(Digest, Object...)} for supported inputs.
   *
   * @return  20-byte array containing hash output.
   *
   * @see  #hash(Digest, Object...)
   */
  public static byte[] sha1(final Object... data)
  {
    return hash(new SHA1Digest(), data);
  }


  /**
   * Produces the SHA-256 hash of the given data.
   *
   * @param  data  Data to hash. See {@link #hash(Digest, Object...)} for supported inputs.
   *
   * @return  32-byte array containing hash output.
   *
   * @see  #hash(Digest, Object...)
   */
  public static byte[] sha256(final Object... data)
  {
    return hash(new SHA256Digest(), data);
  }


  /**
   * Produces the SHA-512 hash of the given data.
   *
   * @param  data  Data to hash. See {@link #hash(Digest, Object...)} for supported inputs.
   *
   * @return  64-byte array containing hash output.
   *
   * @see  #hash(Digest, Object...)
   */
  public static byte[] sha512(final Object... data)
  {
    return hash(new SHA512Digest(), data);
  }


  /**
   * Produces the SHA-3 hash of the given data.
   *
   * @param  bitLength  One of the supported SHA-3 output bit lengths: 224, 256, 384, or 512.
   * @param  data  Data to hash. See {@link #hash(Digest, Object...)} for supported inputs.
   *
   * @return  Byte array of size <code>bitLength</code> containing hash output.
   *
   * @see  #hash(Digest, Object...)
   */
  public static byte[] sha3(final int bitLength, final Object... data)
  {
    return hash(new SHA3Digest(bitLength), data);
  }


  /**
   * Digests the data in the given stream. Note this method does not finalize the digest process by calling {@link
   * Digest#doFinal(byte[], int)}.
   *
   * @param  digest  Digest algorithm.
   * @param  in  Input stream containing data to hash.
   */
  private static void hashStream(final Digest digest, final InputStream in)
  {
    final byte[] buffer = new byte[StreamUtil.CHUNK_SIZE];
    int length;
    try {
      while ((length = in.read(buffer)) > 0) {
        digest.update(buffer, 0, length);
      }
    } catch (IOException e) {
      throw new RuntimeException("Error reading stream", e);
    }
  }
}
