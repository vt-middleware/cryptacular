/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator.sp80038d;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
import org.cryptacular.generator.LimitException;
import org.cryptacular.generator.Nonce;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.NonceUtil;

/**
 * RBG-based nonce generation strategy that uses a RBG component to produce values for the invocation field as described
 * in NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf">SP-800-38D</a>, section 8.2.2.
 *
 * <p><strong>NOTE:</strong> users of this class are responsible for counting number of invocations and enforcing the
 * constraints described in section 8.3; namely the following:</p>
 *
 * <blockquote>The total number of invocations of the authenticated encryption function shall not exceed 2<sup>32</sup>,
 * including all IV lengths and all instances of the authenticated encryption function with the given key.</blockquote>
 *
 * <p>Instances of this class are thread safe.</p>
 *
 * @author  Middleware Services
 */
public class RBGNonce implements Nonce
{

  /** Fixed field value. */
  private final byte[] fixed;

  /** Number of bytes of random data in invocation field. */
  private final int randomLength;

  /** Random bit generator. */
  private final SP80090DRBG rbg;


  /**
   * Creates a new instance that produces 12-bytes (96-bits) of random data; that is, the fixed field of the nonce is
   * null.
   */
  public RBGNonce()
  {
    this(12);
  }


  /**
   * Creates a new instance that produces length bytes of random data; that is, the fixed field of the nonce is null.
   *
   * @param  randomLength  Number of bytes in the random part of the nonce. MUST be at least 12.
   */
  public RBGNonce(final int randomLength)
  {
    this(null, randomLength);
  }


  /**
   * Creates a new instance using the given fixed field value.
   *
   * @param  fixed  User-defined fixed field value.
   * @param  randomLength  Number of bytes in the random part of the nonce. MUST be at least 12.
   */
  public RBGNonce(final String fixed, final int randomLength)
  {
    if (randomLength < 12) {
      throw new IllegalArgumentException("Must specify at least 12 bytes (96 bits) for random part.");
    }
    this.randomLength = randomLength;
    if (fixed != null) {
      this.fixed = ByteUtil.toBytes(fixed);
    } else {
      this.fixed = new byte[0];
    }
    this.rbg = newRBG(this.randomLength, this.fixed);
  }


  @Override
  public byte[] generate()
    throws LimitException
  {
    final byte[] random = new byte[randomLength];
    synchronized (rbg) {
      rbg.generate(random, null, false);
    }

    final byte[] value = new byte[getLength()];
    System.arraycopy(fixed, 0, value, 0, fixed.length);
    System.arraycopy(random, 0, value, fixed.length, random.length);
    return value;
  }


  @Override
  public int getLength()
  {
    return fixed.length + randomLength;
  }


  /**
   * Creates a new DRBG instance.
   *
   * @param  length  Length in bits of values produced by DRBG.
   * @param  domain  Domain qualifier.
   *
   * @return  New DRBG instance.
   */
  private static SP80090DRBG newRBG(final int length, final byte[] domain)
  {
    return
      new HashSP800DRBG(
        new SHA256Digest(),
        length,
        new EntropySource() {
          @Override
          public boolean isPredictionResistant()
          {
            return false;
          }

          @Override
          public byte[] getEntropy()
          {
            return NonceUtil.timestampNonce(length);
          }

          @Override
          public int entropySize()
          {
            return length;
          }
        },
        domain,
        NonceUtil.timestampNonce(8));
  }
}
