/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator.sp80038d;

import java.util.concurrent.atomic.AtomicLong;
import org.cryptacular.CryptUtil;
import org.cryptacular.generator.LimitException;
import org.cryptacular.generator.Nonce;
import org.cryptacular.util.ByteUtil;

/**
 * Deterministic nonce generation strategy that uses a counter for the invocation field as described in NIST <a
 * href="http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf">SP-800-38D</a>, section 8.2.1. The
 * invocation part of the sequence is always 64 bits (8 bytes) due to the use of a <code>long</code>, thus the length of
 * the nonce is determined by the length of the fixed part: <code>length = 8 + fixed.length</code>.
 *
 * <p><strong>NOTE:</strong> users of this class are responsible for maintaining the invocation count in order to
 * support enforcement of constraints described in section 8.3; namely the following:</p>
 *
 * <blockquote>The total number of invocations of the authenticated encryption function shall not exceed 2<sup>32</sup>,
 * including all IV lengths and all instances of the authenticated encryption function with the given key.</blockquote>
 *
 * <p>Instances of this class enforce this constraint by considering the nonce length, which determines whether the
 * constraint applies, and the invocation count. The invocation count is incremented upon every invocation of {@link
 * #generate()} method. The current invocation count is accessible via {@link #getInvocations()}.</p>
 *
 * <p>Instances of this class are thread safe.</p>
 *
 * @author  Middleware Services
 */
public class CounterNonce implements Nonce
{

  /** Default nonce getLength is {@value} bytes. */
  public static final int DEFAULT_LENGTH = 12;

  /**
   * Maximum invocations is 2<sup>32</sup>. Does not apply to nonces with default getLength, {@value #DEFAULT_LENGTH}.
   */
  public static final long MAX_INVOCATIONS = 0xFFFFFFFFL;

  /** Fixed field value. */
  private final byte[] fixed;

  /** Invocation count. */
  private final AtomicLong count;


  /**
   * Creates a new instance.
   *
   * @param  fixed  User-defined fixed field value.
   * @param  invocations  Initial invocation count. The invocations field is incremented _before_ use in {@link
   *                      #generate()}.
   */
  public CounterNonce(final String fixed, final long invocations)
  {
    this(ByteUtil.toBytes(fixed), invocations);
  }


  /**
   * Creates a new instance. Instances of this method produces nonces of the default length, {@value #DEFAULT_LENGTH},
   * and are not subject to constraints on the number of invocations.
   *
   * @param  fixed  User-defined fixed field value.
   * @param  invocations  Initial invocation count. The invocations field is incremented _before_ use in {@link
   *                      #generate()}.
   */
  public CounterNonce(final int fixed, final long invocations)
  {
    this(ByteUtil.toBytes(fixed), invocations);
  }


  /**
   * Creates a new instance.
   *
   * @param  fixed  User-defined fixed field value.
   * @param  invocations  Initial invocation count. The invocations field is incremented _before_ use in {@link
   *                      #generate()}.
   */
  public CounterNonce(final long fixed, final long invocations)
  {
    this(ByteUtil.toBytes(fixed), invocations);
  }


  /**
   * Creates a new instance.
   *
   * @param  fixed  User-defined fixed field value.
   * @param  invocations  Initial invocation count. The invocations field is incremented _before_ use in {@link
   *                      #generate()}.
   */
  public CounterNonce(final byte[] fixed, final long invocations)
  {
    this.fixed = CryptUtil.assertNotNullArgOr(fixed, v -> v.length == 0, "Fixed part cannot be null or empty.");
    this.count = new AtomicLong(invocations);
  }


  @Override
  public byte[] generate()
    throws LimitException
  {
    final byte[] value = new byte[getLength()];
    System.arraycopy(fixed, 0, value, 0, fixed.length);

    final long next = count.incrementAndGet();
    if (value.length != DEFAULT_LENGTH) {
      // Enforce constraints described in section 8.3
      if (next > MAX_INVOCATIONS) {
        throw new LimitException("Exceeded 2^32 invocations.");
      }
    }
    ByteUtil.toBytes(next, value, fixed.length);
    return value;
  }


  @Override
  public int getLength()
  {
    return fixed.length + 8;
  }


  /** @return  Current invocation count. */
  public long getInvocations()
  {
    return count.get();
  }
}
