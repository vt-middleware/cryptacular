/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator.sp80038a;

import java.util.concurrent.atomic.AtomicLong;
import org.cryptacular.generator.LimitException;
import org.cryptacular.generator.Nonce;
import org.cryptacular.util.ByteUtil;

/**
 * Simple counter nonce that uses a long integer counter internally and produces
 * 8-byte nonces. Note that this component is suitable exclusively for ciphers
 * with block length 8, e.g. Blowfish.
 *
 * <p>Instances of this class are thread safe.</p>
 *
 * @author  Middleware Services
 * @see  BigIntegerCounterNonce
 */
public class LongCounterNonce implements Nonce
{

  /** Counter. */
  private final AtomicLong counter;


  /** Creates a new instance whose counter values start at 1. */
  public LongCounterNonce()
  {
    this(0);
  }


  /**
   * Creates a new instance whose counter values start above the given value.
   *
   * @param  start  Start value.
   */
  public LongCounterNonce(final long start)
  {
    counter = new AtomicLong(start);
  }


  @Override
  public byte[] generate()
    throws LimitException
  {
    return ByteUtil.toBytes(counter.incrementAndGet());
  }


  @Override
  public int getLength()
  {
    return 8;
  }
}
