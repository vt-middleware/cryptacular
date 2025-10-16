/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator.sp80038a;

import java.math.BigInteger;
import java.util.Arrays;
import org.cryptacular.CryptUtil;
import org.cryptacular.generator.LimitException;
import org.cryptacular.generator.Nonce;

/**
 * Uses a {@link BigInteger} to back a counter in order to produce nonces of arbitrary length.
 *
 * <p>A common use case for this component is creation of IVs for ciphers with 16-byte block size, e.g. AES.</p>
 *
 * <p>Instances of this class are thread safe.</p>
 *
 * @author  Middleware Services
 */
public class BigIntegerCounterNonce implements Nonce
{

  /** Maximum length of nonce to generate. */
  private static final int MAX_NONCE_LENGTH = 10240;

  /** Counter. */
  private BigInteger counter;

  /** Length of generated counter nonce values in bytes. */
  private final int length;


  /**
   * Creates a new instance with given parameters.
   *
   * @param  counter  Initial counter value.
   * @param  length  Maximum length of generated counter values in bytes.
   */
  public BigIntegerCounterNonce(final BigInteger counter, final int length)
  {
    if (length < 1 || length > MAX_NONCE_LENGTH) {
      throw new IllegalArgumentException("Length must be positive and less than " + MAX_NONCE_LENGTH);
    }
    this.length = length;
    this.counter = CryptUtil.assertNotNullArg(counter, "Counter cannot be null");
  }


  @Override
  public byte[] generate()
    throws LimitException
  {
    final byte[] value;
    synchronized (this) {
      counter = counter.add(BigInteger.ONE);
      value = counter.toByteArray();
    }
    if (value.length > length) {
      throw new LimitException("Counter value exceeded max byte length " + length);
    }
    if (value.length < length) {
      final byte[] temp = new byte[length];
      Arrays.fill(temp, (byte) 0);
      System.arraycopy(value, 0, temp, temp.length - value.length, value.length);
      return temp;
    }
    return value;
  }


  @Override
  public int getLength()
  {
    return length;
  }
}
