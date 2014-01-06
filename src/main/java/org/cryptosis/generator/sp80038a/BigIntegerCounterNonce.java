package org.cryptosis.generator.sp80038a;

import java.math.BigInteger;
import java.util.Arrays;

import org.cryptosis.generator.LimitException;
import org.cryptosis.generator.Nonce;

/**
 * Uses a {@link BigInteger} to back a counter in order to produce nonces of arbitrary length.
 * <p>
 * A common use case for this component is creation of IVs for ciphers with 16-byte block size, e.g. AES.
 * <p>
 * Instances of this class are thread safe.
 *
 * @author Marvin S. Addison
 */
public class BigIntegerCounterNonce implements Nonce
{
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
    if (length < 1) {
      throw new IllegalArgumentException("Length must be positive");
    }
    this.length = length;
    this.counter = counter;
  }


  /** {@inheritDoc} */
  @Override
  public byte[] generate() throws LimitException
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


  /** {@inheritDoc} */
  @Override
  public int getLength()
  {
    return length;
  }
}
