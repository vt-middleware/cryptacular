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
