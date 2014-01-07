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

package org.cryptacular.generator.sp80038a;

import java.util.concurrent.atomic.AtomicLong;

import org.cryptacular.generator.LimitException;
import org.cryptacular.generator.Nonce;
import org.cryptacular.util.ByteUtil;

/**
 * Simple counter nonce that uses a long integer counter internally and produces 8-byte nonces. Note that this
 * component is suitable exclusively for ciphers with block length 8, e.g. Blowfish.
 * <p>
 * Instances of this class are thread safe.
 *
 * @author  Marvin S. Addison
 * @see  BigIntegerCounterNonce
 */
public class LongCounterNonce implements Nonce
{
  /** Counter. */
  private final AtomicLong counter;


  /**
   * Creates a new instance whose counter values start at 1.
   */
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


  /** {@inheritDoc} */
  @Override
  public byte[] generate() throws LimitException
  {
    return ByteUtil.toBytes(counter.incrementAndGet());
  }


  /** {@inheritDoc} */
  @Override
  public int getLength()
  {
    return 8;
  }
}
