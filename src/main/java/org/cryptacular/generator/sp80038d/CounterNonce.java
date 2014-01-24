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

package org.cryptacular.generator.sp80038d;

import java.util.concurrent.atomic.AtomicLong;

import org.cryptacular.generator.LimitException;
import org.cryptacular.generator.Nonce;
import org.cryptacular.util.ByteUtil;

/**
 * Deterministic nonce generation strategy that uses a counter for the invocation field as described in NIST
 * <a href="http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf">SP-800-38D</a>, section 8.2.1.
 * The invocation part of the sequence is always 64 bits (8 bytes) due to the use of a <code>long</code>, thus the
 * length of the nonce is determined by the length of the fixed part: <code>length = 8 + fixed.length</code>.
 * <p>
 * <strong>NOTE:</strong> users of this class are responsible for maintaining the invocation count in order to support
 * enforcement of constraints described in section 8.3; namely the following:
 * <blockquote>
 * The total number of invocations of the authenticated encryption function shall not exceed 2<sup>32</sup>,
 * including all IV lengths and all instances of the authenticated encryption function with the given key.
 * </blockquote>
 * Instances of this class enforce this constraint by considering the nonce length, which determines whether the
 * constraint applies, and the invocation count. The invocation count is incremented upon every invocation
 * of {@link #generate()} method. The current invocation count is accessible via {@link #getInvocations()}.
 * </p>
 * <p>
 * Instances of this class are thread safe.
 *
 * @author Marvin S. Addison
 */
public class CounterNonce implements Nonce
{
  /** Default nonce getLength is {@value} bytes. */
  public static final int DEFAULT_LENGTH = 12;

  /**
   * Maximum invocations is 2<sup>32</sup>.
   * Does not apply to nonces with default getLength, {@value #DEFAULT_LENGTH}.
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
   * @param  invocations  Initial invocation count.
   *                      The invocations field is incremented _before_ use in {@link #generate()}.
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
   * @param  invocations  Initial invocation count.
   *                      The invocations field is incremented _before_ use in {@link #generate()}.
   */
  public CounterNonce(final int fixed, final long invocations)
  {
    this(ByteUtil.toBytes(fixed), invocations);
  }


  /**
   * Creates a new instance.
   *
   * @param  fixed  User-defined fixed field value.
   * @param  invocations  Initial invocation count.
   *                      The invocations field is incremented _before_ use in {@link #generate()}.
   */
  public CounterNonce(final long fixed, final long invocations)
  {
    this(ByteUtil.toBytes(fixed), invocations);
  }


  /**
   * Creates a new instance.
   *
   * @param  fixed  User-defined fixed field value.
   * @param  invocations  Initial invocation count.
   *                      The invocations field is incremented _before_ use in {@link #generate()}.
   */
  public CounterNonce(final byte[] fixed, final long invocations)
  {
    if (fixed == null || fixed.length == 0) {
      throw new IllegalArgumentException("Fixed part cannot be null or empty.");
    }
    this.count = new AtomicLong(invocations);
    this.fixed = fixed;
  }


  /** {@inheritDoc} */
  @Override
  public byte[] generate() throws LimitException
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


  /** {@inheritDoc} */
  @Override
  public int getLength()
  {
    return fixed.length + 8;
  }


  /**
   * @return  Current invocation count.
   */
  public long getInvocations()
  {
    return count.get();
  }
}
