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

package org.cryptacular.generator;

import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
import org.cryptacular.util.NonceUtil;

/**
 * Generates random identifiers with an alphanumeric character set by default.
 *
 * @author Marvin S. Addison
 */
public class RandomIdGenerator implements IdGenerator
{
  /** Default character set. */
  public static final String DEFAULT_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  /** Size of generated identifiers. */
  private final int length;

  /** Identifier character set. */
  private final String charset;

  /** Random bit generator. */
  private final SP80090DRBG rbg;


  /**
   * Creates a new instance with the default character set.
   *
   * @param  length  Number of characters in generated identifiers.
   */
  public RandomIdGenerator(final int length)
  {
    this(length, DEFAULT_CHARSET);
  }


  /**
   * Creates a new instance with a defined character set.
   *
   * @param  length  Number of characters in generated identifiers.
   * @param  charset  Character set.
   */
  public RandomIdGenerator(final int length, final String charset)
  {
    if (length < 1) {
      throw new IllegalArgumentException("Length must be positive");
    }
    this.length = length;
    if (charset == null || charset.length() < 2 || charset.length() > 128) {
      throw new IllegalArgumentException("Charset length must be in the range 2 - 128");
    }
    this.charset = charset;
    this.rbg = NonceUtil.newRBG(8);
  }


  /** {@inheritDoc} */
  @Override
  public String generate()
  {
    final StringBuilder id = new StringBuilder(length);
    final byte[] bits = new byte[1];
    int index;
    for (int i = 0; i < length; i++) {
      rbg.generate(bits, null, false);
      index = 0x7F & bits[0];
      id.append(charset.charAt(index % charset.length()));
    }
    return id.toString();
  }
}
