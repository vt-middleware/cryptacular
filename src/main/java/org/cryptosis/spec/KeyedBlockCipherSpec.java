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

package org.cryptosis.spec;

/**
 * Describes a block cipher algorithm with a known key size.
 *
 * @author Marvin S. Addison
 */
public class KeyedBlockCipherSpec extends BufferedBlockCipherSpec
{
  /** Key length in bits. */
  private final int keyLength;


  /**
   * Creates a new instance from the given cipher specifications.
   *
   * @param  algName  Cipher algorithm name.
   * @param  cipherMode  Cipher mode.
   * @param  cipherPadding  Cipher padding scheme algorithm.
   * @param  keyBitLength  Key length in bits.
   */
  public KeyedBlockCipherSpec(
      final String algName, final String cipherMode, final String cipherPadding, final int keyBitLength)
  {
    super(algName, cipherMode, cipherPadding);
    if (keyBitLength < 0) {
      throw new IllegalArgumentException("Key length must be non-negative");
    }
    this.keyLength = keyBitLength;
  }


  /**
   * Gets the cipher key length in bits.
   *
   * @return  Key length in bits.
   */
  public int getKeyLength()
  {
    return keyLength;
  }
}
