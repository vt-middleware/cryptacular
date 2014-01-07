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

package org.cryptacular.adapter;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Provides a consistent interface for cipher operations against dissimilar BC cipher types.
 *
 * @author Marvin S. Addison
 */
public interface CipherAdapter
{
  /**
   * Initialize the underlying cipher.
   *
   * @param  forEncryption  True for encryption mode, false for decryption mode.
   * @param  params  Cipher initialization parameters.
   */
  void init(boolean forEncryption, CipherParameters params);


  /**
   * Process an array of bytes, producing output if necessary.
   *
   * @param  in  Input data.
   * @param  inOff Offset at which the input data starts.
   * @param  len  The number of bytes in the input data to process.
   * @param  out  Array to receive any data produced by cipher.
   * @param  outOff  Offset into output array.
   *
   * @return  The number of bytes produced by the cipher.
   */
  int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff);


  /**
   * Reset the cipher. After resetting the cipher is in the same state
   * as it was after the last init (if there was one).
   */
  void reset();
}
