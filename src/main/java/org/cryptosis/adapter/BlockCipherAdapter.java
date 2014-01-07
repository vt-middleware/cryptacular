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

package org.cryptosis.adapter;

/**
 * Adapter for all block cipher types.
 *
 * @author Marvin S. Addison
 */
public interface BlockCipherAdapter extends CipherAdapter
{
  /**
   * Gets the size of the output buffer required to hold the output of an input buffer of the given size.
   *
   * @param  len  Length of input buffer.
   *
   * @return  Size of output buffer.
   */
  int getOutputSize(int len);


  /**
   * Finish the encryption/decryption operation (e.g. apply padding).
   *
   * @param  out  Output buffer to receive final processing output.
   * @param  outOff  Offset into output buffer where processed data should start.
   *
   * @return  Number of bytes written to output buffer.
   */
  int doFinal(byte[] out, int outOff);
}
