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

package org.cryptacular.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * Describes a potentially stateful byte-to-character encoder.
 *
 * @author Marvin S. Addison
 */
public interface Encoder
{
  /**
   * Encodes bytes in input buffer into characters placed in the output buffer.
   * This method may be called multiple times, followed by {@link #finalize(java.nio.CharBuffer)}
   * after all input bytes have been provided.
   *
   * @param  input  Input byte buffer.
   * @param  output  Output character buffer.
   */
  void encode(ByteBuffer input, CharBuffer output);


  /**
   * Performs final output encoding (e.g. padding) after all input bytes have been provided.
   *
   * @param  output  Output character buffer.
   */
  void finalize(CharBuffer output);


  /**
   * Expected number of characters in the output buffer for an input buffer of the given size.
   *
   * @param  inputSize  Size of input buffer in bytes.
   *
   * @return  Minimum character buffer size required to store all encoded input bytes.
   */
  int outputSize(int inputSize);
}
