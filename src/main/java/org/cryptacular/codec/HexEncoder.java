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
 * Stateless hexadecimal byte-to-character encoder.
 *
 * @author Marvin S. Addison
 */
public class HexEncoder implements Encoder
{
  /** Hex character encoding table. */
  private static final char[] ENCODING_TABLE = new char[16];

  /** Flag indicating whether to delimit every two characters with ':' as in key fingerprints, etc. */
  private final boolean delimit;


  /** Creates a new instance that does not delimit bytes in the output hex string. */
  public HexEncoder()
  {
    this(false);
  }

  /**
   * Creates a new instance with optional delimiting of bytes in the output hex string.
   *
   * @param  delimitBytes  True to delimit every two characters (i.e. every byte) with ':' character.
   */
  public HexEncoder(final boolean delimitBytes)
  {
    delimit = delimitBytes;
  }


  /** Initializes the encoding character table. */
  static
  {
    final String charset = "0123456789abcdef";
    for (int i = 0; i < charset.length(); i++) {
      ENCODING_TABLE[i] = charset.charAt(i);
    }
  }


  /** {@inheritDoc} */
  @Override
  public void encode(final ByteBuffer input, final CharBuffer output)
  {
    byte current;
    while (input.hasRemaining()) {
      current = input.get();
      output.put(ENCODING_TABLE[(current & 0xf0) >> 4]);
      output.put(ENCODING_TABLE[current & 0x0f]);
      if (delimit && input.hasRemaining()) {
        output.put(':');
      }
    }
  }


  /** {@inheritDoc} */
  @Override
  public void finalize(final CharBuffer output) {}


  /** {@inheritDoc} */
  @Override
  public int outputSize(final int inputSize)
  {
    int size = inputSize * 2;
    if (delimit) {
      size += inputSize - 1;
    }
    return size;
  }
}
