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

package org.cryptosis.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * Stateful base64 encoder with support for configurable line breaks.
 *
 * @author Marvin S. Addison
 */
public class Base64Encoder implements Encoder
{
  /** Base64 character encoding table. */
  private static final char[] ENCODING_TABLE = new char[64];

  /** Platform-specific line terminator string, e.g. LF (Unix), CRLF (Windows). */
  private static final String NEWLINE;

  /** Number of base64 characters per line. */
  private final int lineLength;

  /** Holds a block of bytes to encode. */
  private int block;

  /** Number of bits in encode block remaining. */
  private int remaining = 24;

  /** Number of characters written. */
  private int outCount;


  /** Initializes the encoding character table. */
  static
  {
    NEWLINE = System.lineSeparator();
    final String charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < charset.length(); i++) {
      ENCODING_TABLE[i] = charset.charAt(i);
    }
  }


  /**
   * Creates a new instance that produces base64-encoded output.
   */
  public Base64Encoder()
  {
    // Default to no line breaks.
    this(-1);
  }


  /**
   * Creates a new instance that produces base64-encoded output with the given number of characters per line.
   *
   * @param  charactersPerLine  Number of characters per line. A zero or negative value disables line breaks.
   */
  public Base64Encoder(final int charactersPerLine)
  {
    this.lineLength = charactersPerLine;
  }


  /** {@inheritDoc} */
  @Override
  public void encode(final ByteBuffer input, final CharBuffer output)
  {
    while (input.hasRemaining()) {
      remaining -= 8;
      block |= (input.get() & 0xff) << remaining;
      if (remaining == 0) {
        writeOutput(output, 0);
      }
    }
  }


  /** {@inheritDoc} */
  @Override
  public void finalize(final CharBuffer output)
  {
    if (remaining == 16) {
      writeOutput(output, 12);
      output.put('=').put('=');
    } else if (remaining == 8) {
      writeOutput(output, 6);
      output.put('=');
    }
    // Append trailing newline to make consistent with OpenSSL base64 output
    if (lineLength > 0 && output.position() > 0) {
      output.append(NEWLINE);
    }
    outCount = 0;
  }


  /** {@inheritDoc} */
  @Override
  public int outputSize(final int inputSize)
  {
    int len = (inputSize + 2) * 4 / 3;
    if (lineLength > 0) {
      len += (len / lineLength + 1) * NEWLINE.length();
    }
    return len;
  }


  /**
   * Writes bytes in the current encoding block to the output buffer.
   *
   * @param  output  Output buffer.
   * @param  stop  Bit shift stop position where data in current encoding block ends.
   */
  private void writeOutput(final CharBuffer output, final int stop)
  {
    int mask = 0xfc0000;
    for (int shift = 18; shift >= stop; shift -= 6) {
      output.put(ENCODING_TABLE[(block & mask) >> shift]);
      outCount++;
      if (lineLength > 0 && outCount % lineLength == 0) {
        output.put(NEWLINE);
      }
      mask >>= 6;
    }
    block = 0;
    remaining = 24;
  }
}
