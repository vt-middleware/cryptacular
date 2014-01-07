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

package org.cryptacular.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;

/**
 * Utilities for working with bytes.
 *
 * @author Marvin S. Addison
 */
public final class ByteUtil
{
  /** Default character set for bytes is UTF-8. */
  public static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

  /** ASCII charactr set. */
  public static final Charset ASCII_CHARSET = Charset.forName("ASCII");

  /** Private constructor of utilty class. */
  private ByteUtil() {}


  /**
   * Converts the big-endian representation of a 32-bit integer to the equivalent integer value.
   *
   * @param  data  4-byte array in big-endian format.
   *
   * @return  Long integer value.
   */
  public static int toInt(final byte[] data)
  {
    return
       (data[0] << 24) |
      ((data[1] & 0xff) << 16) |
      ((data[2] & 0xff) <<  8) |
       (data[3] & 0xff);
  }


  /**
   * Reads 4-bytes from the input stream and converts to a 32-bit integer.
   *
   * @param  in  Stream from which to read 4 bytes.
   *
   * @return  Integer value.
   */
  public static int readInt(final InputStream in)
  {
    try {
      return
         (in.read() << 24) |
        ((in.read() & 0xff) << 16) |
        ((in.read() & 0xff) <<  8) |
         (in.read() & 0xff);
    } catch (IOException e) {
      throw new RuntimeException("Error reading from stream.", e);
    }
  }


  /**
   * Converts the big-endian representation of a 64-bit integer to the equivalent long value.
   *
   * @param  data  8-byte array in big-endian format.
   *
   * @return  Long integer value.
   */
  public static long toLong(final byte[] data)
  {
    return
       ((long) data[0] << 56) |
      (((long) data[1] & 0xff) << 48) |
      (((long) data[2] & 0xff) << 40) |
      (((long) data[3] & 0xff) << 32) |
      (((long) data[4] & 0xff) << 24) |
      (((long) data[5] & 0xff) << 16) |
      (((long) data[6] & 0xff) <<  8) |
       ((long) data[7] & 0xff);
  }


  /**
   * Reads 8-bytes from the input stream and converts to a 64-bit long integer.
   *
   * @param  in  Stream from which to read 8 bytes.
   *
   * @return  Long integer value.
   */
  public static long readLong(final InputStream in)
  {
    try {
      return
         ((long) in.read() << 56) |
        (((long) in.read() & 0xff) << 48) |
        (((long) in.read() & 0xff) << 40) |
        (((long) in.read() & 0xff) << 32) |
        (((long) in.read() & 0xff) << 24) |
        (((long) in.read() & 0xff) << 16) |
        (((long) in.read() & 0xff) <<  8) |
         ((long) in.read() & 0xff);
    } catch (IOException e) {
      throw new RuntimeException("Error reading from stream.", e);
    }
  }


  /**
   * Converts an integer into a 4-byte big endian array.
   *
   * @param  value  Integer value to convert.
   *
   * @return  4-byte big-endian representation of integer value.
   */
  public static byte[] toBytes(final int value)
  {
    final byte[] bytes = new byte[4];
    toBytes(value, bytes, 0);
    return bytes;
  }


  /**
   * Converts an integer into a 4-byte big endian array.
   *
   * @param  value  Integer value to convert.
   * @param  output  Array into which bytes are placed.
   * @param  offset  Offset into output array at which output bytes start.
   */
  public static void toBytes(final int value, final byte[] output, final int offset)
  {
    int shift = 24;
    for (int i = 0; i < 4; i++) {
      output[offset + i] = (byte) (value >> shift);
      shift -= 8;
    }
  }


  /**
   * Converts a long integer into an 8-byte big endian array.
   *
   * @param  value  Long integer value to convert.
   *
   * @return  8-byte big-endian representation of long integer value.
   */
  public static byte[] toBytes(final long value)
  {
    final byte[] bytes = new byte[8];
    toBytes(value, bytes, 0);
    return bytes;
  }


  /**
   * Converts an integer into a 8-byte big endian array.
   *
   * @param  value  Long value to convert.
   * @param  output  Array into which bytes are placed.
   * @param  offset  Offset into output array at which output bytes start.
   */
  public static void toBytes(final long value, final byte[] output, final int offset)
  {
    int shift = 56;
    for (int i = 0; i < 8; i++) {
      output[offset + i] = (byte) (value >> shift);
      shift -= 8;
    }
  }


  /**
   * Converts a byte array into a string in the UTF-8 character set.
   *
   * @param  bytes  Byte array to convert.
   *
   * @return  UTF-8 string representation of bytes.
   */
  public static String toString(final byte[] bytes)
  {
    return new String(bytes, DEFAULT_CHARSET);
  }


  /**
   * Converts a byte buffer into a string in the UTF-8 character set.
   *
   * @param  buffer Byte buffer to convert.
   *
   * @return  UTF-8 string representation of bytes.
   */
  public static String toString(final ByteBuffer buffer)
  {
    return toCharBuffer(buffer).toString();
  }

  /**
   * Converts a byte buffer into a character buffer.
   *
   * @param  buffer Byte buffer to convert.
   *
   * @return  Character buffer containing UTF-8 string representation of bytes.
   */
  public static CharBuffer toCharBuffer(final ByteBuffer buffer)
  {
    return DEFAULT_CHARSET.decode(buffer);
  }


  /**
   * Converts a string into bytes in the UTF-8 character set.
   *
   * @param  s  String to convert.
   *
   * @return  Byte buffer containing byte representation of string.
   */
  public static ByteBuffer toByteBuffer(final String s)
  {
    return DEFAULT_CHARSET.encode(CharBuffer.wrap(s));
  }


  /**
   * Converts a string into bytes in the UTF-8 character set.
   *
   * @param  s  String to convert.
   *
   * @return  Byte array containing byte representation of string.
   */
  public static byte[] toBytes(final String s)
  {
    return s.getBytes(DEFAULT_CHARSET);
  }


  /**
   * Converts a byte buffer into a byte array.
   *
   * @param  buffer  Byte buffer to convert.
   *
   * @return  Byte array corresponding to bytes of buffer from current position to limit.
   */
  public static byte[] toArray(final ByteBuffer buffer)
  {
    if (buffer.limit() == buffer.capacity()) {
      return buffer.array();
    }
    final byte[] array = new byte[buffer.limit()];
    buffer.position(0);
    buffer.get(array);
    return array;
  }
}
