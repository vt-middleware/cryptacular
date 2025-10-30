/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import org.cryptacular.CryptUtil;
import org.cryptacular.StreamException;

/**
 * Utilities for working with bytes.
 *
 * @author  Middleware Services
 */
public final class ByteUtil
{

  /** Default character set for bytes is UTF-8. */
  public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

  /** ASCII character set. */
  public static final Charset ASCII_CHARSET = StandardCharsets.US_ASCII;

  /** Private constructor of utility class. */
  private ByteUtil() {}


  /**
   * Converts the big-endian representation of a 32-bit integer to the equivalent integer value.
   *
   * @param  data  4-byte array in big-endian format.
   *
   * @return  Integer value.
   */
  public static int toInt(final byte[] data)
  {
    CryptUtil.assertNotNullArgOr(data, v -> v.length != 4, "Data must have a length of 4");
    return (data[0] << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);
  }


  /**
   * Converts an unsigned byte into an integer.
   *
   * @param  unsigned  Unsigned byte.
   *
   * @return  Integer value.
   */
  public static int toInt(final byte unsigned)
  {
    return 0x000000FF & unsigned;
  }


  /**
   * Reads 4-bytes from the input stream and converts to a 32-bit integer.
   *
   * @param  in  Stream from which to read 4 bytes.
   *
   * @return  Integer value.
   *
   * @throws  StreamException  on stream IO errors.
   */
  public static int readInt(final InputStream in) throws StreamException
  {
    CryptUtil.assertNotNullArg(in, "Input stream cannot be null");
    try {
      return (in.read() << 24) | ((in.read() & 0xff) << 16) | ((in.read() & 0xff) << 8) | (in.read() & 0xff);
    } catch (IOException e) {
      throw new StreamException(e);
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
    CryptUtil.assertNotNullArgOr(data, v -> v.length != 8, "Data must have a length of 8");
    return
      ((long) data[0] << 56) | (((long) data[1] & 0xff) << 48) |
      (((long) data[2] & 0xff) << 40) | (((long) data[3] & 0xff) << 32) |
      (((long) data[4] & 0xff) << 24) | (((long) data[5] & 0xff) << 16) |
      (((long) data[6] & 0xff) << 8) | ((long) data[7] & 0xff);
  }


  /**
   * Reads 8-bytes from the input stream and converts to a 64-bit long integer.
   *
   * @param  in  Stream from which to read 8 bytes.
   *
   * @return  Long integer value.
   *
   * @throws  StreamException  on stream IO errors.
   */
  public static long readLong(final InputStream in) throws StreamException
  {
    CryptUtil.assertNotNullArg(in, "Input stream cannot be null");
    try {
      return
        ((long) in.read() << 56) | (((long) in.read() & 0xff) << 48) |
        (((long) in.read() & 0xff) << 40) | (((long) in.read() & 0xff) << 32) |
        (((long) in.read() & 0xff) << 24) | (((long) in.read() & 0xff) << 16) |
        (((long) in.read() & 0xff) << 8) | ((long) in.read() & 0xff);
    } catch (IOException e) {
      throw new StreamException(e);
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
    if (offset < 0) {
      throw new IllegalArgumentException("Offset cannot be negative");
    }
    CryptUtil.assertNotNullArgOr(
      output, v -> v.length < offset + 4 || offset + 4 < 0, "Output length must support offset");
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
   * Converts an integer into an 8-byte big endian array.
   *
   * @param  value  Long value to convert.
   * @param  output  Array into which bytes are placed.
   * @param  offset  Offset into output array at which output bytes start.
   */
  public static void toBytes(final long value, final byte[] output, final int offset)
  {
    if (offset < 0) {
      throw new IllegalArgumentException("Offset cannot be negative");
    }
    CryptUtil.assertNotNullArgOr(
      output, v -> v.length < offset + 8 || offset + 8 < 0, "Output length must support offset");
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
    return new String(CryptUtil.assertNotNullArg(bytes, "Bytes cannot be null"), DEFAULT_CHARSET);
  }


  /**
   * Converts a portion of a byte array into a string in the UTF-8 character set.
   *
   * @param  bytes  Byte array to convert.
   * @param  offset  Offset into byte array where string content begins.
   * @param  length  Total number of bytes to convert.
   *
   * @return  UTF-8 string representation of bytes.
   */
  public static String toString(final byte[] bytes, final int offset, final int length)
  {
    try {
      return new String(CryptUtil.assertNotNullArg(bytes, "Bytes cannot be null"), offset, length, DEFAULT_CHARSET);
    } catch (StringIndexOutOfBoundsException e) {
      throw new IllegalArgumentException(e);
    }
  }


  /**
   * Converts a byte buffer into a string in the UTF-8 character set.
   *
   * @param  buffer  Byte buffer to convert.
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
   * @param  buffer  Byte buffer to convert.
   *
   * @return  Character buffer containing UTF-8 string representation of bytes.
   */
  public static CharBuffer toCharBuffer(final ByteBuffer buffer)
  {
    return DEFAULT_CHARSET.decode(CryptUtil.assertNotNullArg(buffer, "Buffer cannot be null"));
  }


  /**
   * Converts a character sequence into bytes in the UTF-8 character set.
   *
   * @param  cs  CharSequence to convert.
   *
   * @return  Byte buffer containing byte representation of the character sequence.
   */
  public static ByteBuffer toByteBuffer(final CharSequence cs)
  {
    return DEFAULT_CHARSET.encode(
      CharBuffer.wrap(CryptUtil.assertNotNullArg(cs, "Character sequence cannot be null")));
  }


  /**
   * Converts a character sequence into bytes in the UTF-8 character set.
   *
   * @param  cs  Character sequence to convert.
   *
   * @return  Byte array containing byte representation of the character sequence.
   */
  public static byte[] toBytes(final CharSequence cs)
  {
    final ByteBuffer buffer = toByteBuffer(cs);
    final byte[] bytes = new byte[buffer.remaining()];
    buffer.get(bytes);
    return bytes;
  }


  /**
   * Converts an integer into an unsigned byte. All bits above 1 byte are truncated.
   *
   * @param  b  Integer value.
   *
   * @return  Unsigned byte as a byte.
   */
  public static byte toUnsignedByte(final int b)
  {
    return (byte) (0x000000FF & b);
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
    CryptUtil.assertNotNullArg(buffer, "Buffer cannot be null");
    final int size = buffer.limit() - buffer.position();
    if (buffer.hasArray() && size == buffer.capacity()) {
      return buffer.array();
    }
    final byte[] array = new byte[size];
    buffer.get(array);
    return array;
  }
}
