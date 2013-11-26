package org.cryptosis;

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

  /** Private constructor of utilty class. */
  private ByteUtil() {}


  public static int toInt(final byte[] data)
  {
    return
       (data[0] << 24) |
      ((data[1] & 0xff) << 16) |
      ((data[2] & 0xff) <<  8) |
       (data[3] & 0xff);
  }

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


  public static long toLong(final byte[] data)
  {
    return
       ((long)data[0] << 56) |
      (((long)data[1] & 0xff) << 48) |
      (((long)data[2] & 0xff) << 40) |
      (((long)data[3] & 0xff) << 32) |
      (((long)data[4] & 0xff) << 24) |
      (((long)data[5] & 0xff) << 16) |
      (((long)data[6] & 0xff) <<  8) |
       ((long)data[7] & 0xff);
  }


  public static long readLong(final InputStream in)
  {
    try {
      return
         ((long)in.read() << 56) |
        (((long)in.read() & 0xff) << 48) |
        (((long)in.read() & 0xff) << 40) |
        (((long)in.read() & 0xff) << 32) |
        (((long)in.read() & 0xff) << 24) |
        (((long)in.read() & 0xff) << 16) |
        (((long)in.read() & 0xff) <<  8) |
         ((long)in.read() & 0xff);
    } catch (IOException e) {
      throw new RuntimeException("Error reading from stream.", e);
    }
  }


  public static void toBytes(final int value, final byte[] output, final int offset)
  {
    int shift = 24;
    for (int i = 0; i < 4; i++) {
      output[offset + i] = (byte)(value >> shift);
      shift -= 8;
    }
  }


  public static void toBytes(final long value, final byte[] output, final int offset)
  {
    int shift = 56;
    for (int i = 0; i < 8; i++) {
      output[offset + i] = (byte)(value >> shift);
      shift -= 8;
    }
  }


  public static String toString(final byte[] bytes)
  {
    return new String(bytes, DEFAULT_CHARSET);
  }


  public static String toString(final ByteBuffer buffer)
  {
    return toCharBuffer(buffer).toString();
  }


  public static CharBuffer toCharBuffer(final ByteBuffer buffer)
  {
    return DEFAULT_CHARSET.decode(buffer);
  }


  public static ByteBuffer toByteBuffer(final String s)
  {
    return DEFAULT_CHARSET.encode(CharBuffer.wrap(s));
  }


  public static byte[] toBytes(final String s)
  {
    return s.getBytes(DEFAULT_CHARSET);
  }


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
