package org.cryptosis.codec;

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
      output.put(ENCODING_TABLE[current >>> 4]);
      output.put(ENCODING_TABLE[current & 0x0f]);
    }
  }


  /** {@inheritDoc} */
  @Override
  public void finalize(final CharBuffer output) {}


  /** {@inheritDoc} */
  @Override
  public int outputSize(final int inputSize)
  {
    return inputSize * 2;
  }
}
