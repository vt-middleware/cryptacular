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

  /** Number of base64 characters per line. */
  private final int lineLength;

  /** Holds a block of bytes to encode. */
  private int block;

  /** Number of bits in encode block remaining. */
  private int remaining = 24;

  /** Number of characters written. */
  private int outCount = 0;


  /** Initializes the encoding character table. */
  static
  {
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
      output.append('\n');
    }
    outCount = 0;
  }


  /** {@inheritDoc} */
    @Override
    public int outputSize(final int inputSize)
    {
      int len = (inputSize + 2) * 4 / 3;
      if (lineLength > 0) {
        len += len / lineLength;
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
        output.put('\n');
      }
      mask >>= 6;
    }
    block = 0;
    remaining = 24;
  }
}
