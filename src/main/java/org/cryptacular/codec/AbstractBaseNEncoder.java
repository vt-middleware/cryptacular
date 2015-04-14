/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * Base encoder class for encoding schemes described in RFC 3548.
 *
 * @author  Middleware Services
 */
public abstract class AbstractBaseNEncoder implements Encoder
{

  /** Platform-specific line terminator string, e.g. LF (Unix), CRLF (Windows). */
  private static final String NEWLINE = System.lineSeparator();

  /** Number of base64 characters per line. */
  protected final int lineLength;

  /** Encoding character set. */
  private final char[] charset;

  /** Number of bits in a block. */
  private final int blockLength = getBlockLength();

  /** Number of bits encoding a single character. */
  private final int bitsPerChar = getBitsPerChar();

  /** Initial bit mask for selecting characters in a block. */
  private final long initialBitMask;

  /** Holds a block of bytes to encode. */
  private long block;

  /** Number of bits in encode block remaining. */
  private int remaining = blockLength;

  /** Number of characters written. */
  private int outCount;


  /**
   * Creates a new instance with given parameters.
   *
   * @param  characterSet  Encoding character set.
   * @param  charactersPerLine  Number of characters per line.
   */
  public AbstractBaseNEncoder(final char[] characterSet, final int charactersPerLine)
  {
    charset = characterSet;

    long mask = 0;
    for (int i = 1; i <= bitsPerChar; i++) {
      mask |= 1L << (blockLength - i);
    }
    initialBitMask = mask;
    lineLength = charactersPerLine;
  }


  @Override
  public void encode(final ByteBuffer input, final CharBuffer output)
  {
    while (input.hasRemaining()) {
      remaining -= 8;
      block |= (input.get() & 0xffL) << remaining;
      if (remaining == 0) {
        writeOutput(output, 0);
      }
    }
  }


  @Override
  public void finalize(final CharBuffer output)
  {
    if (remaining < blockLength) {
      // Floor division
      final int stop = remaining / bitsPerChar * bitsPerChar;
      writeOutput(output, stop);
      for (int i = stop; i > 0; i -= bitsPerChar) {
        output.put('=');
      }
    }
    // Append trailing newline to make consistent with OpenSSL base64 output
    if (lineLength > 0 && output.position() > 0) {
      output.append(NEWLINE);
    }
    outCount = 0;
  }


  @Override
  public int outputSize(final int inputSize)
  {
    int len = (inputSize + (blockLength / 8) - 1) * 8 / bitsPerChar;
    if (lineLength > 0) {
      len += (len / lineLength + 1) * NEWLINE.length();
    }
    return len;
  }


  /** @return  Number of bits in a block of encoded characters. */
  protected abstract int getBlockLength();


  /** @return  Number of bits encoding a single character. */
  protected abstract int getBitsPerChar();


  /**
   * Writes bytes in the current encoding block to the output buffer.
   *
   * @param  output  Output buffer.
   * @param  stop  Bit shift stop position where data in current encoding block ends.
   */
  private void writeOutput(final CharBuffer output, final int stop)
  {
    int shift = blockLength;
    long mask = initialBitMask;
    int index;
    while (shift > stop) {
      shift -= bitsPerChar;
      index = (int) ((block & mask) >> shift);
      output.put(charset[index]);
      outCount++;
      if (lineLength > 0 && outCount % lineLength == 0) {
        output.put(NEWLINE);
      }
      mask >>= bitsPerChar;
    }
    block = 0;
    remaining = blockLength;
  }
}
