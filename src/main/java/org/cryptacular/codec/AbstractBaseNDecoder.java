/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

import org.cryptacular.EncodingException;

/**
 * Base decoder class for encoding schemes described in RFC 3548.
 *
 * @author  Middleware Services
 */
public abstract class AbstractBaseNDecoder implements Decoder
{

  /** Block of encoded characters. */
  private final char[] block = new char[getBlockLength() / getBitsPerChar()];

  /** Decoding table. */
  private final byte[] table;

  /** Current position in character block. */
  private int blockPos;


  /**
   * Creates a new instance with given parameters.
   *
   * @param  decodingTable  Byte array indexed by characters in the character set encoding.
   */
  public AbstractBaseNDecoder(final byte[] decodingTable)
  {
    table = decodingTable;
  }


  @Override
  public void decode(final CharBuffer input, final ByteBuffer output) throws EncodingException
  {
    char current;
    while (input.hasRemaining()) {
      current = input.get();
      if (Character.isWhitespace(current)) {
        continue;
      }
      block[blockPos++] = current;
      if (blockPos == block.length) {
        writeOutput(output);
      }
    }
  }


  @Override
  public void finalize(final ByteBuffer output) throws EncodingException
  {
    if (blockPos > 0) {
      writeOutput(output);
    }
  }


  @Override
  public int outputSize(final int inputSize)
  {
    return inputSize * getBitsPerChar() / 8;
  }


  /** @return  Number of bits in a block of encoded characters. */
  protected abstract int getBlockLength();


  /** @return  Number of bits encoding a single character. */
  protected abstract int getBitsPerChar();


  /**
   * Writes bytes in the current encoding block to the output buffer.
   *
   * @param  output  Output buffer.
   */
  private void writeOutput(final ByteBuffer output)
  {
    long b;
    long value = 0;
    int shift = getBlockLength();
    for (char c : block) {
      if (c == '=') {
        break;
      }
      b = table[c & 0x7F];
      if (b < 0) {
        throw new EncodingException("Invalid character " + c);
      }
      shift -= getBitsPerChar();
      value |= b << shift;
    }

    final int stop = shift + getBitsPerChar() - 1;
    int offset = getBlockLength();
    while (offset > stop) {
      offset -= 8;
      output.put((byte) ((value & (0xffL << offset)) >> offset));
    }
    blockPos = 0;
  }
}
