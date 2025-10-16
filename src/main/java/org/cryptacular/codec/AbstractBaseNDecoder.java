/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import org.cryptacular.CryptUtil;
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
  private final byte[] decodingTable;

  /** Flag indicating whether input is padded. True by default. */
  private final boolean paddedInput;

  /** Current position in character block. */
  private int blockPos;


  /**
   * Creates a new instance with given parameters.
   *
   * @param  decodingTable  Byte array indexed by characters in the character set encoding.
   */
  public AbstractBaseNDecoder(final byte[] decodingTable)
  {
    this(decodingTable, true);
  }


  /**
   * Creates a new instance with given parameters.
   *
   * @param  decodingTable  Byte array indexed by characters in the character set encoding.
   * @param  paddedInput  True to enable support for padded input, false otherwise.
   */
  public AbstractBaseNDecoder(final byte[] decodingTable, final boolean paddedInput)
  {
    this.decodingTable = CryptUtil.assertNotNullArg(decodingTable, "Decoding table cannot be null");
    this.paddedInput = paddedInput;
  }


  /** @return  True if padded input is accepted (default), false otherwise. */
  public boolean isPaddedInput()
  {
    return paddedInput;
  }


  @Override
  public void decode(final CharBuffer input, final ByteBuffer output) throws EncodingException
  {
    CryptUtil.assertNotNullArg(input, "Input cannot be null");
    CryptUtil.assertNotNullArg(output, "Output cannot be null");
    char current;
    while (input.hasRemaining()) {
      current = input.get();
      if (Character.isWhitespace(current) || current == '=') {
        continue;
      }
      block[blockPos++] = current;
      if (blockPos == block.length) {
        writeOutput(output, block.length);
      }
    }
  }


  @Override
  public void finalize(final ByteBuffer output) throws EncodingException
  {
    CryptUtil.assertNotNullArg(output, "Output cannot be null");
    if (blockPos > 0) {
      try {
        writeOutput(output, blockPos);
      } catch (BufferOverflowException e) {
        throw new EncodingException("Buffer overflow", e);
      }
    }
  }


  @Override
  public int outputSize(final int inputSize)
  {
    final int size;
    if (paddedInput) {
      size = inputSize;
    } else {
      // For unpadded input, add the maximum number of padding characters to get worst-case estimate
      size = inputSize + getBlockLength() / 8 - 1;
    }
    return size * getBitsPerChar() / 8;
  }


  /** @return  Number of bits in a block of encoded characters. */
  protected abstract int getBlockLength();


  /** @return  Number of bits encoding a single character. */
  protected abstract int getBitsPerChar();


  /**
   * Converts the given alphabet into a base-N decoding table.
   *
   * @param  alphabet  Decoding alphabet to use.
   * @param  n  Encoding base.
   *
   * @return  Decoding table of 128 elements.
   */
  protected static byte[] decodingTable(final String alphabet, final int n)
  {
    CryptUtil.assertNotNullArg(alphabet, "Alphabet cannot be null");
    if (alphabet.length() != n) {
      throw new IllegalArgumentException("Alphabet must be exactly " + n + " characters long");
    }
    final byte[] decodingTable = new byte[128];
    for (int i = 0; i < n; i++) {
      decodingTable[alphabet.charAt(i)] = (byte) i;
    }
    return decodingTable;
  }


  /**
   * Writes bytes in the current encoding block to the output buffer.
   *
   * @param  output  Output buffer.
   * @param  len  Number of characters to decode in current block.
   */
  private void writeOutput(final ByteBuffer output, final int len)
  {
    long b;
    long value = 0;
    int shift = getBlockLength();
    for (int i = 0; i < len; i++) {
      b = decodingTable[block[i] & 0x7F];
      if (b < 0) {
        throw new EncodingException("Invalid character " + block[i]);
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
