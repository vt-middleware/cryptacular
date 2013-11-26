package org.cryptosis.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.Arrays;

/**
 * Stateful base64 decoder with support for line breaks.
 *
 * @author Marvin S. Addison
 */
public class Base64Decoder implements Decoder
{
  /** Base64 character decoding table. */
  private static final byte[] DECODING_TABLE = new byte[128];

  /** Block of encoded characters. */
  private char[] block = new char[4];

  /** Current position in character block. */
  private int blockPos;


  /** Initializes the character decoding table. */
  static {
    Arrays.fill(DECODING_TABLE, (byte) -1);
    for (int i = 0; i < 26; i++) {
      DECODING_TABLE[i + 65] = (byte) i;
    }
    for (int i = 0; i < 26; i++) {
      DECODING_TABLE[i + 97] = (byte) (i + 26);
    }
    for (int i = 0; i < 10; i++) {
      DECODING_TABLE[i + 48] = (byte) (i + 52);
    }
    DECODING_TABLE[43] = (byte) 60;
    DECODING_TABLE[47] = (byte) 61;
  }


  /** {@inheritDoc} */
  @Override
  public void decode(final CharBuffer input, final ByteBuffer output)
  {
    char current;
    while (input.hasRemaining()) {
      current = input.get();
      if (Character.isWhitespace(current)) {
        continue;
      }
      block[blockPos++] = current;
      if (blockPos == 4) {
        writeOutput(output);
      }
    }
  }


  /** {@inheritDoc} */
  @Override
  public void finalize(final ByteBuffer output)
  {
    if (blockPos > 0) {
      writeOutput(output);
    }
  }


  /** {@inheritDoc} */
  @Override
  public int outputSize(final int inputSize)
  {
    return inputSize * 3 / 4;
  }


  /**
   * Writes bytes in the current encoding block to the output buffer.
   *
   * @param  output  Output buffer.
   */
  private void writeOutput(final ByteBuffer output)
  {
    byte b;
    char c;
    int value = 0;
    int padLen = 0;
    int shift = 18;
    for (int i = 0; i < 4; i++) {
      c = block[i];
      if (c == '=') {
        padLen++;
        continue;
      }
      b = DECODING_TABLE[c & 0x7F];
      if (b < 0) {
        throw new IllegalArgumentException("Invalid base64 character " + c);
      }
      value |= b << shift;
      shift -= 6;
    }
    output.put((byte) ((value & 0xff0000) >> 16));
    if (padLen < 2) {
      output.put((byte) ((value & 0xff00) >> 8));
      if (padLen < 1) {
        output.put((byte) (value & 0xff));
      }
    }
    blockPos = 0;
  }
}
