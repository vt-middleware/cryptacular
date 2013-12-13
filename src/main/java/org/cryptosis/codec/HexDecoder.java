package org.cryptosis.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.Arrays;

/**
 * Stateful hexadecimal character-to-byte decoder.
 *
 * @author Marvin S. Addison
 */
public class HexDecoder implements Decoder
{
  /** Hex character decoding table. */
  private static final byte[] DECODING_TABLE = new byte[128];

  /** Number of encoded characters processed. */
  private int count = 0;

  /** Initializes the character decoding table. */
  static {
    Arrays.fill(DECODING_TABLE, (byte) -1);
    for (int i = 0; i < 10; i++) {
      DECODING_TABLE[i + 48] = (byte) i;
    }
    for (int i = 0; i < 6; i++) {
      DECODING_TABLE[i + 65] = (byte) (10 + i);
      DECODING_TABLE[i + 97] = (byte) (10 + i);
    }
  }


  /** {@inheritDoc} */
  @Override
  public void decode(final CharBuffer input, final ByteBuffer output)
  {
    byte hi = 0;
    byte lo;
    char current;
    while (input.hasRemaining()) {
      current = input.get();
      if (current == ':' || Character.isWhitespace(current)) {
        continue;
      }
      if ((count++ & 0x01) == 0) {
        hi = lookup(current);
      } else {
        lo = lookup(current);
        output.put((byte) ((hi << 4) | lo));
      }
    }
  }


  /** {@inheritDoc} */
  @Override
  public void finalize(final ByteBuffer output)
  {
    count = 0;
  }


  /** {@inheritDoc} */
  @Override
  public int outputSize(final int inputSize)
  {
    return inputSize / 2;
  }


  /**
   * Looks up the byte that corresponds to the given character.
   *
   * @param  c  Encoded character.
   *
   * @return  Decoded byte.
   */
  private static byte lookup(final char c)
  {
    final byte b = DECODING_TABLE[c & 0x7F];
    if (b < 0) {
      throw new IllegalArgumentException("Invalid hex character " + c);
    }
    return b;
  }
}
