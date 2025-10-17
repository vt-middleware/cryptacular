/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import org.cryptacular.CryptUtil;
import org.cryptacular.EncodingException;

/**
 * Stateless hexadecimal byte-to-character encoder.
 *
 * @author  Middleware Services
 */
public class HexEncoder implements Encoder
{

  /** Lowercase hex character encoding table. */
  private static final char[] LC_ENCODING_TABLE = new char[16];

  /** Uppercase hex character encoding table. */
  private static final char[] UC_ENCODING_TABLE = new char[16];



  /* Initializes the encoding character table. */
  static {
    initTable("0123456789abcdef", LC_ENCODING_TABLE);
    initTable("0123456789ABCDEF", UC_ENCODING_TABLE);
  }

  /** Flag indicating whether to delimit every two characters with ':' as in key fingerprints, etc. */
  private final boolean delimit;

  /** Encoding table to use. */
  private final char[] table;


  /** Creates a new instance that does not delimit bytes in the output hex string. */
  public HexEncoder()
  {
    this(false, false);
  }

  /**
   * Creates a new instance with optional colon-delimiting of bytes.
   *
   * @param  delimitBytes  True to delimit every two characters (i.e. every byte) with ':' character.
   */
  public HexEncoder(final boolean delimitBytes)
  {
    this(delimitBytes, false);
  }


  /**
   * Creates a new instance with optional colon-delimiting of bytes and uppercase output.
   *
   * @param  delimitBytes  True to delimit every two characters (i.e. every byte) with ':' character.
   * @param  uppercase  True to output uppercase alphabetic characters, false for lowercase.
   */
  public HexEncoder(final boolean delimitBytes, final boolean uppercase)
  {
    delimit = delimitBytes;
    table = uppercase ? UC_ENCODING_TABLE : LC_ENCODING_TABLE;
  }


  @Override
  public void encode(final ByteBuffer input, final CharBuffer output) throws EncodingException
  {
    CryptUtil.assertNotNullArg(input, "Input cannot be null");
    CryptUtil.assertNotNullArg(output, "Output cannot be null");
    byte current;
    while (input.hasRemaining()) {
      current = input.get();
      output.put(table[(current & 0xf0) >> 4]);
      output.put(table[current & 0x0f]);
      if (delimit && input.hasRemaining()) {
        output.put(':');
      }
    }
  }


  @Override
  public void finalize(final CharBuffer output) throws EncodingException {}


  @Override
  public int outputSize(final int inputSize)
  {
    int size = inputSize * 2;
    if (delimit) {
      size += inputSize - 1;
    }
    return size;
  }


  /**
   * Initializes the encoding table for the given character set.
   *
   * @param  charset  Character set.
   * @param  table  Encoding table.
   */
  private static void initTable(final String charset, final char[] table)
  {
    for (int i = 0; i < charset.length(); i++) {
      table[i] = charset.charAt(i);
    }
  }
}
