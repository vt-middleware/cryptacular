/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

/**
 * Stateful base 32 encoder with support for configurable line breaks.
 *
 * @author  Middleware Services
 */
public class Base32Encoder extends AbstractBaseNEncoder
{

  /** Base 32 character encoding table. */
  private static final char[] ENCODING_TABLE = new char[32];


  /**
   * Initializes the encoding character table.
   */
  static {
    final String charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    for (int i = 0; i < charset.length(); i++) {
      ENCODING_TABLE[i] = charset.charAt(i);
    }
  }


  /**
   * Creates a new instance that produces base 32-encoded output with no line
   * breaks.
   */
  public Base32Encoder()
  {
    // Default to no line breaks.
    this(-1);
  }


  /**
   * Creates a new instance that produces base 32-encoded output with the given
   * number of characters per line in the default character set.
   *
   * @param  charactersPerLine  Number of characters per line. A zero or
   *                            negative value disables line breaks.
   */
  public Base32Encoder(final int charactersPerLine)
  {
    super(ENCODING_TABLE, charactersPerLine);
  }


  @Override
  protected int getBlockLength()
  {
    return 40;
  }


  @Override
  protected int getBitsPerChar()
  {
    return 5;
  }
}
