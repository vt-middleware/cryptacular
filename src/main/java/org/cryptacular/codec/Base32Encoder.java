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
  private static final char[] ENCODING_TABLE;


  /* Initializes the default character encoding table. */
  static
  {
    ENCODING_TABLE = encodingTable("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 32);
  }


  /**
   * Creates a new instance that produces base 32-encoded output in the RFC 4648 alphabet,
   * <code>ABCDEFGHIJKLMNOPQRSTUVWXYZ234567</code>, with no line breaks in the output.
   */
  public Base32Encoder()
  {
    // Default to no line breaks.
    this(-1);
  }


  /**
   * Creates a new instance that produces base 32-encoded output in the RFC 4648 alphabet,
   * <code>ABCDEFGHIJKLMNOPQRSTUVWXYZ234567</code>, with the given number of characters per line in the output.
   *
   * @param  charactersPerLine  Number of characters per line. A zero or negative value disables line breaks.
   */
  public Base32Encoder(final int charactersPerLine)
  {
    super(ENCODING_TABLE, charactersPerLine);
  }


  /**
   * Creates a new instance that produces base 32-encoded output in the RFC 4648 alphabet,
   * <code>ABCDEFGHIJKLMNOPQRSTUVWXYZ234567</code>, with the given number of characters per line in the output.
   *
   * @param  charactersPerLine  Number of characters per line. A zero or negative value disables line breaks.
   * @param  paddedOutput  True to enable padded output, false otherwise.
   */
  public Base32Encoder(final int charactersPerLine, final boolean paddedOutput)
  {
    super(ENCODING_TABLE, charactersPerLine, paddedOutput);
  }


  /**
   * Creates a new instance that produces base 32-encoded output in the given 32-character alphabet with no line
   * breaks in the output.
   *
   * @param  alphabet  32-character alphabet to use.
   */
  public Base32Encoder(final String alphabet)
  {
    this(alphabet, -1);
  }


  /**
   * Creates a new instance that produces base 32-encoded output in the given 32-character alphabet
   * with the given number of characters per line in the output.
   *
   * @param  alphabet  32-character alphabet to use.
   * @param  charactersPerLine  Number of characters per line. A zero or negative value disables line breaks.
   */
  public Base32Encoder(final String alphabet, final int charactersPerLine)
  {
    super(encodingTable(alphabet, 32), charactersPerLine);
  }


  /**
   * Creates a new instance that produces base 32-encoded output in the given 32-character alphabet
   * with the given number of characters per line in the output.
   *
   * @param  alphabet  32-character alphabet to use.
   * @param  charactersPerLine  Number of characters per line. A zero or negative value disables line breaks.
   * @param  paddedOutput  True to enable padded output, false otherwise.
   */
  public Base32Encoder(final String alphabet, final int charactersPerLine, final boolean paddedOutput)
  {
    super(encodingTable(alphabet, 32), charactersPerLine, paddedOutput);
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
