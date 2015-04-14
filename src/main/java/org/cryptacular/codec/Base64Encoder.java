/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

/**
 * Stateful base 64 encoder with support for configurable line breaks.
 *
 * @author  Middleware Services
 */
public class Base64Encoder extends AbstractBaseNEncoder
{

  /** Default base 64 character encoding table. */
  private static final char[] DEFAULT_ENCODING_TABLE = new char[64];

  /** Filesystem and URL-safe base 64 character encoding table. */
  private static final char[] URLSAFE_ENCODING_TABLE = new char[64];


  /**
   * Initializes the encoding character table.
   */
  static {
    final String defaultCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < defaultCharset.length(); i++) {
      DEFAULT_ENCODING_TABLE[i] = defaultCharset.charAt(i);
      URLSAFE_ENCODING_TABLE[i] = defaultCharset.charAt(i);
    }
    URLSAFE_ENCODING_TABLE[62] = '-';
    URLSAFE_ENCODING_TABLE[63] = '_';
  }


  /** Creates a new instance that produces base 64-encoded output with no line breaks in the default character set. */
  public Base64Encoder()
  {
    // Default to no line breaks.
    this(-1);
  }


  /**
   * Creates a new instance that produces base 64-encoded output with no line breaks and optional URL-safe character
   * set.
   *
   * @param  urlSafe  True to use URL and filesystem-safe character set, false otherwise.
   */
  public Base64Encoder(final boolean urlSafe)
  {
    this(urlSafe, -1);
  }


  /**
   * Creates a new instance that produces base 64-encoded output with the given number of characters per line in the
   * default character set.
   *
   * @param  charactersPerLine  Number of characters per line. A zero or negative value disables line breaks.
   */
  public Base64Encoder(final int charactersPerLine)
  {
    this(false, charactersPerLine);
  }


  /**
   * Creates a new instance that produces base 64-encoded output with the given number of characters per line with the
   * option of URL-safe character set.
   *
   * @param  urlSafe  True to use URL and filesystem-safe character set, false otherwise.
   * @param  charactersPerLine  Number of characters per line. A zero or negative value disables line breaks.
   */
  public Base64Encoder(final boolean urlSafe, final int charactersPerLine)
  {
    super(urlSafe ? URLSAFE_ENCODING_TABLE : DEFAULT_ENCODING_TABLE, charactersPerLine);
  }


  @Override
  protected int getBlockLength()
  {
    return 24;
  }


  @Override
  protected int getBitsPerChar()
  {
    return 6;
  }
}
