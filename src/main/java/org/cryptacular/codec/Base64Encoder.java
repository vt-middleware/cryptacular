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
  private static final char[] DEFAULT_ENCODING_TABLE;

  /** Filesystem and URL-safe base 64 character encoding table. */
  private static final char[] URLSAFE_ENCODING_TABLE;


  /* Initializes the default character encoding tables. */
  static
  {
    DEFAULT_ENCODING_TABLE = encodingTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 64);
    URLSAFE_ENCODING_TABLE = encodingTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", 64);
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


  /**
   * Creates a new instance that produces base 64-encoded output with the given number of characters per line with the
   * option of URL-safe character set.
   *
   * @param  urlSafe  True to use URL and filesystem-safe character set, false otherwise.
   * @param  charactersPerLine  Number of characters per line. A zero or negative value disables line breaks.
   * @param  paddedOutput  True to enable padded output, false otherwise.
   */
  public Base64Encoder(final boolean urlSafe, final int charactersPerLine, final boolean paddedOutput)
  {
    super(urlSafe ? URLSAFE_ENCODING_TABLE : DEFAULT_ENCODING_TABLE, charactersPerLine, paddedOutput);
  }


  /**
   * Creates a new instance that produces base 64-encoded output with the given 64-character alphabet.
   *
   * @param  alphabet  64-character alphabet to use.
   */
  public Base64Encoder(final String alphabet)
  {
    this(alphabet, -1);
  }


  /**
   * Creates a new instance that produces base 64-encoded output with the given 64-character alphabet with line
   * wrapping at the specified line length;
   *
   * @param  alphabet  64-character alphabet to use.
   * @param  charactersPerLine  Number of characters per line. A zero or negative value disables line breaks.
   */
  public Base64Encoder(final String alphabet, final int charactersPerLine)
  {
    super(encodingTable(alphabet, 64), charactersPerLine);
  }


  /**
   * Creates a new instance that produces base 64-encoded output with the given 64-character alphabet with line
   * wrapping at the specified line length;
   *
   * @param  alphabet  64-character alphabet to use.
   * @param  charactersPerLine  Number of characters per line. A zero or negative value disables line breaks.
   * @param  paddedOutput  True to enable padded output, false otherwise.
   */
  public Base64Encoder(final String alphabet, final int charactersPerLine, final boolean paddedOutput)
  {
    super(encodingTable(alphabet, 64), charactersPerLine, paddedOutput);
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


  /**
   * Builder for base-64 encoders.
   */
  public static class Builder
  {
    /** URL-safe alphabet flag. */
    private boolean urlSafe;

    /** Arbitrary alphbet. */
    private String alphabet;

    /** Padding flag. */
    private boolean padding;

    /** Number of base-64 characters per line in output. */
    private int charactersPerLine = -1;


    /**
     * Sets the URL-safe alphabet flag.
     *
     * @param  safe  True for URL-safe alphabet, false otherwise.
     *
     * @return  This instance.
     */
    public Base64Encoder.Builder setUrlSafe(final boolean safe)
    {
      urlSafe = safe;
      return this;
    }


    /**
     * Sets an arbitrary 64-character alphabet for encoding.
     *
     * @param  alpha  Alternative alphabet.
     *
     * @return  This instance.
     */
    public Base64Encoder.Builder setAlphabet(final String alpha)
    {
      alphabet = alpha;
      return this;
    }


    /**
     * Sets padding flag on the encoder.
     *
     * @param  pad  True for base-64 padding, false otherwise.
     *
     * @return  This instance.
     */
    public Base64Encoder.Builder setPadding(final boolean pad)
    {
      padding = pad;
      return this;
    }


    /**
     * Sets the number of characters per line in output produced by the encoder.
     *
     * @param  lineLength  Number of characters per line. Set to <code>-1</code> to suppress line breaks.
     *
     * @return  This instance.
     */
    public Base64Encoder.Builder setCharactersPerLine(final int lineLength)
    {
      charactersPerLine = lineLength;
      return this;
    }


    /**
     * Builds a base-64 encoder with the given options.
     *
     * @return  New base-64 encoder instance.
     */
    public Base64Encoder build()
    {
      final Base64Encoder decoder;
      if (alphabet != null) {
        decoder = new Base64Encoder(alphabet, charactersPerLine, padding);
      } else {
        decoder = new Base64Encoder(urlSafe, charactersPerLine, padding);
      }
      return decoder;
    }
  }
}
