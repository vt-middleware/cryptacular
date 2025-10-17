/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

/**
 * Stateful base 64 decoder with support for line breaks.
 *
 * @author  Middleware Services
 */
public class Base64Decoder extends AbstractBaseNDecoder
{

  /** Default base-64 character decoding table. */
  private static final byte[] DEFAULT_DECODING_TABLE;

  /** URL and filesystem-safe base-64 character decoding table. */
  private static final byte[] URLSAFE_DECODING_TABLE;


  /* Initializes the character decoding table. */
  static
  {
    DEFAULT_DECODING_TABLE = decodingTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 64);
    URLSAFE_DECODING_TABLE = decodingTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", 64);
  }


  /** Creates a new instance that decodes base 64-encoded input in the default character set. */
  public Base64Decoder()
  {
    this(false);
  }


  /**
   * Creates a new instance that decodes base 64-encoded input in the optional URL-safe character set.
   *
   * @param  urlSafe  True to use URL and filesystem-safe character set, false otherwise.
   */
  public Base64Decoder(final boolean urlSafe)
  {
    super(urlSafe ? URLSAFE_DECODING_TABLE : DEFAULT_DECODING_TABLE);
  }


  /**
   * Creates a new instance that decodes base 64-encoded input in the optional URL-safe character set.
   *
   * @param  urlSafe  True to use URL and filesystem-safe character set, false otherwise.
   * @param  paddedInput  True to enable support for padded input, false otherwise.
   */
  public Base64Decoder(final boolean urlSafe, final boolean paddedInput)
  {
    super(urlSafe ? URLSAFE_DECODING_TABLE : DEFAULT_DECODING_TABLE, paddedInput);
  }


  /**
   * Creates a new instance that decodes base-64 character data encoded in the given alphabet.
   *
   * @param  alphabet  Base-64 alphabet to use for decoding
   */
  public Base64Decoder(final String alphabet)
  {
    super(decodingTable(alphabet, 64));
  }


  /**
   * Creates a new instance that decodes base-64 character data encoded in the given alphabet.
   *
   * @param  alphabet  Base-64 alphabet to use for decoding
   * @param  paddedInput  True to enable support for padded input, false otherwise.
   */
  public Base64Decoder(final String alphabet, final boolean paddedInput)
  {
    super(decodingTable(alphabet, 64), paddedInput);
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
   * Builder for base-64 decoders.
   */
  public static class Builder
  {
    /** URL-safe alphabet flag. */
    private boolean urlSafe;

    /** Arbitrary alphbet. */
    private String alphabet;

    /** Padding flag. */
    private boolean padding;


    /**
     * Sets the URL-safe alphabet flag.
     *
     * @param safe True for URL-safe alphabet, false otherwise.
     *
     * @return This instance.
     */
    public Builder setUrlSafe(final boolean safe)
    {
      urlSafe = safe;
      return this;
    }


    /**
     * Sets an arbitrary 64-character alphabet for decoding.
     *
     * @param alpha Alternative alphabet.
     *
     * @return This instance.
     */
    public Builder setAlphabet(final String alpha)
    {
      alphabet = alpha;
      return this;
    }


    /**
     * Sets padding flag on the decoder.
     *
     * @param pad True for base-64 padding, false otherwise.
     *
     * @return This instance.
     */
    public Builder setPadding(final boolean pad)
    {
      padding = pad;
      return this;
    }


    /**
     * Builds a base-64 decoder with the given options.
     *
     * @return New base-64 decoder instance.
     */
    public Base64Decoder build()
    {
      final Base64Decoder decoder;
      if (alphabet != null) {
        decoder = new Base64Decoder(alphabet, padding);
      } else {
        decoder = new Base64Decoder(urlSafe, padding);
      }
      return decoder;
    }
  }
}
