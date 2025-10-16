/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

/**
 * Stateful base 32 decoder with support for line breaks.
 *
 * @author  Middleware Services
 */
public class Base32Decoder extends AbstractBaseNDecoder
{

  /** Base-32 character decoding table. */
  private static final byte[] DECODING_TABLE;


  /* Initializes the character decoding table. */
  static
  {
    DECODING_TABLE = decodingTable("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 32);
  }

  /**
   * Creates a new instance using the RFC 4648 alphabet, <code>ABCDEFGHIJKLMNOPQRSTUVWXYZ234567</code>, for decoding.
   */
  public Base32Decoder()
  {
    super(DECODING_TABLE);
  }


  /**
   * Creates a new instance using the given 32-character alphabet for decoding.
   *
   * @param  alphabet  32-character alphabet to use.
   */
  public Base32Decoder(final String alphabet)
  {
    super(decodingTable(alphabet, 32));
  }


  /**
   * Creates a new instance using the given 32-character alphabet for decoding.
   *
   * @param  paddedInput  True to enable support for padded input, false otherwise.
   */
  public Base32Decoder(final boolean paddedInput)
  {
    super(DECODING_TABLE, paddedInput);
  }


  /**
   * Creates a new instance using the given 32-character alphabet for decoding.
   *
   * @param  alphabet  32-character alphabet to use.
   * @param  paddedInput  True to enable support for padded input, false otherwise.
   */
  public Base32Decoder(final String alphabet, final boolean paddedInput)
  {
    super(decodingTable(alphabet, 32), paddedInput);
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
