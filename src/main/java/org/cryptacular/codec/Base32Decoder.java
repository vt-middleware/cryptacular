/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

import java.util.Arrays;

/**
 * Stateful base 32 decoder with support for line breaks.
 *
 * @author  Middleware Services
 */
public class Base32Decoder extends AbstractBaseNDecoder
{
  /** Base-32 character decoding table. */
  private static final byte[] DECODING_TABLE = new byte[128];


  /**
   * Initializes the character decoding table.
   */
  static {
    Arrays.fill(DECODING_TABLE, (byte) -1);
    for (int i = 0; i < 26; i++) {
      DECODING_TABLE[i + 65] = (byte) i;
    }
    for (int i = 0; i < 6; i++) {
      DECODING_TABLE[i + 50] = (byte) (i + 26);
    }
  }


  /** Creates a new instance. */
  public Base32Decoder()
  {
    super(DECODING_TABLE);
  }


  /** {@inheritDoc} */
  @Override
  protected int getBlockLength()
  {
    return 40;
  }


  /** {@inheritDoc} */
  @Override
  protected int getBitsPerChar()
  {
    return 5;
  }
}
