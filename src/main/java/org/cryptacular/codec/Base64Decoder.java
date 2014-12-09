/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

import java.util.Arrays;

/**
 * Stateful base 64 decoder with support for line breaks.
 *
 * @author  Middleware Services
 */
public class Base64Decoder extends AbstractBaseNDecoder
{

  /** Default base-64 character decoding table. */
  private static final byte[] DEFAULT_DECODING_TABLE = new byte[128];

  /** URL and filesystem-safe base-64 character decoding table. */
  private static final byte[] URLSAFE_DECODING_TABLE = new byte[128];


  /**
   * Initializes the character decoding table.
   */
  static {
    Arrays.fill(DEFAULT_DECODING_TABLE, (byte) -1);
    for (int i = 0; i < 26; i++) {
      DEFAULT_DECODING_TABLE[i + 65] = (byte) i;
    }
    for (int i = 0; i < 26; i++) {
      DEFAULT_DECODING_TABLE[i + 97] = (byte) (i + 26);
    }
    for (int i = 0; i < 10; i++) {
      DEFAULT_DECODING_TABLE[i + 48] = (byte) (i + 52);
    }
    System.arraycopy(DEFAULT_DECODING_TABLE, 0, URLSAFE_DECODING_TABLE, 0, 128);
    DEFAULT_DECODING_TABLE[43] = (byte) 62;
    DEFAULT_DECODING_TABLE[47] = (byte) 63;
    URLSAFE_DECODING_TABLE[45] = (byte) 62;
    URLSAFE_DECODING_TABLE[95] = (byte) 63;
  }


  /**
   * Creates a new instance that decodes base 64-encoded input in the default
   * character set.
   */
  public Base64Decoder()
  {
    this(false);
  }


  /**
   * Creates a new instance that decodes base 64-encoded input in the optional
   * URL-safe character set.
   *
   * @param  urlSafe  True to use URL and filesystem-safe character set, false
   *                  otherwise.
   */
  public Base64Decoder(final boolean urlSafe)
  {
    super(urlSafe ? URLSAFE_DECODING_TABLE : DEFAULT_DECODING_TABLE);
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
