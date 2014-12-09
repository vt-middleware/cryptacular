/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
import org.cryptacular.util.NonceUtil;

/**
 * Generates random identifiers with an alphanumeric character set by default.
 *
 * @author  Middleware Services
 */
public class RandomIdGenerator implements IdGenerator
{

  /** Default character set. */
  public static final String DEFAULT_CHARSET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  /** Size of generated identifiers. */
  private final int length;

  /** Identifier character set. */
  private final String charset;

  /** Random bit generator. */
  private final SP80090DRBG rbg;


  /**
   * Creates a new instance with the default character set.
   *
   * @param  length  Number of characters in generated identifiers.
   */
  public RandomIdGenerator(final int length)
  {
    this(length, DEFAULT_CHARSET);
  }


  /**
   * Creates a new instance with a defined character set.
   *
   * @param  length  Number of characters in generated identifiers.
   * @param  charset  Character set.
   */
  public RandomIdGenerator(final int length, final String charset)
  {
    if (length < 1) {
      throw new IllegalArgumentException("Length must be positive");
    }
    this.length = length;
    if (charset == null || charset.length() < 2 || charset.length() > 128) {
      throw new IllegalArgumentException(
        "Charset length must be in the range 2 - 128");
    }
    this.charset = charset;
    this.rbg = NonceUtil.newRBG(8);
  }


  @Override
  public String generate()
  {
    final StringBuilder id = new StringBuilder(length);
    final byte[] bits = new byte[1];
    int index;
    for (int i = 0; i < length; i++) {
      rbg.generate(bits, null, false);
      index = 0x7F & bits[0];
      id.append(charset.charAt(index % charset.length()));
    }
    return id.toString();
  }
}
