/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.security.SecureRandom;
import org.cryptacular.CryptUtil;

/**
 * Generates random identifiers with an alphanumeric character set by default.
 *
 * @author  Middleware Services
 */
public class RandomIdGenerator implements IdGenerator
{

  /** Default character set. */
  public static final String DEFAULT_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  /** Maximum length of ID to generate in bytes. */
  private static final int MAX_ID_LENGTH = CryptUtil.parseInt(
    System.getProperty("org.cryptacular.generator.maxIdLength", "1024"), i -> i > 0, 1024);

  /** Size of generated identifiers. */
  private final int length;

  /** Identifier character set. */
  private final String charset;

  /** Source of randomness. */
  private final SecureRandom secureRandom;

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
    if (length < 1 || length > MAX_ID_LENGTH) {
      throw new IllegalArgumentException("Length must be greater than 0 and cannot exceed " + MAX_ID_LENGTH);
    }
    this.length = length;
    if (charset == null || charset.length() < 2 || charset.length() > 128) {
      throw new IllegalArgumentException("Charset length must be in the range 2 - 128");
    }
    this.charset = charset;
    secureRandom = new SecureRandom();
    // Call nextBytes to force seeding via default process
    secureRandom.nextBytes(new byte[1]);
  }


  @Override
  public String generate()
  {
    final StringBuilder id = new StringBuilder(length);
    final byte[] output = new byte[length];
    secureRandom.nextBytes(output);
    int index;
    for (int i = 0; i < output.length && id.length() < length; i++) {
      index = 0x7F & output[i];
      id.append(charset.charAt(index % charset.length()));
    }
    return id.toString();
  }
}
