/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

/**
 * Base 64 encoder/decoder pair.
 *
 * @author  Middleware Services
 */
public class Base64Codec implements Codec
{

  /** Encoder. */
  private final Encoder encoder = new Base64Encoder();

  /** Decoder. */
  private final Decoder decoder = new Base64Decoder();

  /**
   * Determines whether the given byte represents an ASCII character in the character set for base64 encoding.
   *
   * @param  b  Byte to test.
   *
   * @return  True if the byte represents an ASCII character in the set of valid characters for base64 encoding, false
   *          otherwise. The padding character '=' is not considered valid since it may only appear at the end of a
   *          base64 encoded value.
   */
  public static boolean isBase64Char(final byte b)
  {
    return !(b < 47 || b > 122 || b > 57 && b < 65 || b > 90 && b < 97) || b == 43;
  }

  @Override
  public Encoder getEncoder()
  {
    return encoder;
  }


  @Override
  public Decoder getDecoder()
  {
    return decoder;
  }
}
