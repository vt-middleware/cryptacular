/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

/**
 * Base 32 encoder/decoder pair.
 *
 * @author  Middleware Services
 */
public class Base32Codec implements Codec
{

  /** Encoder. */
  private final Encoder encoder = new Base32Encoder();

  /** Decoder. */
  private final Decoder decoder = new Base32Decoder();


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
