/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

/**
 * Base64 encoder/decoder pair.
 *
 * @author  Middleware Services
 */
public class Base64Codec implements Codec
{

  /** Encoder. */
  private final Encoder encoder = new Base64Encoder();

  /** Decoder. */
  private final Decoder decoder = new Base64Decoder();


  /** {@inheritDoc} */
  @Override
  public Encoder getEncoder()
  {
    return encoder;
  }


  /** {@inheritDoc} */
  @Override
  public Decoder getDecoder()
  {
    return decoder;
  }
}
