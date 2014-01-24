/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

/**
 * Hexadecimal encoder/decoder pair.
 *
 * @author  Middleware Services
 */
public class HexCodec implements Codec
{

  /** Encoder. */
  private final Encoder encoder = new HexEncoder();

  /** Decoder. */
  private final Decoder decoder = new HexDecoder();


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
