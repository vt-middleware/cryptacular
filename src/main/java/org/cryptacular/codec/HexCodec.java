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


  @Override
  public Encoder newEncoder()
  {
    return new HexEncoder();
  }


  @Override
  public Decoder newDecoder()
  {
    return new HexDecoder();
  }
}
