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
  private final Encoder encoder;

  /** Decoder. */
  private final Decoder decoder = new HexDecoder();

  /** True to encode in uppercase characters, false otherwise. */
  private final boolean uppercase;


  /**
   * Creates a new instance that outputs lowercase hex characters and supports decoding in either case.
   */
  public HexCodec()
  {
    this(false);
  }


  /**
   * Creates a new instance that optionally outputs uppercase hex characters and supports decoding in either case.
   *
   * @param  uppercaseOutput  True to output uppercase alphabetic characters, false for lowercase.
   */
  public HexCodec(final boolean uppercaseOutput)
  {
    uppercase = uppercaseOutput;
    encoder = new HexEncoder(uppercase);
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


  @Override
  public Encoder newEncoder()
  {
    return new HexEncoder(uppercase);
  }


  @Override
  public Decoder newDecoder()
  {
    return new HexDecoder();
  }
}
