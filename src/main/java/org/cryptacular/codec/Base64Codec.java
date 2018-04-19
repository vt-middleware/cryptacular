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
  private final Encoder encoder;

  /** Decoder. */
  private final Decoder decoder;

  /** Custom alphabet to use. */
  private final String customAlphabet;

  /** Whether input/output padding is supported. */
  private final boolean padding;


  /**
   * Creates a new instance using the base-64 alphabet defined in RFC 4648.
   */
  public Base64Codec()
  {
    encoder = new Base64Encoder();
    decoder = new Base64Decoder();
    customAlphabet = null;
    padding = true;
  }


  /**
   * Creates a new instance using the given 64-character alphabet.
   *
   * @param  alphabet  64-character alphabet to use.
   */
  public Base64Codec(final String alphabet)
  {
    this(alphabet, true);
  }


  /**
   * Creates a new instance using the given 64-character alphabet with option to enable/disable padding.
   *
   * @param  alphabet  64-character alphabet to use.
   * @param  inputOutputPadding  True to enable support for padding, false otherwise.
   */
  public Base64Codec(final String alphabet, final boolean inputOutputPadding)
  {
    customAlphabet = alphabet;
    padding = inputOutputPadding;
    encoder = newEncoder();
    decoder = newDecoder();
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
    final Base64Encoder encoder;
    if (customAlphabet != null) {
      encoder = new Base64Encoder(customAlphabet);
    } else {
      encoder = new Base64Encoder();
    }
    encoder.setPaddedOutput(padding);
    return encoder;
  }


  @Override
  public Decoder newDecoder()
  {
    final Base64Decoder decoder;
    if (customAlphabet != null) {
      decoder = new Base64Decoder(customAlphabet);
    } else {
      decoder = new Base64Decoder();
    }
    decoder.setPaddedInput(padding);
    return decoder;
  }
}
