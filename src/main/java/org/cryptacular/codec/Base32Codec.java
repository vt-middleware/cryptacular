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
  private final Encoder encoder;

  /** Decoder. */
  private final Decoder decoder;

  /** Custom alphabet to use. */
  private final String customAlphabet;

  /** Whether input/output padding is supported. */
  private final boolean padding;


  /**
   * Creates a new instance using the RFC 4328 alphabet, <code>ABCDEFGHIJKLMNOPQRSTUVWXYZ234567</code>.
   */
  public Base32Codec()
  {
    encoder = new Base32Encoder();
    decoder = new Base32Decoder();
    customAlphabet = null;
    padding = true;
  }


  /**
   * Creates a new instance using the given 32-character alphabet.
   *
   * @param  alphabet  32-character alphabet to use.
   */
  public Base32Codec(final String alphabet)
  {
    this(alphabet, true);
  }


  /**
   * Creates a new instance using the given 32-character alphabet with option to enable/disable padding.
   *
   * @param  alphabet  32-character alphabet to use.
   * @param  inputOutputPadding  True to enable support for padding, false otherwise.
   */
  public Base32Codec(final String alphabet, final boolean inputOutputPadding)
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
    final Base32Encoder encoder;
    if (customAlphabet != null) {
      encoder = new Base32Encoder(customAlphabet);
    } else {
      encoder = new Base32Encoder();
    }
    encoder.setPaddedOutput(padding);
    return encoder;
  }


  @Override
  public Decoder newDecoder()
  {
    final Base32Decoder decoder;
    if (customAlphabet != null) {
      decoder = new Base32Decoder(customAlphabet);
    } else {
      decoder = new Base32Decoder();
    }
    decoder.setPaddedInput(padding);
    return decoder;
  }
}
