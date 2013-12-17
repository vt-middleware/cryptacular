package org.cryptosis;

import org.cryptosis.codec.Base64Decoder;
import org.cryptosis.codec.Base64Encoder;
import org.cryptosis.codec.Decoder;
import org.cryptosis.codec.Encoder;
import org.cryptosis.codec.HexDecoder;
import org.cryptosis.codec.HexEncoder;

/**
 * Describes a string-to-byte encoding with methods to instantiate the appropriate {@link Encoder}/{@link Decoder}.
 *
 * @author Marvin S. Addison
 */
public enum CodecSpec
{
  /** Hexadecimal encoding. */
  Hex,

  /** Base64 encoding. */
  Base64;


  /**
   * @return  New encoder instances that encodes bytes to characters according to the encoding.
   */
  public Encoder newEncoder()
  {
    final Encoder encoder;
    if ("Hex".equals(name())) {
      encoder = new HexEncoder();
    } else if ("Base64".equals(name())) {
      encoder = new Base64Encoder();
    } else {
      throw new IllegalArgumentException("Invalid encoding.");
    }
    return encoder;
  }


  /**
   * @return  New decoder instances that decodes characters into bytes according to the encoding.
   */
  public Decoder newDecoder()
  {
    final Decoder decoder;
    if ("Hex".equals(name())) {
      decoder = new HexDecoder();
    } else if ("Base64".equals(name())) {
      decoder = new Base64Decoder();
    } else {
      throw new IllegalArgumentException("Invalid encoding.");
    }
    return decoder;
  }
}
