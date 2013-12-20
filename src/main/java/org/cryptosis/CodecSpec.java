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
public class CodecSpec
{
  /** Hexadecimal encoding specification. */
  public static CodecSpec HEX = new CodecSpec("Hex");

  /** Base64 encoding specification. */
  public static CodecSpec BASE64 = new CodecSpec("Base64");


  /** Name of encoding, e.g. "Hex, "Base64". */
  private String encoding;


  /**
   * Creates a new instance of the given encoding.
   *
   * @param  encoding  Name of encoding.
   */
  public CodecSpec(final String encoding)
  {
    if (encoding == null) {
      throw new IllegalArgumentException("Encoding cannot be null.");
    }
    this.encoding = encoding;
  }


  /**
   * @return  The name of the encoding, e.g. "Hex", "Base64".
   */
  public String getEncoding()
  {
    return encoding;
  }


  /**
   * @return  New encoder instances that encodes bytes to characters according to the encoding.
   */
  public Encoder newEncoder()
  {
    final Encoder encoder;
    if ("Hex".equalsIgnoreCase(encoding)) {
      encoder = new HexEncoder();
    } else if ("Base64".equalsIgnoreCase(encoding) || "Base-64".equalsIgnoreCase(encoding)) {
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
    if ("Hex".equalsIgnoreCase(encoding)) {
      decoder = new HexDecoder();
    } else if ("Base64".equalsIgnoreCase(encoding) || "Base-64".equalsIgnoreCase(encoding)) {
      decoder = new Base64Decoder();
    } else {
      throw new IllegalArgumentException("Invalid encoding.");
    }
    return decoder;
  }
}
