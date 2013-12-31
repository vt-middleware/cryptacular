package org.cryptosis.spec;

import org.cryptosis.codec.*;

/**
 * Describes a string-to-byte encoding with methods to instantiate the appropriate {@link Encoder}/{@link Decoder}.
 *
 * @author Marvin S. Addison
 */
public class CodecSpec implements Spec<Codec>
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
  public String getAlgorithm()
  {
    return encoding;
  }


  /** {@inheritDoc} */
  public Codec newInstance()
  {
    final Codec codec;
    if ("Hex".equalsIgnoreCase(encoding)) {
      codec = new HexCodec();
    } else if ("Base64".equalsIgnoreCase(encoding) || "Base-64".equalsIgnoreCase(encoding)) {
      codec = new Base64Codec();
    } else {
      throw new IllegalArgumentException("Invalid encoding.");
    }
    return codec;
  }


  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    return encoding;
  }
}
