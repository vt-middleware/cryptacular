/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.spec;


import org.cryptacular.codec.Base64Codec;
import org.cryptacular.codec.Codec;
import org.cryptacular.codec.HexCodec;

/**
 * Describes a string-to-byte encoding provides a means to create a new instance
 * of the coed via the {@link #newInstance()} method.
 *
 * @author  Middleware Services
 */
public class CodecSpec implements Spec<Codec>
{

  /** Hexadecimal encoding specification. */
  public static final CodecSpec HEX = new CodecSpec("Hex");

  /** Base64 encoding specification. */
  public static final CodecSpec BASE64 = new CodecSpec("Base64");


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


  /** @return  The name of the encoding, e.g. "Hex", "Base64". */
  @Override
  public String getAlgorithm()
  {
    return encoding;
  }


  /** {@inheritDoc} */
  @Override
  public Codec newInstance()
  {
    final Codec codec;
    if ("Hex".equalsIgnoreCase(encoding)) {
      codec = new HexCodec();
    } else if (
      "Base64".equalsIgnoreCase(encoding) ||
        "Base-64".equalsIgnoreCase(encoding)) {
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
