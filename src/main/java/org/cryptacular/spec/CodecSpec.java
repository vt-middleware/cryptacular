/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.spec;


import org.cryptacular.CryptUtil;
import org.cryptacular.codec.Base32Codec;
import org.cryptacular.codec.Base64Codec;
import org.cryptacular.codec.Codec;
import org.cryptacular.codec.HexCodec;

/**
 * Describes a string-to-byte encoding and provides a means to create a new instance of the codec via the {@link
 * #newInstance()} method.
 *
 * @author  Middleware Services
 */
public class CodecSpec implements Spec<Codec>
{

  /** Hexadecimal encoding specification. */
  public static final CodecSpec HEX = new CodecSpec("Hex");

  /** Lowercase hexadecimal encoding specification. */
  public static final CodecSpec HEX_LOWER = new CodecSpec("Hex-Lower");

  /** Uppercase hexadecimal encoding specification. */
  public static final CodecSpec HEX_UPPER = new CodecSpec("Hex-Upper");

  /** Base32 encoding specification. */
  public static final CodecSpec BASE32 = new CodecSpec("Base32");

  /** Unpadded base32 encoding specification. */
  public static final CodecSpec BASE32_UNPADDED = new CodecSpec("Base32-Unpadded");

  /** Base64 encoding specification. */
  public static final CodecSpec BASE64 = new CodecSpec("Base64");

  /** URL-safe base64 encoding specification. */
  public static final CodecSpec BASE64_URLSAFE = new CodecSpec("Base64-URLSafe");

  /** Unpadded base64 encoding specification. */
  public static final CodecSpec BASE64_UNPADDED = new CodecSpec("Base64-Unpadded");

  /** Name of encoding, e.g. "Hex", "Base64". */
  private final String encoding;


  /**
   * Creates a new instance of the given encoding.
   *
   * @param  encoding  Name of encoding.
   */
  public CodecSpec(final String encoding)
  {
    this.encoding = CryptUtil.assertNotNullArg(encoding, "Encoding cannot be null.");
  }


  /** @return  The name of the encoding, e.g. "Hex", "Base32", "Base64". */
  @Override
  public String getAlgorithm()
  {
    return encoding;
  }


  @Override
  public Codec newInstance()
  {
    final Codec codec;
    if ("Hex".equalsIgnoreCase(encoding) || "Hex-Lower".equalsIgnoreCase(encoding)) {
      codec = new HexCodec();
    } else if ("Hex-Upper".equalsIgnoreCase(encoding)) {
      codec = new HexCodec(true);
    } else if ("Base32".equalsIgnoreCase(encoding) || "Base-32".equalsIgnoreCase(encoding)) {
      codec = new Base32Codec();
    } else if ("Base32-Unpadded".equalsIgnoreCase(encoding)) {
      codec = new Base32Codec("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", true);
    } else if ("Base64".equalsIgnoreCase(encoding) || "Base-64".equalsIgnoreCase(encoding)) {
      codec = new Base64Codec();
    } else if ("Base64-URLSafe".equalsIgnoreCase(encoding)) {
      codec = new Base64Codec("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
    } else if ("Base64-Unpadded".equalsIgnoreCase(encoding)) {
      codec = new Base64Codec("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", false);
    } else {
      throw new IllegalArgumentException("Invalid encoding.");
    }
    return codec;
  }


  @Override
  public String toString()
  {
    return encoding;
  }
}
