package org.cryptosis.codec;

import org.cryptosis.ByteUtil;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * Utility class for common encoding conversions.
 *
 * @author Marvin S. Addison
 */
public final class Codex
{
  /** Private constructor of utility class. */
  private Codex() {}


  public static byte[] hex(final String encoded)
  {
    return decode(new HexDecoder(), encoded);
  }


  public static String hex(final byte[] raw)
  {
    return encode(new HexEncoder(), raw);
  }


  public static byte[] b64(final String encoded)
  {
    return decode(new Base64Decoder(), encoded);
  }


  public static String b64(final byte[] raw)
  {
    return encode(new Base64Encoder(), raw);
  }


  public static String encode(final Encoder encoder, final byte[] raw)
  {
    final CharBuffer output = CharBuffer.allocate(encoder.outputSize(raw.length));
    encoder.encode(ByteBuffer.wrap(raw), output);
    encoder.finalize(output);
    return output.toString();
  }


  public static byte[] decode(final Decoder decoder, final String encoded)
  {
    final ByteBuffer output = ByteBuffer.allocate(decoder.outputSize(encoded.length()));
    decoder.decode(CharBuffer.wrap(encoded), output);
    decoder.finalize(output);
    return ByteUtil.toArray(output);
  }
}
