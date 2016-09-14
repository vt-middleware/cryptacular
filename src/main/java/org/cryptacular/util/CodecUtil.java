/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

import org.cryptacular.EncodingException;
import org.cryptacular.codec.Base32Decoder;
import org.cryptacular.codec.Base32Encoder;
import org.cryptacular.codec.Base64Codec;
import org.cryptacular.codec.Base64Decoder;
import org.cryptacular.codec.Base64Encoder;
import org.cryptacular.codec.Decoder;
import org.cryptacular.codec.Encoder;
import org.cryptacular.codec.HexDecoder;
import org.cryptacular.codec.HexEncoder;


/**
 * Utility class for common encoding conversions.
 *
 * @author  Middleware Services
 */
public final class CodecUtil
{

  /** Private constructor of utility class. */
  private CodecUtil() {}


  /**
   * Encodes raw bytes to the equivalent hexadecimal encoded string.
   *
   * @param  raw  Raw bytes to encode.
   *
   * @return  Hexadecimal encoded string.
   *
   * @throws  EncodingException  on encoding errors.
   */
  public static String hex(final byte[] raw) throws EncodingException
  {
    return encode(new HexEncoder(), raw);
  }

  /**
   * Determines whether the given {@link CharSequence} is base64 encoded data
   *
   * @param  encoded  {@link CharSequence} to test
   *
   * @return  True if the byte represents an ASCII character in the set of valid characters for base64 encoding.
   */
  public static boolean isB64(final CharSequence encoded)
  {
    if (encoded == null) {
      return false;
    }
    boolean isBase64 = true;
    final byte[] bytes = encoded.toString().getBytes();
    for (int i = 0; i < bytes.length; i++) {
      if (!Base64Codec.isBase64Char(bytes[i])) {
        if (i > bytes.length - 3) {
          if (bytes[i] != 61) {
            isBase64 = false;
            break;
          }
        } else {
          isBase64 = false;
          break;
        }
      }
    }
    return isBase64;
  }

  /**
   * Encodes raw bytes to the equivalent hexadecimal encoded string with optional delimiting of output.
   *
   * @param  raw  Raw bytes to encode.
   * @param  delimit  True to delimit every two characters (i.e. every byte) of output with ':' character, false
   *                  otherwise.
   *
   * @return  Hexadecimal encoded string.
   *
   * @throws  EncodingException  on encoding errors.
   */
  public static String hex(final byte[] raw, final boolean delimit) throws EncodingException
  {
    return encode(new HexEncoder(delimit), raw);
  }


  /**
   * Decodes a hexadecimal encoded string to raw bytes.
   *
   * @param  encoded  Hex encoded character data.
   *
   * @return  Raw bytes of hex string.
   *
   * @throws  EncodingException  on decoding errors.
   */
  public static byte[] hex(final CharSequence encoded) throws EncodingException
  {
    return decode(new HexDecoder(), encoded);
  }


  /**
   * Encodes bytes into base 64-encoded string.
   *
   * @param  raw  Raw bytes to encode.
   *
   * @return  Base64-encoded string.
   *
   * @throws  EncodingException  on encoding errors.
   */
  public static String b64(final byte[] raw) throws EncodingException
  {
    return encode(new Base64Encoder(), raw);
  }


  /**
   * Decodes a base64-encoded string into raw bytes.
   *
   * @param  encoded  Base64-encoded character data.
   *
   * @return  Base64-decoded bytes.
   *
   * @throws  EncodingException  on decoding errors.
   */
  public static byte[] b64(final CharSequence encoded) throws EncodingException
  {
    return decode(new Base64Decoder(), encoded);
  }


  /**
   * Encodes bytes into base64-encoded string.
   *
   * @param  raw  Raw bytes to encode.
   * @param  lineLength  Length of each base64-encoded line in output.
   *
   * @return  Base64-encoded string.
   *
   * @throws  EncodingException  on encoding errors.
   */
  public static String b64(final byte[] raw, final int lineLength) throws EncodingException
  {
    return encode(new Base64Encoder(lineLength), raw);
  }


  /**
   * Encodes bytes into base 32-encoded string.
   *
   * @param  raw  Raw bytes to encode.
   *
   * @return  Base32-encoded string.
   *
   * @throws  EncodingException  on encoding errors.
   */
  public static String b32(final byte[] raw) throws EncodingException
  {
    return encode(new Base32Encoder(), raw);
  }


  /**
   * Decodes a base32-encoded string into raw bytes.
   *
   * @param  encoded  Base32-encoded character data.
   *
   * @return  Base64-decoded bytes.
   *
   * @throws  EncodingException  on decoding errors.
   */
  public static byte[] b32(final CharSequence encoded) throws EncodingException
  {
    return decode(new Base32Decoder(), encoded);
  }


  /**
   * Encodes bytes into base32-encoded string.
   *
   * @param  raw  Raw bytes to encode.
   * @param  lineLength  Length of each base32-encoded line in output.
   *
   * @return  Base32-encoded string.
   *
   * @throws  EncodingException  on encoding errors.
   */
  public static String b32(final byte[] raw, final int lineLength) throws EncodingException
  {
    return encode(new Base32Encoder(lineLength), raw);
  }


  /**
   * Encodes raw bytes using the given encoder.
   *
   * @param  encoder  Encoder to perform byte-to-char conversion.
   * @param  raw  Raw bytes to encode.
   *
   * @return  Encoded data as a string.
   *
   * @throws  EncodingException  on encoding errors.
   */
  public static String encode(final Encoder encoder, final byte[] raw) throws EncodingException
  {
    final CharBuffer output = CharBuffer.allocate(encoder.outputSize(raw.length));
    encoder.encode(ByteBuffer.wrap(raw), output);
    encoder.finalize(output);
    return output.flip().toString();
  }


  /**
   * Decodes the given encoded data using the given char-to-byte decoder.
   *
   * @param  decoder  Decoder to perform char-to-byte conversion.
   * @param  encoded  Encoded character data.
   *
   * @return  Decoded data as raw bytes.
   *
   * @throws  EncodingException  on decoding errors.
   */
  public static byte[] decode(final Decoder decoder, final CharSequence encoded) throws EncodingException
  {
    final ByteBuffer output = ByteBuffer.allocate(decoder.outputSize(encoded.length()));
    decoder.decode(CharBuffer.wrap(encoded), output);
    decoder.finalize(output);
    output.flip();
    return ByteUtil.toArray(output);
  }
}
