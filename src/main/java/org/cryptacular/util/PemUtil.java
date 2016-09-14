/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.io.IOException;
import java.nio.CharBuffer;
import org.cryptacular.codec.Base64Codec;
import org.cryptacular.io.pem.EncapsulatedPemObject;
import org.cryptacular.io.pem.PemReader;

/**
 * Utility class with helper methods for common PEM encoding operations.
 *
 * @author  Middleware Services
 */
public final class PemUtil
{

  /**
   * Line length.
   * @deprecated Use {@link EncapsulatedPemObject#RFC1421_MAX_LINE_LENGTH}.
   */
  @Deprecated
  public static final int LINE_LENGTH = EncapsulatedPemObject.RFC1421_MAX_LINE_LENGTH;

  /**
   * PEM encoding header start string.
   * @deprecated Use {@link EncapsulatedPemObject#ENCAPSULATION_BEGIN_MARKER}.
   */
  @Deprecated
  public static final String HEADER_BEGIN = EncapsulatedPemObject.ENCAPSULATION_BEGIN_MARKER;

  /**
   * PEM encoding footer start string.
   * @deprecated Use {@link EncapsulatedPemObject#ENCAPSULATION_END_MARKER}.
   */
  @Deprecated
  public static final String FOOTER_END = EncapsulatedPemObject.ENCAPSULATION_END_MARKER;

  /**
   * Procedure type tag for PEM-encoded private key in OpenSSL format.
   * @deprecated Use {@link EncapsulatedPemObject#RFC1421_HEADER_TAG_PROC_TYPE}.
   */
  @Deprecated
  public static final String PROC_TYPE = EncapsulatedPemObject.RFC1421_HEADER_TAG_PROC_TYPE + ":";

  /**
   * Decryption information tag for PEM-encoded private key in OpenSSL format.
   * @deprecated Use {@link EncapsulatedPemObject#RFC1421_HEADER_TAG_DEK_INFO}.
   */
  @Deprecated
  public static final String DEK_INFO = EncapsulatedPemObject.RFC1421_HEADER_TAG_DEK_INFO + ":";

  /** Private constructor of utility class. */
  private PemUtil() {}

  /**
   * Determines whether the data in the given byte array is base64-encoded data of PEM encoding.
   * It very loosely checks to see if the data has Base64 encoded characters.
   *
   * @param  data  Data to test for PEM encoding
   *
   * @return  True if data appears to be PEM encoded, false otherwise.
   */
  public static boolean isPem(final byte[] data)
  {
    final String start = new String(data, 0, 10, ByteUtil.ASCII_CHARSET).trim();
    if (!start.startsWith(EncapsulatedPemObject.ENCAPSULATION_BEGIN_MARKER) &&
            !start.startsWith(EncapsulatedPemObject.RFC1421_HEADER_TAG_PROC_TYPE)) {
      // Check all bytes in first line to make sure they are in the range
      // of base64 character set encoding
      for (int i = 0; i < EncapsulatedPemObject.RFC7468_MAX_LINE_LENGTH; i++) {
        if (!Base64Codec.isBase64Char(data[i])) {
          // Last two bytes may be padding character '=' (61)
          if (i > EncapsulatedPemObject.RFC7468_MAX_LINE_LENGTH - 3) {
            if (data[i] != 61) {
              return false;
            }
          } else {
            return false;
          }
        }
      }
    }
    return true;
  }

  /**
   * Determines whether the data in the given byte array is a valid PEM file.
   *
   * @param  data  Data to test for PEM encoding
   *
   * @return  True if data appears to be PEM encoded, false otherwise.
   */
  public static boolean isValidPem(final byte[] data)
  {
    try {
      return new PemReader(StreamUtil.makeReader(data)).readPemObject() != null;
    } catch (IOException ex) {
      return false;
    }
  }

  /**
   * Determines whether the data in the given byte array is base64-encoded data of PEM encoding
   * as defined by RFC 4716.
   *
   * @param  data  Data to test for PEM encoding
   *
   * @return  True if data appears to be PEM encoded, false otherwise.
   */
  public static boolean isRFC4716Pem(final byte[] data)
  {
    final String start = new String(data, 0, EncapsulatedPemObject.RFC4716_ENCAPSULATION_BEGIN_MARKER.length() + 5,
            ByteUtil.ASCII_CHARSET).trim();
    return start.startsWith(EncapsulatedPemObject.RFC4716_ENCAPSULATION_BEGIN_MARKER);
  }

 /**
   * Determines whether the given byte represents an ASCII character in the character set for base64 encoding.
   *
   * @param  b  Byte to test.
   *
   * @deprecated Use {@link Base64Codec#isBase64Char(byte)}
   * @return  True if the byte represents an ASCII character in the set of valid characters for base64 encoding, false
   *          otherwise. The padding character '=' is not considered valid since it may only appear at the end of a
   *          base64 encoded value.
   */
  @Deprecated
  public static boolean isBase64Char(final byte b)
  {
    return Base64Codec.isBase64Char(b);
  }

  /**
   * Decodes a PEM-encoded cryptographic object into {@link EncapsulatedPemObject} instance.
   *
   * @param  pem  Bytes of PEM-encoded data to decode.
   *
   * @return  {@link EncapsulatedPemObject} instance
   * @throws java.io.IOException If there are errors reading the PEM file data
   */
  public static EncapsulatedPemObject decodeToPem(final byte[] pem) throws IOException
  {
    return new PemReader(StreamUtil.makeReader(pem)).readPemObject();
  }

  /**
   * Decodes a PEM-encoded cryptographic object into the raw bytes of its ASN.1 encoding. Header/footer data and
   * metadata info, e.g. Proc-Type, are ignored.
   *
   * @param  pem  Bytes of PEM-encoded data to decode.
   *
   * @return  ASN.1 encoded bytes.
   */
  public static byte[] decode(final byte[] pem)
  {
    return decode(new String(pem, ByteUtil.ASCII_CHARSET));
  }


  /**
   * Decodes a PEM-encoded cryptographic object into the raw bytes of its ASN.1 encoding. Header/footer data and
   * metadata info, e.g. Proc-Type, are ignored.
   *
   * @param  pem  PEM-encoded data to decode.
   *
   * @return  ASN.1 encoded bytes.
   */
  public static byte[] decode(final String pem)
  {
    final CharBuffer line = CharBuffer.allocate(128);
    final CharBuffer input = CharBuffer.wrap(pem);
    final CharBuffer output = CharBuffer.allocate(pem.length());
    char current;
    while (input.hasRemaining()) {
      current = input.get();
      if (current == '\r') {
        // Assume CRLF line endings, so discard next char before writing line
        input.get();
        writeLine(line, output);
      } else if (current == '\n') {
        writeLine(line, output);
      } else {
        line.put(current);
      }
    }
    if (line.hasRemaining()) {
      writeLine(line, output);
    }
    output.flip();
    return CodecUtil.b64(output);
  }


  /**
   * Copies a non-header line to the output buffer.
   *
   * @param  line  Line to consider writing.
   * @param  output  Output buffer.
   */
  private static void writeLine(final CharBuffer line, final CharBuffer output)
  {
    final String s = line.flip().toString();
    if (
      !(s.startsWith(EncapsulatedPemObject.ENCAPSULATION_BEGIN_MARKER) ||
            s.startsWith(EncapsulatedPemObject.ENCAPSULATION_END_MARKER) ||
            EncapsulatedPemObject.RFC1421_HEADERS.stream().anyMatch(predicate-> s.startsWith(predicate)) ||
          s.trim().length() == 0)) {
      output.put(line);
    }
    line.clear();
  }
}
