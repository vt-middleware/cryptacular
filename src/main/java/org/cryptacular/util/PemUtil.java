/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.nio.CharBuffer;

/**
 * Utility class with helper methods for common PEM encoding operations.
 *
 * @author  Middleware Services
 */
public final class PemUtil
{

  /** Line length. */
  public static final int LINE_LENGTH = 64;

  /** PEM encoding header start string. */
  public static final String HEADER_BEGIN = "-----BEGIN";

  /** PEM encoding footer start string. */
  public static final String FOOTER_END = "-----END";

  /** Procedure type tag for PEM-encoded private key in OpenSSL format. */
  public static final String PROC_TYPE = "Proc-Type:";

  /** Decryption infor tag for PEM-encoded private key in OpenSSL format. */
  public static final String DEK_INFO = "DEK-Info:";


  /** Private constructor of utility class. */
  private PemUtil() {}


  /**
   * Determines whether the data in the given byte array is base64-encoded data
   * of PEM encoding. The determination is made using as little data from the
   * given array as necessary to make a reasonable determination about encoding.
   *
   * @param  data  Data to test for PEM encoding
   *
   * @return  True if data appears to be PEM encoded, false otherwise.
   */
  public static boolean isPem(final byte[] data)
  {
    final String start = new String(data, 0, 10, ByteUtil.ASCII_CHARSET).trim();
    if (!start.startsWith(HEADER_BEGIN) && !start.startsWith(PROC_TYPE)) {
      // Check all bytes in first line to make sure they are in the range
      // of base64 character set encoding
      for (int i = 0; i < LINE_LENGTH; i++) {
        if (!isBase64Char(data[i])) {
          // Last two bytes may be padding character '=' (61)
          if (i > LINE_LENGTH - 3) {
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
   * Determines whether the given byte represents an ASCII character in the
   * character set for base64 encoding.
   *
   * @param  b  Byte to test.
   *
   * @return  True if the byte represents an ASCII character in the set of valid
   * characters for base64 encoding, false otherwise. The padding character '='
   * is not considered valid since it may only appear at the end of a base64
   * encoded value.
   */
  public static boolean isBase64Char(final byte b)
  {
    return
      !(b < 47 || b > 122 || b > 57 && b < 65 || b > 90 && b < 97) || b == 43;
  }


  /**
   * Decodes a PEM-encoded cryptographic object into the raw bytes of its ASN.1
   * encoding. Header/footer data and metadata info, e.g. Proc-Type, are
   * ignored.
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
   * Decodes a PEM-encoded cryptographic object into the raw bytes of its ASN.1
   * encoding. Header/footer data and metadata info, e.g. Proc-Type, are
   * ignored.
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
      !(s.startsWith(HEADER_BEGIN) || s.startsWith(FOOTER_END) ||
          s.startsWith(PROC_TYPE) || s.startsWith(DEK_INFO) ||
          s.trim().length() == 0)) {
      output.put(line);
    }
    line.clear();
  }
}
