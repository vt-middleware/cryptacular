/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.util.io.pem.PemHeader;
import org.cryptacular.codec.Base64Codec;
import org.cryptacular.io.pem.EncapsulatedPemObject;

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
      return readPem(StreamUtil.makeBufferedReader(data)) != null;
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
    return readPem(StreamUtil.makeBufferedReader(pem));
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
   * Determines the RFC format governing the PEM file in the Reader as well as
   * populating a new ExtendedPemObject instance from the data.  Both RFC7468 and RFC4716 PEM formats
   * may be read using this method
   * @param reader {@link BufferedReader} instance instantiated with PEM file data
   * @return Populated ExtendedPemObject instance
   * @throws IOException In case of exceptions reading the buffer, or malformed PEM data
   */
  public static EncapsulatedPemObject readPem(final BufferedReader reader)
          throws IOException
  {
    final EncapsulatedPemObject.Format foundFormat;
    final StringBuilder explanatoryTextBuilder = new StringBuilder(256);
    final List<PemHeader> headers = new ArrayList<>();
    String line = reader.readLine();
    while (line != null && !(line.startsWith(EncapsulatedPemObject.ENCAPSULATION_BEGIN_MARKER) ||
            line.startsWith(EncapsulatedPemObject.RFC4716_ENCAPSULATION_BEGIN_MARKER))) {
      //Read "explanatory text" as defined by RFC 7468
      if (line.length() > 0) {
        explanatoryTextBuilder.append(line).append("\n");
      }
      line = reader.readLine();
    }
    if (line != null) {
      final boolean isRFC4716 = line.startsWith(EncapsulatedPemObject.RFC4716_ENCAPSULATION_BEGIN_MARKER);
      line = line.substring(isRFC4716 ?
                      EncapsulatedPemObject.RFC4716_ENCAPSULATION_BEGIN_MARKER.length() :
                      EncapsulatedPemObject.ENCAPSULATION_BEGIN_MARKER.length());
      final int index = line.indexOf('-');
      final String type = line.substring(0, index).trim();
      if (isRFC4716) {
        foundFormat = EncapsulatedPemObject.Format.RFC4716;
      } else if (explanatoryTextBuilder.length() > 0) {
        foundFormat = EncapsulatedPemObject.Format.RFC7468;
      } else {
        foundFormat = EncapsulatedPemObject.Format.RFC1421;
      }
      if (index > 0) {
        return parsePem(reader, type, foundFormat, headers, explanatoryTextBuilder.toString());
      }
    }
    return null;
  }


  /**
   * Reads the contents of the PEM data between the BEGIN and END markers per its respective RFC
   * @param reader {@link BufferedReader} instance instantiated with PEM file data
   * @param type The type of this data
   * @param rfcFormat RFC format governing the PEM structure
   * @param headers Headers container
   * @param explanatoryText "explanatory text" as defined by RFC 7468
   * @return ExtendedPemObject instance with the data read
   * @throws IOException In case of exceptions reading the buffer, or malformed PEM data
   */
  private static EncapsulatedPemObject parsePem(
          final BufferedReader reader,
          final String type,
          final EncapsulatedPemObject.Format rfcFormat,
          final List<PemHeader> headers,
          final String explanatoryText)
          throws IOException
  {
    int lineLength = -1;
    String line;
    final String endMarker = (rfcFormat == EncapsulatedPemObject.Format.RFC4716 ?
            EncapsulatedPemObject.RFC4716_ENCAPSULATION_END_MARKER :
            EncapsulatedPemObject.ENCAPSULATION_END_MARKER) + " " + type;
    final StringBuilder base64DataBuilder = new StringBuilder();
    while ((line = reader.readLine()) != null) {
      final PemHeader headerLine = readPemHeader(reader, line, rfcFormat);
      if (headerLine != null) {
        headers.add(headerLine);
        continue;
      }
      lineLength = Math.max(lineLength, line.length());
      if (line.contains(endMarker)) {
        break;
      }
      base64DataBuilder.append(line.trim());
    }
    final String b64buffer = base64DataBuilder.toString();
    if (line == null) {
      throw new IOException(endMarker + " not found");
    }
    enforceLineLengthRestrictions(rfcFormat, lineLength);
    if (rfcFormat.equals(EncapsulatedPemObject.Format.RFC7468)) {
      return new EncapsulatedPemObject(type, CodecUtil.b64(b64buffer), explanatoryText);
    } else {
      return new EncapsulatedPemObject(type, headers, CodecUtil.b64(b64buffer), rfcFormat);
    }
  }


  /**
   * Reads a header line which takes into account header types from RFC 1421 & RFC 4716
   * @param reader {@link BufferedReader} instance instantiated with PEM file data
   * @param line Current line read in the buffer
   * @param rfcFormat RFC format governing the PEM file
   * @return {@link PemHeader} if a header value pair could be successfully read, otherwise null is returned
   * @throws IOException In case of any read errors in the buffer
   */
  private static PemHeader readPemHeader(
          final BufferedReader reader,
          final String line,
          final EncapsulatedPemObject.Format rfcFormat) throws IOException
  {
    if (line.contains(":")) {
      final int index = line.indexOf(':');
      String hdr = line.substring(0, index);
      String value = line.substring(index + 1);
      if (rfcFormat == EncapsulatedPemObject.Format.RFC4716) {
        while (value.endsWith("\\")) {
          value = value.substring(0, value.length() - 1);
          value += reader.readLine();
        }
      } else if (rfcFormat == EncapsulatedPemObject.Format.RFC1421) {
        if (hdr.startsWith("X-")) {
          //Chomp X- as per RFC 1421 Section 4.6
          hdr = hdr.substring(2);
        }
        String nextLine = StreamUtil.peekNextLine(reader, EncapsulatedPemObject.RFC1421_MAX_LINE_LENGTH);
        while (nextLine.startsWith(" ")) {
          value += reader.readLine().trim();
          nextLine = StreamUtil.peekNextLine(reader, EncapsulatedPemObject.RFC1421_MAX_LINE_LENGTH);
        }
      }
      value = value.trim();
      if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
        //chomp the quotes as suggested by RFC 4716
        value = value.substring(1, value.length() - 1);
      }
      return new PemHeader(hdr, value);
    } else {
      return null;
    }
  }


  /**
   * Throws an exception if the data contains rules restricted by their respective RFCs.
   *
   * @param rfcFormat Format which governs this PEM data
   * @param maxLineLength maximum length in b64buffer lines prior to concatenation
   * @throws IllegalArgumentException In case of a constraint violation
   */
  private static void enforceLineLengthRestrictions(
          final EncapsulatedPemObject.Format rfcFormat,
          final int maxLineLength) throws IllegalArgumentException
  {
    switch (rfcFormat) {
    case RFC4716:
      if (maxLineLength > EncapsulatedPemObject.RFC4716_MAX_LINE_LENGTH) {
        throw new IllegalArgumentException(
                "Malformed RFC 4716 type PEM data (b64 lines longer than maximum allowed length)");
      }
      break;
    case RFC7468:
      if (maxLineLength > EncapsulatedPemObject.RFC7468_MAX_LINE_LENGTH) {
        throw new IllegalArgumentException(
                "Malformed RFC 7468 type PEM data (b64 lines longer than maximum allowed length)");
      }
      break;
    case RFC1421:
      if (maxLineLength > EncapsulatedPemObject.RFC1421_MAX_LINE_LENGTH) {
        throw new IllegalArgumentException(
                "Malformed RFC 1421 type PEM data (b64 lines longer than maximum allowed length)");
      }
      break;
    default:
      break;
    }
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
