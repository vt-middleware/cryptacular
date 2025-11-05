/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.pem;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.util.io.pem.PemHeader;
import org.cryptacular.CryptUtil;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.CodecUtil;

/**
 * Parser to decode PEM data into a {@link PemObject}.
 *
 * @author Middleware Services
 */
final class PemParser
{

  /**
   * Parses the encoded bytes.
   *
   * @param encoded to parse
   *
   * @return new PEM object
   */
  PemObject parse(final byte[] encoded)
  {
    try {
      return parse(
        new BufferedReader(new InputStreamReader(new ByteArrayInputStream(encoded),  ByteUtil.ASCII_CHARSET)));
    } catch (IOException e) {
      throw new IllegalArgumentException("Could not parse PEM data", e);
    }
  }


  /**
   * Parses the supplied reader.
   *
   * @param reader to parse
   *
   * @return new PEM object
   */
  private PemObject parse(final BufferedReader reader)
    throws IOException
  {
    return parseInternal(reader, parseDescriptor(CryptUtil.assertNotNullArg(reader, "Reader cannot be null")));
  }

  /**
   * Reads the contents of the PEM data between the BEGIN and END markers by format specified.
   *
   * @param reader {@link BufferedReader} reader that contains the data to parse
   * @param descriptor Descriptor regarding the PEM encoded format (see {@link Descriptor})
   *
   * @return ExtendedPemObject instance with the data read
   *
   * @throws IOException In case of exceptions reading the buffer
   */
  private static PemObject parseInternal(final BufferedReader reader, final Descriptor descriptor)
    throws IOException
  {
    CryptUtil.assertNotNullArg(reader, "Reader cannot be null");
    CryptUtil.assertNotNullArg(descriptor, "Descriptor cannot be null");
    final List<PemHeader> headers = new ArrayList<>();
    int lineLength = -1;
    String line;
    final String endMarker = (descriptor.getFormat() == Format.RFC4716 ?
      Constants.RFC4716_ENCAPSULATION_END_MARKER :
      Constants.RFC1421_ENCAPSULATION_END_MARKER) + " " + descriptor.getType();
    final String beginMarker = (descriptor.getFormat() == Format.RFC4716 ?
      Constants.RFC4716_ENCAPSULATION_BEGIN_MARKER :
      Constants.RFC1421_ENCAPSULATION_BEGIN_MARKER) + " " + descriptor.getType();
    final String beginLine = reader.readLine();
    if (beginLine == null || !beginLine.startsWith(beginMarker)) {
      throw new IllegalArgumentException(String.format("%s not found in \"%s", beginMarker, beginLine));
    }
    final StringBuilder base64DataBuilder = new StringBuilder();
    while ((line = reader.readLine()) != null) {
      final PemHeader headerLine = parseHeader(reader, line, descriptor.getFormat());
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
      throw new IllegalArgumentException(endMarker + " not found");
    }
    assertLineLength(descriptor.getFormat(), lineLength);
    if (descriptor.getFormat().equals(Format.RFC7468)) {
      return new PemObject(descriptor, CodecUtil.b64(b64buffer));
    } else {
      return new PemObject(descriptor, headers, CodecUtil.b64(b64buffer));
    }
  }


  /**
   * Reads a header line which takes into account header types from RFC 1421 & RFC 4716
   *
   * @param reader {@link BufferedReader} instance instantiated with PEM file data
   * @param line Current line read in the buffer
   * @param format RFC format governing the PEM file
   *
   * @return {@link PemHeader} if a header value pair could be successfully read, otherwise null is returned
   *
   * @throws IOException In case of any read errors in the buffer
   */
  private static PemHeader parseHeader(final BufferedReader reader, final String line, final Format format)
    throws IOException
  {
    if (line.contains(":")) {
      final int index = line.indexOf(':');
      String specifier = line.substring(0, index);
      String value = line.substring(index + 1);
      if (format == Format.RFC4716) {
        while (value.charAt(value.length() - 1) == '\\') {
          value = value.substring(0, value.length() - 1);
          final String l = reader.readLine();
          if (l == null) {
            break;
          }
          value += l;
        }
      } else if (format == Format.RFC1421) {
        if (specifier.startsWith("X-")) {
          //Remove X- as per RFC 1421 Section 4.6
          specifier = specifier.substring(2);
        }
        final StringBuilder sb = new StringBuilder(value);
        String nextLine = peekNextLine(reader, Constants.RFC1421_MAX_LINE_LENGTH);
        while (nextLine != null && nextLine.startsWith(" ")) {
          final String l = reader.readLine();
          if (l == null) {
            break;
          }
          sb.append(l.trim());
          nextLine = peekNextLine(reader, Constants.RFC1421_MAX_LINE_LENGTH);
        }
        value = sb.toString();
      }
      value = value.trim();
      if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
        //Remove the quotes as suggested by RFC 4716
        value = value.substring(1, value.length() - 1);
      }
      return new PemHeader(specifier, value);
    } else {
      return null;
    }
  }


  /**
   * Throws an exception if the data contains rules restricted by their respective RFCs.
   *
   * @param format Format which governs this PEM data
   * @param maxLineLength maximum length in b64buffer lines prior to concatenation
   *
   * @throws IllegalArgumentException In case of a constraint violation
   */
  private static void assertLineLength(final Format format, final int maxLineLength)
    throws IllegalArgumentException
  {
    switch (format) {
    case RFC4716:
      if (maxLineLength > Constants.RFC4716_MAX_LINE_LENGTH) {
        throw new IllegalArgumentException(
          "Malformed RFC 4716 type PEM data (b64 lines longer than maximum allowed length)");
      }
      break;
    case RFC7468:
      if (maxLineLength > Constants.RFC7468_MAX_LINE_LENGTH) {
        throw new IllegalArgumentException(
          "Malformed RFC 7468 type PEM data (b64 lines longer than maximum allowed length)");
      }
      break;
    case RFC1421:
      if (maxLineLength > Constants.RFC1421_MAX_LINE_LENGTH) {
        throw new IllegalArgumentException(
          "Malformed RFC 1421 type PEM data (b64 lines longer than maximum allowed length)");
      }
      break;
    default:
      break;
    }
  }


  /**
   * Determines the RFC format governing the PEM file in the reader and constructs a
   * {@link Descriptor} accordingly.
   *
   * @param reader {@link BufferedReader} instance instantiated with PEM file data
   *
   * @return Populated Descriptor instance or null if the descriptor could not be parsed
   *
   * @throws IOException In case of exceptions reading the buffer, or malformed PEM data
   */
  private static Descriptor parseDescriptor(final BufferedReader reader)
    throws IOException
  {
    final Format format;
    final String explanatoryText = readExplanatoryText(reader);
    final String firstPemLine = peekNextLine(reader, Constants.RFC2440_MAX_LINE_LENGTH);
    if (firstPemLine != null) {
      final String pemType;
      final boolean isRFC4716Markers =
        firstPemLine.startsWith(Constants.RFC4716_ENCAPSULATION_BEGIN_MARKER);
      pemType = getPemType(isRFC4716Markers, firstPemLine);
      if (pemType != null) {
        format = getFormat(explanatoryText, pemType, isRFC4716Markers);
        return new Descriptor(format, explanatoryText, pemType);
      }
    }
    return null;
  }


  /**
   * Determines the RFC governing the format of the PEM file based of the parameters provided.
   *
   * @param explanatoryText Explanatory text is only allowed in RFC 7468
   * @param pemType All types begin with PGP in RFC 2440
   * @param isRFC4716Markers It either starts with four dashes (RFC RFC4716) or five (RFC 1421)
   *
   * @return Format determined (see {@link Descriptor#getFormat()})
   */
  private static Format getFormat(final String explanatoryText, final String pemType, final boolean isRFC4716Markers)
  {
    final Format format;
    if (!explanatoryText.isEmpty()) {
      format = Format.RFC7468;
    } else if (pemType.startsWith("PGP")) {
      format = Format.RFC2440;
    } else if (isRFC4716Markers) {
      format = Format.RFC4716;
    } else {
      format = Format.RFC1421;
    }
    return format;
  }


  /**
   * Returns the message type based on the marker format provided.
   *
   * @param isRFC4716Markers isRFC4716Markers (either four dashes and a space, or five dashes)
   * @param firstPemLine First line of the PEM file
   *
   * @return PEM type or null if the type cannot be determined
   */
  private static String getPemType(final boolean isRFC4716Markers, final String firstPemLine)
  {
    if (isRFC4716Markers) {
      final int index = firstPemLine.indexOf(
        Constants.RFC4716_ENCAPSULATION_MARKER, Constants.RFC4716_ENCAPSULATION_BEGIN_MARKER.length());
      if (Constants.RFC4716_ENCAPSULATION_BEGIN_MARKER.length() <= index && index <= firstPemLine.length()) {
        return firstPemLine.substring(Constants.RFC4716_ENCAPSULATION_BEGIN_MARKER.length(), index).trim();
      }
    } else {
      final int index = firstPemLine.indexOf(
        Constants.RFC1421_ENCAPSULATION_MARKER, Constants.RFC1421_ENCAPSULATION_BEGIN_MARKER.length());
      if (Constants.RFC1421_ENCAPSULATION_BEGIN_MARKER.length() <= index && index <= firstPemLine.length()) {
        return firstPemLine.substring(Constants.RFC1421_ENCAPSULATION_BEGIN_MARKER.length(), index).trim();
      }
    }
    return null;
  }


  /**
   * Reads the explanatory text as described by RFC 7468 5.2. Method simply reads a line until a known header marker
   * is found.
   *
   * @param reader only the explanatory text will actually be read off the reader
   *
   * @return Explanatory text
   *
   * @throws IOException In case of errors reading the buffer
   */
  private static String readExplanatoryText(final BufferedReader reader)
    throws IOException
  {
    final StringBuilder explanatoryTextBuilder = new StringBuilder(0);
    String line = peekNextLine(reader, Constants.RFC2440_MAX_LINE_LENGTH);
    while (line != null && !(line.startsWith(Constants.RFC1421_ENCAPSULATION_BEGIN_MARKER) ||
      line.startsWith(Constants.RFC4716_ENCAPSULATION_BEGIN_MARKER))) {
      line = reader.readLine();
      //Read "explanatory text" as defined by RFC 7468
      if (line != null && !line.isEmpty()) {
        explanatoryTextBuilder.append(line).append("\n");
      }
      line = peekNextLine(reader, Constants.RFC2440_MAX_LINE_LENGTH);
    }
    return explanatoryTextBuilder.toString();
  }


  /**
   * Reads the next line in a {@link BufferedReader} instance without consuming it from the buffer
   *
   * @param reader {@link BufferedReader} instance
   * @param maximumReadLength Maximum number of characters to peek
   *
   * @return Next line
   *
   * @throws IOException In case of errors reading the buffer
   */
  private static String peekNextLine(final BufferedReader reader, final int maximumReadLength)
    throws IOException
  {
    reader.mark(maximumReadLength);
    final String nextLine = reader.readLine();
    reader.reset();
    return nextLine;
  }
}
