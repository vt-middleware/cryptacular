/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.io.pem;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemHeader;
import org.cryptacular.io.pem.Pem.Format;

/**
 * A {@link BufferedReader} extension which populates PEM data ({@link Pem}) governed by multiple RFCs.
 *
 * @author Middleware Services
 */
public class PemReader
        extends BufferedReader
{

  /**
   * Default constructor, yields to super
   * @param reader Reader instance to buffer
   */
  public PemReader(final Reader reader)
  {
    super(reader);
  }

  /**
   * Determines the RFC format governing the PEM file in the Reader as well as
   * populating a new ExtendedPemObject instance from the data.  Both RFC7468 and RFC4716 PEM formats
   * may be read using this method
   * @return Populated ExtendedPemObject instance
   * @throws IOException In case of exceptions reading the buffer, or malformed PEM data
   */
  public Pem readPemObject()
          throws IOException
  {
    final Format foundFormat;
    final StringBuilder explanatoryTextBuilder = new StringBuilder(256);
    final List<PemHeader> headers = new ArrayList<>();
    String line = readLine();
    while (line != null && !(line.startsWith(Pem.ENCAPSULATION_BEGIN_MARKER) ||
            line.startsWith(Pem.RFC4716_ENCAPSULATION_BEGIN_MARKER))) {
      //Read "explanatory text" as defined by RFC 7468
      if (line.length() > 0) {
        explanatoryTextBuilder.append(line).append("\n");
      }
      line = readLine();
    }
    if (line != null) {
      final boolean isRFC4716 = line.startsWith(Pem.RFC4716_ENCAPSULATION_BEGIN_MARKER);
      line = line.substring(isRFC4716 ?
                      Pem.RFC4716_ENCAPSULATION_BEGIN_MARKER.length() :
                      Pem.ENCAPSULATION_BEGIN_MARKER.length());
      final int index = line.indexOf('-');
      final String type = line.substring(0, index).trim();
      if (isRFC4716) {
        foundFormat = Format.RFC4716;
      } else if (explanatoryTextBuilder.length() > 0) {
        foundFormat = Format.RFC7468;
      } else {
        foundFormat = Format.RFC1421;
      }
      if (index > 0) {
        return loadObject(type, foundFormat, headers, explanatoryTextBuilder.toString());
      }
    }
    return null;
  }

  /**
   * Reads the contents of the PEM data between the BEGIN and END markers per its respective RFC
   * @param type The type of this data
   * @param rfcFormat RFC format governing the PEM structure
   * @param headers Headers container
   * @param explanatoryText "explanatory text" as defined by RFC 7468
   * @return ExtendedPemObject instance with the data read
   * @throws IOException In case of exceptions reading the buffer, or malformed PEM data
   */
  private Pem loadObject(final String type,
          final Format rfcFormat,
          final List<PemHeader> headers,
          final String explanatoryText)
          throws IOException
  {
    int lineLength = -1;
    String line;
    final String endMarker = (rfcFormat == Format.RFC4716 ?
            Pem.RFC4716_ENCAPSULATION_END_MARKER :
            Pem.ENCAPSULATION_END_MARKER) + " " + type;
    final StringBuilder base64DataBuilder = new StringBuilder();
    while ((line = readLine()) != null) {
      final PemHeader headerLine = readPemHeader(line, rfcFormat);
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
    if (rfcFormat.equals(Pem.Format.RFC7468)) {
      return new Pem(type, Base64.decode(b64buffer), explanatoryText);
    } else {
      return new Pem(type, headers, Base64.decode(b64buffer), rfcFormat);
    }
  }

  /**
   * Reads a header line which takes into account header types from RFC 1421 & RFC 4716
   * @param line Current line read in the buffer
   * @param rfcFormat RFC format governing the PEM file
   * @return {@link PemHeader} if a header value pair could be successfully read, otherwise null is returned
   * @throws IOException In case of any read errors in the buffer
   */
  private PemHeader readPemHeader(final String line, final Format rfcFormat) throws IOException
  {
    if (line.contains(":")) {
      final int index = line.indexOf(':');
      String hdr = line.substring(0, index);
      String value = line.substring(index + 1);
      if (rfcFormat == Format.RFC4716) {
        while (value.endsWith("\\")) {
          value = value.substring(0, value.length() - 1);
          value += readLine();
        }
      } else if (rfcFormat == Format.RFC1421) {
        if (hdr.startsWith("X-")) {
          //Chomp X- as per RFC 1421 Section 4.6
          hdr = hdr.substring(2);
        }
        String nextLine = peekNextLine(Pem.RFC1421_MAX_LINE_LENGTH);
        while (nextLine.startsWith(" ")) {
          value += readLine().trim();
          nextLine = peekNextLine(Pem.RFC1421_MAX_LINE_LENGTH);
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
   * Reads the next line in the stream without consuming it from the buffer
   * @param maximumReadLength Maximum number of characters to peek
   * @return Next line
   * @throws IOException In case of errors reading the buffer
   */
  private String peekNextLine(final int maximumReadLength) throws IOException
  {
    mark(maximumReadLength);
    final String nextLine = readLine();
    reset();
    return nextLine;
  }

  /**
   * Throws an exception if the data contains rules restricted by their respective RFCs.
   *
   * @param rfcFormat Format which governs this PEM data
   * @param maxLineLength maximum length in b64buffer lines prior to concatenation
   * @throws IllegalArgumentException In case of a constraint violation
   */
  private void enforceLineLengthRestrictions(
          final Format rfcFormat,
          final int maxLineLength) throws IllegalArgumentException
  {
    switch (rfcFormat) {
    case RFC4716:
      if (maxLineLength > Pem.RFC4716_MAX_LINE_LENGTH) {
        throw new IllegalArgumentException(
                "Malformed RFC 4716 type PEM data (b64 lines longer than maximum allowed length)");
      }
      break;
    case RFC7468:
      if (maxLineLength > Pem.RFC7468_MAX_LINE_LENGTH) {
        throw new IllegalArgumentException(
                "Malformed RFC 7468 type PEM data (b64 lines longer than maximum allowed length)");
      }
      break;
    case RFC1421:
      if (maxLineLength > Pem.RFC1421_MAX_LINE_LENGTH) {
        throw new IllegalArgumentException(
                "Malformed RFC 1421 type PEM data (b64 lines longer than maximum allowed length)");
      }
      break;
    default:
      break;
    }
  }
}
