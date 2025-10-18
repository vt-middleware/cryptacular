/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.io.pem;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.util.io.pem.PemHeader;
import org.cryptacular.util.CodecUtil;

/**
 * Container for PEM encoded data.
 *
 * @author Middleware Services
 */
public final class PemObject extends org.bouncycastle.util.io.pem.PemObject
{

  /**
   * Enum to define the RFC governing the PEM format
   *
   * @author Middleware Services
   */
  public enum Format
  {
    /**
     * a PEM encoded file as defined by RFC-2440 (OpenPGP).
     */
    RFC2440,
    /**
     * a PEM encoded file as defined by RFC-7468 (Textual Encodings of PKIX, PKCS, and CMS Structures).
     */
    RFC7468,
    /**
     * a PEM encoded file as defined by RFC-1421 (Privacy Enhanced Message).
     */
    RFC1421,
    /**
     * a PEM encoded file as defined by RFC-4716 (SSH).
     */
    RFC4716,
  }

  /**
   * RFC4716 3.3.3. Private Use Headers
   */
  public static final int RFC7468_MAX_LINE_LENGTH = 64;

  /**
   * RFC4716 3.3.3. Private Use Headers
   */
  public static final int RFC1421_MAX_LINE_LENGTH = 64;

  /**
   * RFC4716 3.3.3. Private Use Headers
   */
  public static final int RFC4716_MAX_LINE_LENGTH = 72;

  /**
   * RFC4716 3.3.3. Private Use Headers
   */
  public static final int RFC2440_MAX_LINE_LENGTH = 76;

  /**
   * RFC4716 3.3.3. Private Use Headers
   */
  public static final String RFC4716_SPECIFIER_PRIVATE_BEGIN_MARKER = "x-";

  /**
   * (RFC1421 4.4 Encapsulation Mechanism) (RFC7468 2. General Considerations) (RFC2440 6.2. Forming ASCII Armor)
   */
  public static final String RFC1421_ENCAPSULATION_MARKER = "-----";

  /**
   * RFC4716 3.2. Begin and End Markers
   */
  public static final String RFC4716_ENCAPSULATION_MARKER = "----";

  /**
   * RFC4716 3.2. Begin and End Markers
   */
  public static final String RFC4716_ENCAPSULATION_BEGIN_MARKER = RFC4716_ENCAPSULATION_MARKER + " BEGIN";

  /**
   * RFC4716 3.2. Begin and End Markers
   */
  public static final String RFC4716_ENCAPSULATION_END_MARKER = RFC4716_ENCAPSULATION_MARKER + " END";

  /**
   * (RFC1421 4.4 Encapsulation Mechanism) (RFC7468 2. General Considerations) (RFC2440 6.2. Forming ASCII Armor)
   */
  public static final String RFC1421_ENCAPSULATION_BEGIN_MARKER = RFC1421_ENCAPSULATION_MARKER + "BEGIN";

  /**
   * (RFC1421 4.4 Encapsulation Mechanism) (RFC7468 2. General Considerations) (RFC2440 6.2. Forming ASCII Armor)
   */
  public static final String RFC1421_ENCAPSULATION_END_MARKER = RFC1421_ENCAPSULATION_MARKER + "END";

  /**
   * Proc-Type header as defined by RFC 1421
   */
  public static final String RFC1421_SPECIFIER_PROC_TYPE = "Proc-Type";

  /**
   * DEK-Info header as defined by RFC 1421
   */
  public static final String RFC1421_SPECIFIER_DEK_INFO = "DEK-Info";

  /**
   * Originator-ID-Asymmetric header as defined by RFC 1421
   */
  public static final String RFC1421_SPECIFIER_ORIGINATOR_ID_ASYMMETRIC = "Originator-ID-Asymmetric";

  /**
   * Originator-ID-Symmetric header as defined by RFC 1421
   */
  public static final String RFC1421_SPECIFIER_ORIGINATOR_ID_SYMMETRIC = "Originator-ID-Symmetric";

  /**
   * Recipient-ID-Asymmetric header as defined by RFC 1421
   */
  public static final String RFC1421_SPECIFIER_RECIPIENT_ID_ASYMMETRIC = "Recipient-ID-Asymmetric";

  /**
   * Recipient-ID-Symmetric header as defined by RFC 1421
   */
  public static final String RFC1421_SPECIFIER_RECIPIENT_ID_SYMMETRIC = "Recipient-ID-Symmetric";

  /**
   * Originator-Certificate header as defined by RFC 1421
   */
  public static final String RFC1421_SPECIFIER_ORIGINATOR_CERTIFICATE = "Originator-Certificate";

  /**
   * Issuer-Certificate header as defined by RFC 1421
   */
  public static final String RFC1421_SPECIFIER_ISSUER_CERTIFICATE = "Issuer-Certificate";

  /**
   * MIC-Info header as defined by RFC 1421
   */
  public static final String RFC1421_SPECIFIER_MIC_INFO = "MIC-Info";

  /**
   * Key-Info header as defined by RFC 1421
   */
  public static final String RFC1421_SPECIFIER_KEY_INFO = "Key-Info";

  /**
   * CRL header as defined by RFC 1421
   */
  public static final String RFC1421_SPECIFIER_CRL = "CRL";

  /**
   * Version header as defined by RFC 2440
   */
  public static final String RFC2440_SPECIFIER_VERSION = "Version";

  /**
   * Comment header as defined by RFC 2440
   */
  public static final String RFC2440_SPECIFIER_COMMENT = "Comment";

  /**
   * MessageID header as defined by RFC 2440. The MessageID SHOULD NOT appear unless it is in a multi-part message.
   */
  public static final String RFC2440_SPECIFIER_MESSAGEID = "MessageID";

  /**
   * Hash header as defined by RFC 2440
   */
  public static final String RFC2440_SPECIFIER_HASH = "Hash";

  /**
   * Charset header as defined by RFC 2440
   */
  public static final String RFC2440_SPECIFIER_CHARSET = "Charset";

  /**
   * Subject header as defined by RFC 4716
   */
  public static final String RFC4716_SPECIFIER_SUBJECT = "Subject";

  /**
   * Comment header as defined by RFC 4716
   */
  public static final String RFC4716_SPECIFIER_COMMENT = "Comment";

  /**
   * Proc-Type header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_FIELD_PROC_TYPE = RFC1421_SPECIFIER_PROC_TYPE + ":";

  /**
   * DEK-Info header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_FIELD_DEK_INFO = RFC1421_SPECIFIER_DEK_INFO + ":";

  /**
   * Originator-ID-Asymmetric header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_FIELD_ORIGINATOR_ID_ASYMMETRIC =
          RFC1421_SPECIFIER_ORIGINATOR_ID_ASYMMETRIC + ":";

  /**
   * Originator-ID-Symmetric header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_FIELD_ORIGINATOR_ID_SYMMETRIC =
          RFC1421_SPECIFIER_ORIGINATOR_ID_SYMMETRIC + ":";

  /**
   * Recipient-ID-Asymmetric header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_FIELD_RECIPIENT_ID_ASYMMETRIC =
          RFC1421_SPECIFIER_RECIPIENT_ID_ASYMMETRIC + ":";

  /**
   * Recipient-ID-Symmetric header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_FIELD_RECIPIENT_ID_SYMMETRIC =
          RFC1421_SPECIFIER_RECIPIENT_ID_SYMMETRIC + ":";

  /**
   * Originator-Certificate header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_FIELD_ORIGINATOR_CERTIFICATE =
          RFC1421_SPECIFIER_ORIGINATOR_CERTIFICATE + ":";

  /**
   * Issuer-Certificate header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_FIELD_ISSUER_CERTIFICATE = RFC1421_SPECIFIER_ISSUER_CERTIFICATE +
          ":";

  /**
   * MIC-Info header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_FIELD_MIC_INFO = RFC1421_SPECIFIER_MIC_INFO + ":";

  /**
   * Key-Info header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_FIELD_KEY_INFO = RFC1421_SPECIFIER_KEY_INFO + ":";

  /**
   * CRL header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_FIELD_CRL = RFC1421_SPECIFIER_CRL + ":";

  /**
   * Version header as defined by RFC 2440
   */
  public static final String RFC2440_HEADER_FIELD_VERSION = RFC2440_SPECIFIER_VERSION + ":";

  /**
   * Comment header as defined by RFC 2440
   */
  public static final String RFC2440_HEADER_FIELD_COMMENT = RFC2440_SPECIFIER_COMMENT + ":";

  /**
   * MessageID header as defined by RFC 2440. The MessageID SHOULD NOT appear unless it is in a multi-part message.
   */
  public static final String RFC2440_HEADER_FIELD_MESSAGEID = RFC2440_SPECIFIER_MESSAGEID + ":";

  /**
   * Hash header as defined by RFC 2440
   */
  public static final String RFC2440_HEADER_FIELD_HASH = RFC2440_SPECIFIER_HASH + ":";

  /**
   * Charset header as defined by RFC 2440
   */
  public static final String RFC2440_HEADER_FIELD_CHARSET = RFC2440_SPECIFIER_CHARSET + ":";

  /**
   * Subject header as defined by RFC 4716
   */
  public static final String RFC4716_HEADER_FIELD_SUBJECT = RFC4716_SPECIFIER_SUBJECT + ":";

  /**
   * Comment header as defined by RFC 4716
   */
  public static final String RFC4716_HEADER_FIELD_COMMENT = RFC4716_SPECIFIER_COMMENT + ":";

  /**
   * Headers covered in RFC 4716. In addition to this set all headers starting with
   * {@link #RFC4716_SPECIFIER_PRIVATE_BEGIN_MARKER} are allowed by RFC 4716.
   */
  public static final Set<String> RFC4716_SPECIFIERS = Collections.unmodifiableSet(
          Stream.of(
                  RFC4716_SPECIFIER_SUBJECT,
                  RFC4716_SPECIFIER_COMMENT
          ).collect(Collectors.toSet())
  );

  /**
   * Headers allowed by RFC 4716. {@link #RFC2440_SPECIFIER_MESSAGEID} SHOULD NOT appear unless it is in a multi-part
   * message.
   */
  public static final Set<String> RFC2440_SPECIFIERS = Collections.unmodifiableSet(
          Stream.of(
                  RFC2440_SPECIFIER_CHARSET,
                  RFC2440_SPECIFIER_HASH,
                  RFC2440_SPECIFIER_MESSAGEID,
                  RFC2440_SPECIFIER_COMMENT,
                  RFC2440_SPECIFIER_VERSION
          ).collect(Collectors.toSet())
  );

  /**
   * Headers allowed by RFC 1421.
   */
  public static final Set<String> RFC1421_SPECIFIERS = Collections.unmodifiableSet(
          Stream.of(
                  RFC1421_SPECIFIER_CRL,
                  RFC1421_SPECIFIER_KEY_INFO,
                  RFC1421_SPECIFIER_MIC_INFO,
                  RFC1421_SPECIFIER_ISSUER_CERTIFICATE,
                  RFC1421_SPECIFIER_ORIGINATOR_CERTIFICATE,
                  RFC1421_SPECIFIER_RECIPIENT_ID_SYMMETRIC,
                  RFC1421_SPECIFIER_RECIPIENT_ID_ASYMMETRIC,
                  RFC1421_SPECIFIER_ORIGINATOR_ID_SYMMETRIC,
                  RFC1421_SPECIFIER_ORIGINATOR_ID_ASYMMETRIC,
                  RFC1421_SPECIFIER_DEK_INFO,
                  RFC1421_SPECIFIER_PROC_TYPE
          ).collect(Collectors.toSet())
  );

  /**
   * {@link Descriptor} for this PEM object which includes the RFC governing its format and other relevant data
   * about the data.
   */
  private final Descriptor descriptor;

  /**
   * Generic constructor for object without headers.
   *
   * @param descriptorParam Descriptor on the content (i.e. RFC governing PEM format, type etc.)
   * @param content The binary content of the object.
   */
  private PemObject(final Descriptor descriptorParam, final byte[] content)
  {
    super(descriptorParam.getType(), content);
    this.descriptor = descriptorParam;
  }


  /**
   * Generic constructor for object with headers.
   *
   * @param descriptorParam Descriptor on the content (i.e. RFC governing PEM format, type etc.)
   * @param headers A list of PemHeader objects.
   * @param content The binary content of the object.
   */
  private PemObject(final Descriptor descriptorParam, final List headers, final byte[] content)
  {
    super(descriptorParam.getType(), headers, content);
    this.descriptor = descriptorParam;
    assertHeadersValid(headers);
  }


  /**
   * Returns descriptor on PEM object
   *
   * @return {@link Descriptor}
   */
  public Descriptor getDescriptor()
  {
    return descriptor;
  }


  /**
   * Throws an exception if the headers are not according to their governing RFC format.
   *
   * @param headers headers
   */
  private void assertHeadersValid(final List headers)
  {
    switch (this.descriptor.getFormat()) {
    case RFC1421:
      assertPemHeaderValid(headers, RFC1421_SPECIFIERS,
              Format.RFC1421, false, true);
      break;
    case RFC2440:
      assertPemHeaderValid(headers, RFC2440_SPECIFIERS,
              Format.RFC2440, false, false);
      break;
    case RFC4716:
      assertPemHeaderValid(headers, RFC4716_SPECIFIERS,
              Format.RFC4716, true, false);
      break;
    case RFC7468:
      throw new IllegalArgumentException(
              "Headers are not allowed in this PEM format specified (RFC 7468)");
    default:
      break;
    }
  }


  /**
   * Checks to make sure a given list of {@link PemHeader} instances the names specified are valid.
   *
   * @param headers headers
   * @param specifiers Set of allowed specifiers/headers
   * @param format RFC format
   * @param allowX Allow specifiers/headers starting with X-
   * @param disregardX Treat specifiers/headers starting with X- as if they do not
   * @throws IllegalArgumentException If header element in the headers list is not valid
   */
  private void assertPemHeaderValid(final List headers, final Set<String> specifiers,
          final Format format, final boolean allowX, final boolean disregardX)
          throws IllegalArgumentException
  {
    for (final Object header : headers) {
      if (!(header instanceof PemHeader)) {
        throw new IllegalArgumentException("Headers must be of type PemHeader");
      }
      final PemHeader pemHeader = (PemHeader) header;
      if (pemHeader == null || pemHeader.getName() == null) {
        throw new IllegalArgumentException("Neither a supplied PemHeader nor its name may be null");
      }
      final boolean isXHeader = pemHeader.getName().toLowerCase()
              .startsWith(RFC4716_SPECIFIER_PRIVATE_BEGIN_MARKER);
      final String headerName = disregardX && isXHeader ?
              pemHeader.getName().substring(2) : pemHeader.getName();
      if (!specifiers.contains(headerName) && !allowX && isXHeader) {
        throw new IllegalArgumentException(
                String.format("Invalid header \"%s\" specified in PEM format (%s)",
                        pemHeader.getName(), format.name()));
      }
    }
  }

  public static class Builder
  {

    /**
     * Default empty constructor.
     *
     */
    public Builder()
    {
    }

    public PemObject build(final Descriptor descriptor, final byte[] content) throws IOException
    {
      return new PemObject(descriptor, content);
    }

    public PemObject build(final Descriptor descriptor, final List headers, final byte[] content) throws IOException
    {
      return new PemObject(descriptor, headers, content);
    }

    public PemObject build(final BufferedReader reader) throws IOException
    {
      return parseInternal(reader, parseDescriptor(reader));
    }


    /**
     * Reads the contents of the PEM data between the BEGIN and END markers by format specified.
     *
     * @param reader {@link BufferedReader} reader that contains the data to parse
     * @param descriptor Descriptor regarding the PEM encoded format (see {@link Descriptor})
     * @return ExtendedPemObject instance with the data read
     * @throws IOException In case of exceptions reading the buffer
     * @throws IllegalArgumentException In case of malformed PEM data
     */
    private static PemObject parseInternal(
            final BufferedReader reader,
            final Descriptor descriptor)
            throws IOException, IllegalArgumentException
    {
      final List<PemHeader> headers = new ArrayList<>();
      int lineLength = -1;
      String line;
      final String endMarker = (descriptor.getFormat() == Format.RFC4716 ?
              PemObject.RFC4716_ENCAPSULATION_END_MARKER :
              PemObject.RFC1421_ENCAPSULATION_END_MARKER) + " " + descriptor.getType();
      final String beginMarker = (descriptor.getFormat() == Format.RFC4716 ?
              PemObject.RFC4716_ENCAPSULATION_BEGIN_MARKER :
              PemObject.RFC1421_ENCAPSULATION_BEGIN_MARKER) + " " + descriptor.getType();
      final String beginLine = reader.readLine();
      if (!beginLine.startsWith(beginMarker)) {
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
     * @return {@link PemHeader} if a header value pair could be successfully read, otherwise null is returned
     * @throws IOException In case of any read errors in the buffer
     */
    private static PemHeader parseHeader(
            final BufferedReader reader,
            final String line,
            final Format format) throws IOException
    {
      if (line.contains(":")) {
        final int index = line.indexOf(':');
        String specifier = line.substring(0, index);
        String value = line.substring(index + 1);
        if (format == Format.RFC4716) {
          while (value.endsWith("\\")) {
            value = value.substring(0, value.length() - 1);
            value += reader.readLine();
          }
        } else if (format == Format.RFC1421) {
          if (specifier.startsWith("X-")) {
            //Remove X- as per RFC 1421 Section 4.6
            specifier = specifier.substring(2);
          }
          String nextLine = peekNextLine(reader, PemObject.RFC1421_MAX_LINE_LENGTH);
          while (nextLine.startsWith(" ")) {
            value += reader.readLine().trim();
            nextLine = peekNextLine(reader, PemObject.RFC1421_MAX_LINE_LENGTH);
          }
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
     * @throws IllegalArgumentException In case of a constraint violation
     */
    private static void assertLineLength(
            final Format format,
            final int maxLineLength) throws IllegalArgumentException
    {
      switch (format) {
      case RFC4716:
        if (maxLineLength > PemObject.RFC4716_MAX_LINE_LENGTH) {
          throw new IllegalArgumentException(
                  "Malformed RFC 4716 type PEM data (b64 lines longer than maximum allowed length)");
        }
        break;
      case RFC7468:
        if (maxLineLength > PemObject.RFC7468_MAX_LINE_LENGTH) {
          throw new IllegalArgumentException(
                  "Malformed RFC 7468 type PEM data (b64 lines longer than maximum allowed length)");
        }
        break;
      case RFC1421:
        if (maxLineLength > PemObject.RFC1421_MAX_LINE_LENGTH) {
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
     * @return Populated ExtendedPemObject instance
     * @throws IOException In case of exceptions reading the buffer, or malformed PEM data
     */
    private static Descriptor parseDescriptor(final BufferedReader reader)
            throws IOException
    {
      final Format format;
      final String explanatoryText = readExplanatoryText(reader);
      final String firstPemLine = peekNextLine(reader, PemObject.RFC2440_MAX_LINE_LENGTH);
      if (firstPemLine != null) {
        final String pemType;
        final boolean isRFC4716Markers =
                firstPemLine.startsWith(PemObject.RFC4716_ENCAPSULATION_BEGIN_MARKER);
        pemType = getPemType(isRFC4716Markers, firstPemLine);
        format = getFormat(explanatoryText, pemType, isRFC4716Markers);
        return new Descriptor(format, explanatoryText, pemType);
      }
      return null;
    }


    /**
     * Determines the RFC governing the format of the PEM file based of the parameters provided.
     *
     * @param explanatoryText Explanatory text is only allowed in RFC 7468
     * @param pemType All types begin with PGP in RFC 2440
     * @param isRFC4716Markers It either starts with four dashes (RFC RFC4716) or five (RFC 1421)
     * @return Format determined (see {@link Descriptor#getFormat()})
     */
    private static Format getFormat(
            final String explanatoryText, final String pemType, final boolean isRFC4716Markers)
    {
      final Format format;
      if (explanatoryText.length() > 0) {
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
     * @return PEM type
     */
    private static String getPemType(final boolean isRFC4716Markers, final String firstPemLine)
    {
      if (isRFC4716Markers) {
        return firstPemLine.substring(PemObject.RFC4716_ENCAPSULATION_BEGIN_MARKER.length(),
                firstPemLine.indexOf(PemObject.RFC4716_ENCAPSULATION_MARKER,
                        PemObject.RFC4716_ENCAPSULATION_BEGIN_MARKER.length())).trim();
      }
      return firstPemLine.substring(PemObject.RFC1421_ENCAPSULATION_BEGIN_MARKER.length(),
              firstPemLine.indexOf(PemObject.RFC1421_ENCAPSULATION_MARKER,
                      PemObject.RFC1421_ENCAPSULATION_BEGIN_MARKER.length())).trim();
    }


    /**
     * Reads the explanatory text as described by RFC 7468 5.2. Method simply reads a line until a known header marker
     * is found.
     *
     * @param reader only the explanatory text will actually be read off the reader
     * @return Explanatory text
     * @throws IOException In case of errors reading the buffer
     */
    private static String readExplanatoryText(final BufferedReader reader) throws IOException
    {
      final StringBuilder explanatoryTextBuilder = new StringBuilder(0);
      String line = peekNextLine(reader, PemObject.RFC2440_MAX_LINE_LENGTH);
      while (line != null && !(line.startsWith(PemObject.RFC1421_ENCAPSULATION_BEGIN_MARKER) ||
              line.startsWith(PemObject.RFC4716_ENCAPSULATION_BEGIN_MARKER))) {
        line = reader.readLine();
        //Read "explanatory text" as defined by RFC 7468
        if (line.length() > 0) {
          explanatoryTextBuilder.append(line).append("\n");
        }
        line = peekNextLine(reader, PemObject.RFC2440_MAX_LINE_LENGTH);
      }
      return explanatoryTextBuilder.toString();
    }


    /**
     * Reads the next line in a {@link BufferedReader} instance without consuming it from the buffer
     *
     * @param reader {@link BufferedReader} instance
     * @param maximumReadLength Maximum number of characters to peek
     * @return Next line
     * @throws IOException In case of errors reading the buffer
     */
    private static String peekNextLine(final BufferedReader reader, final int maximumReadLength) throws IOException
    {
      reader.mark(maximumReadLength);
      final String nextLine = reader.readLine();
      reader.reset();
      return nextLine;
    }

  }


  /**
   * Descriptor for {@link org.bouncycastle.util.io.pem.PemObject}
   *
   * @author Middleware Services
   */
  public static final class Descriptor
  {

    /**
     * The RFC PEM specification which governs the format of this PEM object.
     */
    private final Format format;

    /**
     * The type of this PEM encoded data (i.e. PUBLIC KEY).
     */
    private final String type;

    /**
     * Explanatory text prior to the encapsulation header as defined by RFC 7468 Section 5.2
     */
    private String explanatoryText;

    /**
     * Constructor with RFC format and explanatory text.
     *
     * @param formatParam RFC governing PEM format
     * @param explanatoryTextParam Explanatory text if applicable
     * @param typeParam Data type
     */
    public Descriptor(final Format formatParam, final String explanatoryTextParam, final String typeParam)
    {
      this.format = formatParam;
      this.type = typeParam;
      if (this.format == Format.RFC7468) {
        this.explanatoryText = explanatoryTextParam;
      }
    }

    /**
     * @return The RFC {@link Format} governing this PEM data.
     */
    public Format getFormat()
    {
      return format;
    }

    /**
     * @return The encoded data type
     */
    public String getType()
    {
      return type;
    }

    /**
     * @return The explanatory text included with this PEM as defined by RFC-7468 5.2 null is returned if this PEM file
     * is not of {@link Format#RFC7468}
     */
    public String getExplanatoryText()
    {
      return explanatoryText;
    }
  }
}
