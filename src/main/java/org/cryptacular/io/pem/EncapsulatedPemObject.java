/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.io.pem;

import java.util.Collections;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * Container for PEM encoded data.
 *
 * @author Middleware Services
 */
public final class EncapsulatedPemObject extends PemObject
{

  /**
   * Enum to define the RFC governing the PEM format
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
     * a PEM encoded file as defined by RFC-4716 (SSH2).
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
  public static final String RFC4716_HEADER_TAG_PRIVATE_BEGIN_MARKER = "x-";

  /**
   * RFC4716 3.2. Begin and End Markers
   */
  public static final String RFC4716_ENCAPSULATION_BEGIN_MARKER = "---- BEGIN";

  /**
   * RFC4716 3.2. Begin and End Markers
   */
  public static final String RFC4716_ENCAPSULATION_END_MARKER = "---- END";

  /**
   * (RFC1421 4.4 Encapsulation Mechanism) (RFC7468 2. General Considerations) (RFC2440 6.2. Forming ASCII Armor)
   */
  public static final String ENCAPSULATION_BEGIN_MARKER = "-----BEGIN";
  /**
   * (RFC1421 4.4 Encapsulation Mechanism) (RFC7468 2. General Considerations) (RFC2440 6.2. Forming ASCII Armor)
   */

  public static final String ENCAPSULATION_END_MARKER = "-----END";

  /**
   * Proc-Type header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_TAG_PROC_TYPE = "Proc-Type";
  /**
   * DEK-Info header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_TAG_DEK_INFO = "DEK-Info";
  /**
   * Originator-ID-Asymmetric header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_TAG_ORIGINATOR_ID_ASYMMETRIC = "Originator-ID-Asymmetric";
  /**
   * Originator-ID-Symmetric header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_TAG_ORIGINATOR_ID_SYMMETRIC = "Originator-ID-Symmetric";
  /**
   * Recipient-ID-Asymmetric header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_TAG_RECIPIENT_ID_ASYMMETRIC = "Recipient-ID-Asymmetric";
  /**
   * Recipient-ID-Symmetric header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_TAG_RECIPIENT_ID_SYMMETRIC = "Recipient-ID-Symmetric";
  /**
   * Originator-Certificate header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_TAG_ORIGINATOR_CERTIFICATE = "Originator-Certificate";
  /**
   * Issuer-Certificate header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_TAG_ISSUER_CERTIFICATE = "Issuer-Certificate";
  /**
   * MIC-Info header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_TAG_MIC_INFO = "MIC-Info";
  /**
   * Key-Info header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_TAG_KEY_INFO = "Key-Info";
  /**
   * CRL header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_TAG_CRL = "CRL";
  /**
   * Version header as defined by RFC 2440
   */
  public static final String RFC2440_HEADER_TAG_VERSION = "Version";
  /**
   * Comment header as defined by RFC 2440
   */
  public static final String RFC2440_HEADER_TAG_COMMENT = "Comment";
  /**
   * MessageID header as defined by RFC 2440. The MessageID SHOULD NOT appear unless it is in a multi-part
   * message.
   */
  public static final String RFC2440_HEADER_TAG_MESSAGEID = "MessageID";
  /**
   * Hash header as defined by RFC 2440
   */
  public static final String RFC2440_HEADER_TAG_HASH = "Hash";
  /**
   * Charset header as defined by RFC 2440
   */
  public static final String RFC2440_HEADER_TAG_CHARSET = "Charset";
  /**
   * Subject header as defined by RFC 4716
   */
  public static final String RFC4716_HEADER_TAG_SUBJECT = "Subject";
  /**
   * Comment header as defined by RFC 4716
   */
  public static final String RFC4716_HEADER_TAG_COMMENT = "Comment";

  /**
   * Headers covered in RFC 4716.  In addition to this set all headers starting with
   * {@link RFC4716_HEADER_TAG_PRIVATE_BEGIN_MARKER} are allowed by RFC 4716.
   */
  public static final Set<String> RFC4716_HEADERS = Collections.unmodifiableSet(
          Stream.of(
                  RFC4716_HEADER_TAG_SUBJECT,
                  RFC4716_HEADER_TAG_COMMENT
          ).collect(Collectors.toSet())
  );

  /**
   * Headers allowed by RFC 4716. {@link #RFC2440_HEADER_TAG_MESSAGEID} SHOULD NOT appear unless it is in a multi-part
   * message.
   */
  public static final Set<String> RFC2440_HEADERS = Collections.unmodifiableSet(
          Stream.of(
                  RFC2440_HEADER_TAG_CHARSET,
                  RFC2440_HEADER_TAG_HASH,
                  RFC2440_HEADER_TAG_MESSAGEID,
                  RFC2440_HEADER_TAG_COMMENT,
                  RFC2440_HEADER_TAG_VERSION
          ).collect(Collectors.toSet())
  );

  /**
   * Headers allowed by RFC 1421.
   */
  public static final Set<String> RFC1421_HEADERS = Collections.unmodifiableSet(
          Stream.of(
                  RFC1421_HEADER_TAG_CRL,
                  RFC1421_HEADER_TAG_KEY_INFO,
                  RFC1421_HEADER_TAG_MIC_INFO,
                  RFC1421_HEADER_TAG_ISSUER_CERTIFICATE,
                  RFC1421_HEADER_TAG_ORIGINATOR_CERTIFICATE,
                  RFC1421_HEADER_TAG_RECIPIENT_ID_SYMMETRIC,
                  RFC1421_HEADER_TAG_RECIPIENT_ID_ASYMMETRIC,
                  RFC1421_HEADER_TAG_ORIGINATOR_ID_SYMMETRIC,
                  RFC1421_HEADER_TAG_ORIGINATOR_ID_ASYMMETRIC,
                  RFC1421_HEADER_TAG_DEK_INFO,
                  RFC1421_HEADER_TAG_PROC_TYPE
          ).collect(Collectors.toSet())
  );

  /**
   * The RFC PEM specification which governs the format of this PEM object.
   */
  private final Format format;

  /**
   * Headers accompanying this PEM data
   */
  private final List<PemHeader> headers;

  /**
   * Explanatory text prior to the encapsulation header as defined by RFC 7468 Section 5.2
   */
  private String explanatoryText = "";

  /**
   * Constructor including content, and pemFormat
   * @param type Type of this PEM data (CERTIFICATE, CRL etc.)
   * @param content Byte array holding the encoded data of this PEM format
   * @param pemFormat RFC format governing the PEM structure
   */
  public EncapsulatedPemObject(final String type, final byte[] content, final Format pemFormat)
  {
    super(type, content);
    this.headers = Collections.unmodifiableList(Collections.emptyList());
    this.format = pemFormat;
  }

  /**
   * Constructor including content, headers, and pemFormat
   * @param type Type of this PEM data (CERTIFICATE, CRL etc.)
   * @param headersParameter PEM headers
   * @param content Byte array holding the encoded data of this PEM format
   * @param pemFormat RFC format governing the PEM structure
   */
  public EncapsulatedPemObject(final String type, final List<PemHeader> headersParameter, final byte[] content,
          final Format pemFormat)
  {
    super(type, content);
    this.headers = Collections.unmodifiableList(headersParameter);
    this.format = pemFormat;
  }

  /**
   * Constructor for RFC 7468 type PEM data
   * @param type Type of this PEM data (CERTIFICATE, CRL etc.)
   * @param explanatoryTextParameter Explanatory Text as per RFC 7468
   * @param content Byte array holding the encoded data of this PEM format
   */
  public EncapsulatedPemObject(final String type,
          final byte[] content,
          final String explanatoryTextParameter)
  {
    super(type, content);
    this.headers = Collections.unmodifiableList(Collections.emptyList());
    this.explanatoryText = explanatoryTextParameter;
    this.format = Format.RFC7468;
  }

  /**
   * Get all {@link PemHeader} instances in headers where the header tag matches the header's name property.
   *
   * @param headerTag header name tag
   * @return List of matching {@link PemHeader}, otherwise empty list
   */
  public List<PemHeader> getHeadersByTag(final String headerTag)
  {
    return headers.stream()
            .filter(header -> header != null && header.getName().equals(headerTag))
            .collect(Collectors.toList());
  }

  /**
   * Get the first matching {@link PemHeader} instance in headers where the header tag matches the header name
   * property.
   *
   * @param headerTag header name tag
   * @return Matching {@link PemHeader}
   * @throws NoSuchElementException if no header exists by the given name
   */
  public PemHeader getHeaderByTag(final String headerTag) throws NoSuchElementException
  {
    return headers.stream()
            .filter(header -> header != null && header.getName().equals(headerTag))
            .findFirst()
            .get();
  }

  /**
   * @return The RFC {@link Format} governing this PEM data.
   */
  public Format getFormat()
  {
    return format;
  }

  /**
   * @return The explanatory text included with this PEM as defined by RFC-7468 5.2
   * null is returned if this PEM file is not of {@link Format#RFC7468}
   */
  public String getExplanatoryText()
  {
    return getFormat() == Format.RFC7468 ? explanatoryText : null;
  }
}
