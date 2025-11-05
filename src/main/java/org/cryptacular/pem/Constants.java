/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.pem;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * PEM constants.
 *
 * @author Middleware Services
 */
public final class Constants
{

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
  private static final String RFC1421_SPECIFIER_PROC_TYPE = "Proc-Type";

  /**
   * DEK-Info header as defined by RFC 1421
   */
  private static final String RFC1421_SPECIFIER_DEK_INFO = "DEK-Info";

  /**
   * Originator-ID-Asymmetric header as defined by RFC 1421
   */
  private static final String RFC1421_SPECIFIER_ORIGINATOR_ID_ASYMMETRIC = "Originator-ID-Asymmetric";

  /**
   * Originator-ID-Symmetric header as defined by RFC 1421
   */
  private static final String RFC1421_SPECIFIER_ORIGINATOR_ID_SYMMETRIC = "Originator-ID-Symmetric";

  /**
   * Recipient-ID-Asymmetric header as defined by RFC 1421
   */
  private static final String RFC1421_SPECIFIER_RECIPIENT_ID_ASYMMETRIC = "Recipient-ID-Asymmetric";

  /**
   * Recipient-ID-Symmetric header as defined by RFC 1421
   */
  private static final String RFC1421_SPECIFIER_RECIPIENT_ID_SYMMETRIC = "Recipient-ID-Symmetric";

  /**
   * Originator-Certificate header as defined by RFC 1421
   */
  private static final String RFC1421_SPECIFIER_ORIGINATOR_CERTIFICATE = "Originator-Certificate";

  /**
   * Issuer-Certificate header as defined by RFC 1421
   */
  private static final String RFC1421_SPECIFIER_ISSUER_CERTIFICATE = "Issuer-Certificate";

  /**
   * MIC-Info header as defined by RFC 1421
   */
  private static final String RFC1421_SPECIFIER_MIC_INFO = "MIC-Info";

  /**
   * Key-Info header as defined by RFC 1421
   */
  private static final String RFC1421_SPECIFIER_KEY_INFO = "Key-Info";

  /**
   * CRL header as defined by RFC 1421
   */
  private static final String RFC1421_SPECIFIER_CRL = "CRL";

  /**
   * Version header as defined by RFC 2440
   */
  private static final String RFC2440_SPECIFIER_VERSION = "Version";

  /**
   * Comment header as defined by RFC 2440
   */
  private static final String RFC2440_SPECIFIER_COMMENT = "Comment";

  /**
   * MessageID header as defined by RFC 2440. The MessageID SHOULD NOT appear unless it is in a multi-part message.
   */
  private static final String RFC2440_SPECIFIER_MESSAGE_ID = "MessageID";

  /**
   * Hash header as defined by RFC 2440
   */
  private static final String RFC2440_SPECIFIER_HASH = "Hash";

  /**
   * Charset header as defined by RFC 2440
   */
  private static final String RFC2440_SPECIFIER_CHARSET = "Charset";

  /**
   * Subject header as defined by RFC 4716
   */
  private static final String RFC4716_SPECIFIER_SUBJECT = "Subject";

  /**
   * Comment header as defined by RFC 4716
   */
  private static final String RFC4716_SPECIFIER_COMMENT = "Comment";

  /**
   * DEK-Info header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_FIELD_DEK_INFO = RFC1421_SPECIFIER_DEK_INFO + ":";

  /**
   * Proc-Type header as defined by RFC 1421
   */
  public static final String RFC1421_HEADER_FIELD_PROC_TYPE = RFC1421_SPECIFIER_PROC_TYPE + ":";

  /**
   * Headers covered in RFC 4716. In addition to this set all headers starting with
   * {@link #RFC4716_SPECIFIER_PRIVATE_BEGIN_MARKER} are allowed by RFC 4716.
   */
  public static final Set<String> RFC4716_SPECIFIERS = Collections.unmodifiableSet(
    Stream.of(RFC4716_SPECIFIER_SUBJECT, RFC4716_SPECIFIER_COMMENT).collect(Collectors.toSet()));

  /**
   * Headers allowed by RFC 4716. {@link #RFC2440_SPECIFIER_MESSAGE_ID} SHOULD NOT appear unless it is in a multi-part
   * message.
   */
  public static final Set<String> RFC2440_SPECIFIERS = Collections.unmodifiableSet(
    Stream.of(
      RFC2440_SPECIFIER_CHARSET,
      RFC2440_SPECIFIER_HASH,
      RFC2440_SPECIFIER_MESSAGE_ID,
      RFC2440_SPECIFIER_COMMENT,
      RFC2440_SPECIFIER_VERSION).collect(Collectors.toSet()));

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
      RFC1421_SPECIFIER_PROC_TYPE).collect(Collectors.toSet()));

  /** Default constructor */
  private Constants() {}
}
