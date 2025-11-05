/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.pem;

/**
 * Descriptor for {@link org.bouncycastle.util.io.pem.PemObject}
 *
 * @author Middleware Services
 */
public final class Descriptor
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
    format = formatParam;
    type = typeParam;
    if (format == Format.RFC7468) {
      explanatoryText = explanatoryTextParam;
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
