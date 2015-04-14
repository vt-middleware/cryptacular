/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

/**
 * Simple implementation of the X.501 AttributeTypeAndValue that makes up the RelativeDistinguishedName type described
 * in section 4.1.2.4 of RFC 2459.
 *
 * @author  Middleware Services
 */
public class Attribute
{

  /** Attribute type. */
  private final AttributeType type;

  /** Attribute value. */
  private final String value;


  /**
   * Creates a new instance of the given type and value.
   *
   * @param  type  Attribute type.
   * @param  value  Attribute value.
   */
  public Attribute(final AttributeType type, final String value)
  {
    if (type == null) {
      throw new IllegalArgumentException("Type cannot be null.");
    }
    this.type = type;
    if (value == null) {
      throw new IllegalArgumentException("Value cannot be null.");
    }
    this.value = value;
  }


  /** @return  Attribute type. */
  public AttributeType getType()
  {
    return type;
  }


  /** @return  Attribute value. */
  public String getValue()
  {
    return value;
  }
}
