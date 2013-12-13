package org.cryptosis.x509.dn;

/**
 * Simple implementation of the X.501 AttributeTypeAndValue that makes up the RelativeDistinguishedName type described
 * in section 4.1.2.4 of RFC 2459.
 *
 * @author Marvin S. Addison
 */
public class Attribute
{
  /** Attribute type. */
  private final AttributeType type;

  /** Attribute value. */
  private final String value;

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

  public AttributeType getType()
  {
    return type;
  }

  public String getValue()
  {
    return value;
  }

  @Override
  public String toString()
  {
    return value;
  }
}
