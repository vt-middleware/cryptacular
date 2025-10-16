/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import org.cryptacular.CryptUtil;

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
   * @param  typeOid  OID of attribute type.
   * @param  value  Attribute value.
   */
  public Attribute(final String typeOid, final String value)
  {
    CryptUtil.assertNotNullArg(typeOid, "Type OID cannot be null");
    CryptUtil.assertNotNullArg(value, "Value cannot be null");
    final StandardAttributeType type = StandardAttributeType.fromOid(typeOid);
    if (type != null) {
      this.type = type;
    } else {
      this.type = new UnknownAttributeType(typeOid);
    }
    this.value = value;
  }


  /**
   * Creates a new instance of the given type and value.
   *
   * @param  type  Attribute type.
   * @param  value  Attribute value.
   */
  public Attribute(final AttributeType type, final String value)
  {
    this.type = CryptUtil.assertNotNullArg(type, "Type cannot be null");
    this.value = CryptUtil.assertNotNullArg(value, "Value cannot be null");
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
