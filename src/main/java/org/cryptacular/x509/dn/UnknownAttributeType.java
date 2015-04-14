/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import java.util.regex.Pattern;

/**
 * Describes a non-standard AttributeType in dotted decimal form that may appear in a RelativeDistinguishedName (RDN) as
 * defined in section 2 of RFC 2253.
 *
 * @author  Middleware Services
 */
public class UnknownAttributeType implements AttributeType
{

  /** Dotted decimal OID pattern. */
  private static final Pattern PATTERN = Pattern.compile("[0-9]+(.[0-9]+)*");

  /** Attribute type OID. */
  private final String oid;


  /**
   * Creates a new instance from the given oid.
   *
   * @param  attributeTypeOid  Attribute type OID.
   */
  public UnknownAttributeType(final String attributeTypeOid)
  {
    if (!PATTERN.matcher(attributeTypeOid).matches()) {
      throw new IllegalArgumentException(attributeTypeOid + " is not an OID");
    }
    this.oid = attributeTypeOid;
  }

  @Override
  public String getOid()
  {
    return oid;
  }

  @Override
  public String getName()
  {
    return oid;
  }

  @Override
  public String toString()
  {
    return oid;
  }
}
