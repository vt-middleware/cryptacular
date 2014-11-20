/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

/**
 * Describes values of AttributeType that may appear in a
 * RelativeDistinguishedName (RDN) as defined in section 2 of RFC 2253.
 *
 * @author  Middleware Services
 */
public interface AttributeType
{

  /** @return  Attribute OID. */
  String getOid();

  /** @return  Attribute name. */
  String getName();
}
