/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import org.cryptacular.CryptUtil;

/**
 * Simple implementation of the X.501 RelativeDistinguishedName type described in section 4.1.2.4 of RFC 2459.
 *
 * @author  Middleware Services
 */
public class RDN
{

  /** RDN attributes. */
  private final Attributes attributes;


  /**
   * Creates a new instance with given attributes.
   *
   * @param  attributes  Container for one or more AttributeTypeAndValues.
   */
  public RDN(final Attributes attributes)
  {
    this.attributes = CryptUtil.assertNotNullArg(attributes, "Attributes cannot be null");
  }


  /** @return  RDN attributes. */
  public Attributes getAttributes()
  {
    return attributes;
  }
}
