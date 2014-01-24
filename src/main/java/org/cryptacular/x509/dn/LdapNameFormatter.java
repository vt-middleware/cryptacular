/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import java.util.Iterator;
import javax.security.auth.x500.X500Principal;

/**
 * Produces a string representation of an X.500 distinguished name using the
 * process described in section 2 of RFC 2253, LADPv3 Distinguished Names.
 *
 * @author  Middleware Services
 */
public class LdapNameFormatter implements NameFormatter
{

  /** Separator character between RDN components. */
  public static final char SEPARATOR = ',';


  /** {@inheritDoc} */
  @Override
  public String format(final X500Principal dn)
  {
    final StringBuilder builder = new StringBuilder();
    final Iterator<Attribute> iterator = NameReader.readX500Principal(dn)
      .backward();
    Attribute attr;
    while (iterator.hasNext()) {
      attr = iterator.next();
      builder.append(attr.getType()).append('=').append(attr.getValue());
      if (iterator.hasNext()) {
        builder.append(SEPARATOR);
      }
    }
    return builder.toString();
  }
}
