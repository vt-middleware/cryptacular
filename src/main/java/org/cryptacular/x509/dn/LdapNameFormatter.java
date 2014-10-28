/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

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
  public static final char RDN_SEPARATOR = ',';

  /** Separator character between ATV components in the same RDN element. */
  public static final char ATV_SEPARATOR = '+';


  /** {@inheritDoc} */
  @Override
  public String format(final X500Principal dn)
  {
    final StringBuilder builder = new StringBuilder();
    final RDNSequence sequence = NameReader.readX500Principal(dn);
    int i = 0;
    int j;
    for (RDN rdn : sequence.backward()) {
      if (i++ > 0) {
        builder.append(RDN_SEPARATOR);
      }
      j = 0;
      for (Attribute attr : rdn.getAttributes()) {
        if (j++ > 0) {
          builder.append(ATV_SEPARATOR);
        }
        builder.append(attr.getType()).append('=').append(attr.getValue());
      }
    }
    return builder.toString();
  }
}
