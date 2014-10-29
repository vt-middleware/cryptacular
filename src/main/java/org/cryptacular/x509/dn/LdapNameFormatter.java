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

  /** Escape character. */
  public static final char ESCAPE_CHAR = '\\';

  /** String of characters that need to be escaped. */
  public static final String RESERVED_CHARS = ",+\"\\<>;";


  /** {@inheritDoc} */
  @Override
  public String format(final X500Principal dn)
  {
    final StringBuilder builder = new StringBuilder();
    final RDNSequence sequence = NameReader.readX500Principal(dn);
    int i = 0;
    for (RDN rdn : sequence.backward()) {
      if (i++ > 0) {
        builder.append(RDN_SEPARATOR);
      }
      int j = 0;
      for (Attribute attr : rdn.getAttributes()) {
        if (j++ > 0) {
          builder.append(ATV_SEPARATOR);
        }
        builder.append(attr.getType()).append('=');
        final String value = attr.getValue();
        char c = value.charAt(0);
        if (c == ' ' || c == '#') {
          builder.append(ESCAPE_CHAR);
        }
        builder.append(c);
        final int nmax = value.length() - 1;
        for (int n = 1; n < nmax; n++) {
          c = value.charAt(n);
          if (RESERVED_CHARS.indexOf(c) > -1) {
            builder.append(ESCAPE_CHAR);
          }
          builder.append(c);
        }
        c = value.charAt(nmax);
        if (c == ' ') {
          builder.append(ESCAPE_CHAR);
        }
        builder.append(c);
      }
    }
    return builder.toString();
  }
}
