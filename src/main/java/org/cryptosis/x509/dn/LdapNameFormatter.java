/*
  $Id: LDAPv3DNFormatter.java 2745 2013-06-25 21:16:10Z dfisher $

  Copyright (C) 2003-2013 Virginia Tech.
  All rights reserved.

  SEE LICENSE FOR MORE INFORMATION

  Author:  Middleware Services
  Email:   middleware@vt.edu
  Version: $Revision: 2745 $
  Updated: $Date: 2013-06-25 17:16:10 -0400 (Tue, 25 Jun 2013) $
*/
package org.cryptosis.x509.dn;

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
  public String format(final X500Principal dn)
  {
    final StringBuilder builder = new StringBuilder();
    final Iterator<Attribute> iterator = NameReader.readX500Principal(dn).backward();
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
