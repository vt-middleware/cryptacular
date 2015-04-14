/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import javax.security.auth.x500.X500Principal;

/**
 * Strategy pattern interface for producing a string representation of an X.500 distinguished name.
 *
 * @author  Middleware Services
 */
public interface NameFormatter
{

  /**
   * Produces a string representation of the given X.500 principal.
   *
   * @param  dn  Distinguished name as as X.500 principal.
   *
   * @return  String representation of DN.
   */
  String format(X500Principal dn);
}
