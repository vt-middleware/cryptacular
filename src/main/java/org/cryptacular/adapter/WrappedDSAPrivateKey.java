/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import java.math.BigInteger;
import java.security.interfaces.DSAPrivateKey;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;

/**
 * JCE/JDK DSA private key that wraps the corresponding BC DSA private key type,
 * {@link DSAPrivateKeyParameters}.
 *
 * @author  Middleware Services
 */
public class WrappedDSAPrivateKey
  extends AbstractWrappedDSAKey<DSAPrivateKeyParameters>
  implements DSAPrivateKey
{

  /**
   * Creates a new instance that wraps the given BC DSA private key.
   *
   * @param  parameters  BC DSA private key.
   */
  public WrappedDSAPrivateKey(final DSAPrivateKeyParameters parameters)
  {
    super(parameters);
  }


  @Override
  public BigInteger getX()
  {
    return delegate.getX();
  }
}
