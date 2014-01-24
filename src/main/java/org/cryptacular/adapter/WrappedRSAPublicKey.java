/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * JCE/JDK RSA public key that wraps the corresponding BC RSA public key type,
 * {@link RSAKeyParameters}.
 *
 * @author  Middleware Services
 */
public class WrappedRSAPublicKey extends AbstractWrappedRSAKey<RSAKeyParameters>
  implements RSAPublicKey
{

  /**
   * Creates a new instance that wraps the given key.
   *
   * @param  wrappedKey  RSA key to wrap.
   */
  public WrappedRSAPublicKey(final RSAKeyParameters wrappedKey)
  {
    super(wrappedKey);
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getPublicExponent()
  {
    return delegate.getExponent();
  }
}
