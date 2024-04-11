/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;

/**
 * JCE/JDK DSA public key that wraps the corresponding BC DSA public key type, {@link DSAPublicKeyParameters}.
 *
 * @author  Middleware Services
 */
public class WrappedDSAPublicKey extends AbstractWrappedDSAKey<DSAPublicKeyParameters> implements DSAPublicKey
{

  /** serialVersionUID. */
  private static final long serialVersionUID = -3349509056520420431L;

  /**
   * Creates a new instance that wraps the given key.
   *
   * @param  wrappedKey  DSA key to wrap.
   */
  public WrappedDSAPublicKey(final DSAPublicKeyParameters wrappedKey)
  {
    super(wrappedKey);
  }


  @Override
  public BigInteger getY()
  {
    return delegate.getY();
  }

}
