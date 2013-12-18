package org.cryptosis.jce;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * JCE/JDK RSA public key that wraps the corresponding BC RSA public key type, {@link RSAKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedRSAPublicKey extends AbstractWrappedRSAKey<RSAKeyParameters> implements RSAPublicKey
{
  /**
   * {@inheritDoc}
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
