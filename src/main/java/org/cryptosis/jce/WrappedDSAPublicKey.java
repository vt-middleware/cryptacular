package org.cryptosis.jce;

import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;

import org.bouncycastle.crypto.params.DSAPublicKeyParameters;

/**
 * JCE/JDK DSA public key that wraps the corresponding BC DSA public key type, {@link DSAPublicKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedDSAPublicKey extends AbstractWrappedDSAKey<DSAPublicKeyParameters> implements DSAPublicKey
{
  /** {@inheritDoc} */
  public WrappedDSAPublicKey(final DSAPublicKeyParameters wrappedKey)
  {
    super(wrappedKey);
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getY()
  {
    return delegate.getY();
  }

}
