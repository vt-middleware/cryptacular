package org.cryptosis.adapter;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

/**
 * JCE/JDK EC private key that wraps the corresponding BC EC private key type, {@link ECPrivateKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedECPrivateKey extends AbstractWrappedECKey<ECPrivateKeyParameters> implements ECPrivateKey
{
  /** {@inheritDoc} */
  public WrappedECPrivateKey(final ECPrivateKeyParameters parameters)
  {
    super(parameters);
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getS()
  {
    return delegate.getD();
  }
}
