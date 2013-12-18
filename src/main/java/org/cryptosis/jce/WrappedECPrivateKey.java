package org.cryptosis.jce;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

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
