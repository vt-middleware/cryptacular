package org.cryptosis.jce;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * JCE/JDK EC private key that wraps the corresponding BC EC private key type, {@link org.bouncycastle.crypto.params.ECPrivateKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedECPublicKey extends AbstractWrappedECKey<ECPublicKeyParameters> implements ECPublicKey
{
  /** {@inheritDoc} */
  public WrappedECPublicKey(final ECPublicKeyParameters parameters)
  {
    super(parameters);
  }


  /** {@inheritDoc} */
  @Override
  public ECPoint getW()
  {
    return new ECPoint(
      delegate.getQ().getX().toBigInteger(),
      delegate.getQ().getY().toBigInteger());
  }

}
