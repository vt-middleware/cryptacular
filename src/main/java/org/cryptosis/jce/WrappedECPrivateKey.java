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
public class WrappedECPrivateKey extends AbstractWrappedKey<ECPrivateKeyParameters> implements ECPrivateKey
{
  /** Elliptic curve algorithm name. */
  private static final String ALGORITHM = "EC";


  /**
   * Creates a new instance that wraps the given BC RSA private key.
   *
   * @param  parameters  BC RSA private (certificate) key.
   */
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


  /** {@inheritDoc} */
  @Override
  public ECParameterSpec getParams()
  {
    final ECDomainParameters params = delegate.getParameters();
    return new ECParameterSpec(
      EC5Util.convertCurve(params.getCurve(), params.getSeed()),
      new ECPoint(
        params.getG().getX().toBigInteger(),
        params.getG().getY().toBigInteger()),
      params.getN(),
      params.getH().intValue());
  }


  /** {@inheritDoc} */
  @Override
  public String getAlgorithm()
  {
    return ALGORITHM;
  }
}
