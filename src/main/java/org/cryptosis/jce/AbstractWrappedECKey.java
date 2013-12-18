package org.cryptosis.jce;

import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

/**
 * Base class for wrapped EC keys.
 *
 * @author Marvin S. Addison
 */
public class AbstractWrappedECKey<T extends ECKeyParameters> extends AbstractWrappedKey<T>
{
  /** Elliptic curve algorithm name. */
  private static final String ALGORITHM = "EC";


  /** {@inheritDoc} */
  public AbstractWrappedECKey(final T wrappedKey)
  {
    super(wrappedKey);
  }


  /** @return  EC domain parameters. */
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
