/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * JCE/JDK RSA private key that wraps the corresponding BC RSA private key type, {@link RSAPrivateCrtKeyParameters}.
 *
 * @author  Middleware Services
 */
public class WrappedRSAPrivateCrtKey extends AbstractWrappedRSAKey<RSAPrivateCrtKeyParameters>
  implements RSAPrivateCrtKey
{

  /** serialVersionUID. */
  private static final long serialVersionUID = 99555083744578278L;

  /**
   * Creates a new instance that wraps the given BC RSA private key.
   *
   * @param  parameters  BC RSA private (certificate) key.
   */
  public WrappedRSAPrivateCrtKey(final RSAPrivateCrtKeyParameters parameters)
  {
    super(parameters);
  }


  @Override
  public BigInteger getPublicExponent()
  {
    return delegate.getPublicExponent();
  }


  @Override
  public BigInteger getPrimeP()
  {
    return delegate.getP();
  }


  @Override
  public BigInteger getPrimeQ()
  {
    return delegate.getQ();
  }


  @Override
  public BigInteger getPrimeExponentP()
  {
    return delegate.getDP();
  }


  @Override
  public BigInteger getPrimeExponentQ()
  {
    return delegate.getDQ();
  }


  @Override
  public BigInteger getCrtCoefficient()
  {
    return delegate.getQInv();
  }


  @Override
  public BigInteger getPrivateExponent()
  {
    return delegate.getExponent();
  }


}
