package org.cryptosis.jce;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;

import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * JCE/JDK RSA private key that wraps the corresponding BC RSA private key type, {@link RSAPrivateCrtKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedRSAPrivateCrtKey extends AbstractWrappedKey<RSAPrivateCrtKeyParameters> implements RSAPrivateCrtKey
{
  /** DSA algorithm name. */
  private static final String ALGORITHM = "RSA";


  /**
   * Creates a new instance that wraps the given BC RSA private key.
   *
   * @param  parameters  BC RSA private (certificate) key.
   */
  public WrappedRSAPrivateCrtKey(final RSAPrivateCrtKeyParameters parameters)
  {
    super(parameters);
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getPublicExponent()
  {
    return delegate.getPublicExponent();
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getPrimeP()
  {
    return delegate.getP();
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getPrimeQ()
  {
    return delegate.getQ();
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getPrimeExponentP()
  {
    return delegate.getDP();
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getPrimeExponentQ()
  {
    return delegate.getDQ();
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getCrtCoefficient()
  {
    return delegate.getQInv();
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getPrivateExponent()
  {
    return delegate.getExponent();
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getModulus()
  {
    return delegate.getModulus();
  }


  /** {@inheritDoc} */
  @Override
  public String getAlgorithm()
  {
    return ALGORITHM;
  }
}
