package org.cryptosis.adapter;

import java.math.BigInteger;

import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * Base class for RSA wrapped keys.
 *
 * @author Marvin S. Addison
 */
public class AbstractWrappedRSAKey<T extends RSAKeyParameters> extends AbstractWrappedKey<T>
{
  /** RSA algorithm name. */
  private static final String ALGORITHM = "RSA";


  /** {@inheritDoc} */
  public AbstractWrappedRSAKey(final T wrappedKey)
  {
    super(wrappedKey);
  }


  /**
   * @return  Gets the RSA modulus.
   */
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
