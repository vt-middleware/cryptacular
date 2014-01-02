package org.cryptosis.adapter;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;

import org.bouncycastle.crypto.params.DSAKeyParameters;

/**
 * Base class for DSA wrapped keys.
 *
 * @author Marvin S. Addison
 */
public abstract class AbstractWrappedDSAKey<T extends DSAKeyParameters> extends AbstractWrappedKey<T>
{
  /** DSA algorithm name. */
  private static final String ALGORITHM = "DSA";


  /** {@inheritDoc} */
  public AbstractWrappedDSAKey(final T parameters)
  {
    super(parameters);
  }


  /**
   * @return  DSA key parameters.
   */
  public DSAParams getParams()
  {
    return new DSAParams()
    {
      @Override
      public BigInteger getP()
      {
        return delegate.getParameters().getP();
      }

      @Override
      public BigInteger getQ()
      {
        return delegate.getParameters().getQ();
      }

      @Override
      public BigInteger getG()
      {
        return delegate.getParameters().getG();
      }
    };
  }


  /** {@inheritDoc} */
  @Override
  public String getAlgorithm()
  {
    return ALGORITHM;
  }
}
