package org.cryptosis.jce;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;

import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;

/**
 * JCE/JDK DSA private key that wraps the corresponding BC DSA private key type, {@link DSAPrivateKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedDSAPrivateKey extends AbstractWrappedKey<DSAPrivateKeyParameters> implements DSAPrivateKey
{
  /** DSA algorithm name. */
  private static final String ALGORITHM = "DSA";


  /**
   * Creates a new instance that wraps the given BC DSA private key.
   *
   * @param  parameters  BC DSA private key.
   */
  public WrappedDSAPrivateKey(final DSAPrivateKeyParameters parameters)
  {
    super(parameters);
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getX()
  {
    return delegate.getX();
  }


  /** {@inheritDoc} */
  @Override
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
