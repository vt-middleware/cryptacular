/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import java.math.BigInteger;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * Base class for RSA wrapped keys.
 *
 * @param  <T>  RSA key parameters type handled by this class.
 *
 * @author  Middleware Services
 */
public abstract class AbstractWrappedRSAKey<T extends RSAKeyParameters>
  extends AbstractWrappedKey<T>
{

  /** RSA algorithm name. */
  private static final String ALGORITHM = "RSA";


  /**
   * Creates a new instance that wraps the given key.
   *
   * @param  wrappedKey  Key to wrap.
   */
  public AbstractWrappedRSAKey(final T wrappedKey)
  {
    super(wrappedKey);
  }


  /** @return  Gets the RSA modulus. */
  public BigInteger getModulus()
  {
    return delegate.getModulus();
  }


  @Override
  public String getAlgorithm()
  {
    return ALGORITHM;
  }
}
