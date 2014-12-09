/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

/**
 * JCE/JDK EC private key that wraps the corresponding BC EC private key type,
 * {@link ECPrivateKeyParameters}.
 *
 * @author  Middleware Services
 */
public class WrappedECPrivateKey
  extends AbstractWrappedECKey<ECPrivateKeyParameters> implements ECPrivateKey
{

  /**
   * Creates a new instance that wraps the given key.
   *
   * @param  wrappedKey  EC key to wrap.
   */
  public WrappedECPrivateKey(final ECPrivateKeyParameters wrappedKey)
  {
    super(wrappedKey);
  }


  @Override
  public BigInteger getS()
  {
    return delegate.getD();
  }
}
