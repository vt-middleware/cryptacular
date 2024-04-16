/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * JCE/JDK EC public key that wraps the corresponding BC EC public key type, {@link ECPublicKeyParameters}.
 *
 * @author  Middleware Services
 */
public class WrappedECPublicKey extends AbstractWrappedECKey<ECPublicKeyParameters> implements ECPublicKey
{

  /** serialVersionUID. */
  private static final long serialVersionUID = -8218654577692012657L;

  /**
   * Creates a new instance that wraps the given key.
   *
   * @param  wrappedKey  EC key to wrap.
   */
  public WrappedECPublicKey(final ECPublicKeyParameters wrappedKey)
  {
    super(wrappedKey);
  }


  @Override
  public ECPoint getW()
  {
    return
      new ECPoint(
        delegate.getQ().normalize().getXCoord().toBigInteger(),
        delegate.getQ().normalize().getYCoord().toBigInteger());
  }

}
