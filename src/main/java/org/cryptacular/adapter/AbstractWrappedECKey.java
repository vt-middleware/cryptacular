/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.math.ec.ECCurve;

/**
 * Base class for wrapped EC keys.
 *
 * @param  <T>  EC key parameters type.
 *
 * @author  Middleware Services
 */
public abstract class AbstractWrappedECKey<T extends ECKeyParameters> extends AbstractWrappedKey<T>
{

  /** Elliptic curve algorithm name. */
  private static final String ALGORITHM = "EC";


  /**
   * Creates a new instance that wraps the given key.
   *
   * @param  wrappedKey  Key to wrap.
   */
  public AbstractWrappedECKey(final T wrappedKey)
  {
    super(wrappedKey);
  }


  /** @return  EC domain parameters. */
  public ECParameterSpec getParams()
  {
    final ECDomainParameters params = delegate.getParameters();
    return
      new ECParameterSpec(
        convertCurve(params.getCurve(), params.getSeed()),
        new ECPoint(
          params.getG().normalize().getXCoord().toBigInteger(),
          params.getG().normalize().getYCoord().toBigInteger()),
        params.getN(),
        params.getH().intValue());
  }


  @Override
  public String getAlgorithm()
  {
    return ALGORITHM;
  }

  private static EllipticCurve convertCurve(final ECCurve curve, final byte[] seed)
  {
    final ECField field;
    if (curve instanceof ECCurve.Fp) {
      field = new ECFieldFp(((ECCurve.Fp) curve).getQ());
    } else {
      final ECCurve.F2m f2m = (ECCurve.F2m) curve;
      final int m = f2m.getM();
      final int k1 = f2m.getK1();
      final int k2 = f2m.getK2();
      final int k3 = f2m.getK3();
      if (k2 == 0) {
        field = new ECFieldF2m(m, new int[]{k1});
      } else {
        field = new ECFieldF2m(m, new int[]{k3, k2, k1});
      }
    }
    return new EllipticCurve(
      field,
      curve.getA().toBigInteger(),
      curve.getB().toBigInteger(),
      seed);
  }
}

