package org.cryptosis.jce;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * Static factory with methods to convert from BC type to the corresponding JCE type.
 * @author Marvin S. Addison
 */
public final class Converter
{
  /** Private constructor of utility class. */
  private Converter() {}


  /**
   * Produces a {@link PrivateKey} from a BC private key type.
   *
   * @param  bcKey  BC private key.
   *
   * @return  JCE private key.
   */
  public static PrivateKey convertPrivateKey(final AsymmetricKeyParameter bcKey)
  {
    if (!bcKey.isPrivate()) {
      throw new IllegalArgumentException("AsymmetricKeyParameter is not a private key: " + bcKey);
    }
    final PrivateKey key;
    if (bcKey instanceof DSAPrivateKeyParameters) {
      key = new WrappedDSAPrivateKey((DSAPrivateKeyParameters) bcKey);
    } else if (bcKey instanceof ECPrivateKeyParameters) {
      key = new WrappedECPrivateKey((ECPrivateKeyParameters) bcKey);
    } else if (bcKey instanceof RSAPrivateCrtKeyParameters) {
      key = new WrappedRSAPrivateCrtKey((RSAPrivateCrtKeyParameters) bcKey);
    } else {
      throw new IllegalArgumentException("Unsupported private key " + bcKey);
    }
    return key;
  }


  /**
   * Produces a {@link PublicKey} from a BC public key type.
   *
   * @param  bcKey  BC public key.
   *
   * @return  JCE public key.
   */
  public static PublicKey convertPublicKey(final AsymmetricKeyParameter bcKey)
  {
    if (bcKey.isPrivate()) {
      throw new IllegalArgumentException("AsymmetricKeyParameter is not a public key: " + bcKey);
    }
    final PublicKey key;
    if (bcKey instanceof DSAPublicKeyParameters) {
      key = new WrappedDSAPublicKey((DSAPublicKeyParameters) bcKey);
    } else if (bcKey instanceof ECPublicKeyParameters) {
      key = new WrappedECPublicKey((ECPublicKeyParameters) bcKey);
    } else if (bcKey instanceof RSAKeyParameters) {
      key = new WrappedRSAPublicKey((RSAKeyParameters) bcKey);
    } else {
      throw new IllegalArgumentException("Unsupported public key " + bcKey);
    }
    return key;
  }
}
