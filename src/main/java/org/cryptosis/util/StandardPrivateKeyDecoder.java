package org.cryptosis.util;

import java.security.PrivateKey;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.cryptosis.jce.WrappedDSAPrivateKey;
import org.cryptosis.jce.WrappedECPrivateKey;
import org.cryptosis.jce.WrappedRSAPrivateCrtKey;

/**
 * Produces {@PrivateKey} objects containing private key data from ASN.1 encoded bytes in DER or PEM format.
 * This class handles encrypted private keys in PKCS#8 format or OpenSSL "traditional" format.
 *
 * @author Marvin S. Addison
 */
public class StandardPrivateKeyDecoder implements PrivateKeyDecoder<PrivateKey>
{
  /** Operations delegate to this for decoding then convert returned object to JDK PrivateKey. */
  private final AsymmetricKeyParameterDecoder delegate = new AsymmetricKeyParameterDecoder();


  /** {@inheritDoc} */
  @Override
  public PrivateKey decode(final byte[] encoded)
  {
    return convertKey(delegate.decode(encoded));
  }


  /** {@inheritDoc} */
  @Override
  public PrivateKey decode(byte[] encrypted, char[] password)
  {
    return convertKey(delegate.decode(encrypted, password));
  }


  /**
   * Converts a BC private key to corresponding JDK/JCE object.
   *
   * @param  bcKey  BC private key.
   *
   * @return  JCE/JCK private key.
   */
  private static PrivateKey convertKey(final AsymmetricKeyParameter bcKey)
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
}
