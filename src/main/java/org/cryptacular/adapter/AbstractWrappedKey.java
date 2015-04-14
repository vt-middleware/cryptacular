/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import java.io.IOException;
import java.security.Key;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

/**
 * JCE/JDK key base class that wraps a BC native private key.
 *
 * @param  <T>  Asymmetric key parameters type wrapped by this class.
 *
 * @author  Middleware Services
 */
public abstract class AbstractWrappedKey<T extends AsymmetricKeyParameter> implements Key
{

  /** PKCS#8 format identifier used with private keys. */
  public static final String PKCS8_FORMAT = "PKCS#8";

  /** X.509 format identifier used with private keys. */
  public static final String X509_FORMAT = "X.509";


  /** Wrapped key. */
  protected final T delegate;


  /**
   * Creates a new instance that wraps the given BC key.
   *
   * @param  wrappedKey  BC key to wrap.
   */
  public AbstractWrappedKey(final T wrappedKey)
  {
    if (wrappedKey == null) {
      throw new IllegalArgumentException("Wrapped key cannot be null.");
    }
    delegate = wrappedKey;
  }


  /** @return  {@value #PKCS8_FORMAT} in the case of a private key, otherwise {@link #X509_FORMAT}. */
  @Override
  public String getFormat()
  {
    if (delegate.isPrivate()) {
      return PKCS8_FORMAT;
    }
    return X509_FORMAT;
  }


  /**
   * @return  Encoded PrivateKeyInfo structure in the case of a private key, otherwise an encoded SubjectPublicKeyInfo
   *          structure.
   */
  @Override
  public byte[] getEncoded()
  {
    try {
      if (delegate.isPrivate()) {
        return PrivateKeyInfoFactory.createPrivateKeyInfo(delegate).getEncoded();
      }
      return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(delegate).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException("Key encoding error.", e);
    }
  }
}
