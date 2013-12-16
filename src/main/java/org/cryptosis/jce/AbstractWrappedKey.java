package org.cryptosis.jce;

import java.security.Key;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * JCE/JDK key base class that wraps a BC native private key.
 *
 * @author Marvin S. Addison
 */
public abstract class AbstractWrappedKey<T extends AsymmetricKeyParameter> implements Key
{
  /** Wrapped key. */
  protected final T delegate;


  public AbstractWrappedKey(final T wrappedKey)
  {
    if (wrappedKey == null) {
      throw new IllegalArgumentException("Wrapped key cannot be null.");
    }
    if (!wrappedKey.isPrivate()) {
      throw new IllegalArgumentException(wrappedKey + " is not a private key");
    }
    delegate = wrappedKey;
  }


  /**
   * @return  Null to indicate that encoding is not supported.
   */
  @Override
  public String getFormat()
  {
    return null;
  }


  /**
   * @return  Null to indicate that encoding is not supported.
   */
  @Override
  public byte[] getEncoded()
  {
    return null;
  }
}
