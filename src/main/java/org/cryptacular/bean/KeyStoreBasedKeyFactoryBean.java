/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import org.cryptacular.CryptUtil;
import org.cryptacular.CryptoException;

/**
 * Factory that produces either a {@link javax.crypto.SecretKey} or {@link java.security.PrivateKey}.
 *
 * <p>from a {@link KeyStore}.</p>
 *
 * @param  <T>  Type of key, either {@link javax.crypto.SecretKey} or {@link java.security.PrivateKey}.
 *
 * @author  Middleware Services
 */
public class KeyStoreBasedKeyFactoryBean<T extends Key> implements FactoryBean<T>
{

  /** Keystore containing secret key. */
  private final KeyStore keyStore;

  /** Alias of keystore entry containing secret key. */
  private final String alias;

  /** Password required to read key entry. */
  private final String password;


  /**
   * Creates a new keystore based key factory bean.
   *
   * @param  keyStore  Key store containing encryption key.
   * @param  alias  Name of encryption key entry in key store.
   * @param  password  Password used to decrypt key entry in keystore.
   */
  public KeyStoreBasedKeyFactoryBean(final KeyStore keyStore, final String alias, final String password)
  {
    this.keyStore = CryptUtil.assertNotNullArg(keyStore, "KeyStore cannot be null");
    this.alias = alias;
    this.password = password;
  }


  /** @return  Keystore that contains the {@link #keyStore}. */
  public KeyStore getKeyStore()
  {
    return keyStore;
  }


  /** @return  Alias that specifies the {@link KeyStore} entry containing the key. */
  public String getAlias()
  {
    return alias;
  }


  @Override
  @SuppressWarnings("unchecked")
  public T newInstance()
  {
    final Key key;
    try {
      key = keyStore.getKey(alias, password.toCharArray());
    } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
      throw new CryptoException("Error accessing keystore entry " + alias, e);
    }
    return (T) key;
  }
}
