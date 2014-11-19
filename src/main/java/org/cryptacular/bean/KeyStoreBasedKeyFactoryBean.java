/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.security.Key;
import java.security.KeyStore;

/**
 * Factory that produces either a {@link javax.crypto.SecretKey} or {@link
 * java.security.PrivateKey}.
 *
 * <p>from a {@link KeyStore}.</p>
 *
 * @param  <T>  Type of key, either {@link javax.crypto.SecretKey} or {@link
 * java.security.PrivateKey}.
 *
 * @author  Middleware Services
 */
public class KeyStoreBasedKeyFactoryBean<T extends Key>
  implements FactoryBean<T>
{

  /** Keystore containing secret key. */
  private KeyStore keyStore;

  /** Alias of keystore entry containing secret key. */
  private String alias;

  /** Password required to read key entry. */
  private String password;


  /** Creates a new instance. */
  public KeyStoreBasedKeyFactoryBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  keyStore  Key store containing encryption key.
   * @param  alias  Name of encryption key entry in key store.
   * @param  password  Password used to decrypt key entry in keystore.
   */
  public KeyStoreBasedKeyFactoryBean(
    final KeyStore keyStore,
    final String alias,
    final String password)
  {
    setKeyStore(keyStore);
    setAlias(alias);
    setPassword(password);
  }


  /** @return  Keystore that contains the {@link #keyStore}. */
  public KeyStore getKeyStore()
  {
    return keyStore;
  }


  /**
   * Sets the keystore that contains the key.
   *
   * @param  keyStore  Non-null keystore.
   */
  public void setKeyStore(final KeyStore keyStore)
  {
    this.keyStore = keyStore;
  }


  /**
   * @return  Alias that specifies the {@link KeyStore} entry containing the
   * key.
   */
  public String getAlias()
  {
    return alias;
  }


  /**
   * Sets the alias that specifies the {@link KeyStore} entry containing the
   * key.
   *
   * @param  alias  Keystore alias of key entry.
   */
  public void setAlias(final String alias)
  {
    this.alias = alias;
  }


  /**
   * Sets the password used to access the key entry.
   *
   * @param  password  Key entry password.
   */
  public void setPassword(final String password)
  {
    this.password = password;
  }


  /** {@inheritDoc} */
  @Override
  @SuppressWarnings("unchecked")
  public T newInstance()
  {
    final Key key;
    try {
      key = keyStore.getKey(alias, password.toCharArray());
    } catch (Exception e) {
      throw new RuntimeException("Error accessing " + alias, e);
    }
    return (T) key;
  }
}
