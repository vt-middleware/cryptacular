/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.security.Key;
import java.security.KeyStore;
import javax.crypto.SecretKey;

/**
 * Factory that produces a {@link SecretKey} from a {@link KeyStore}.
 *
 * @author  Middleware Services
 */
public class KeyStoreBasedSecretKeyFactoryBean implements FactoryBean<SecretKey>
{

  /** Keystore containing secret key. */
  private KeyStore keyStore;

  /** Alias of keystore entry containing secret key. */
  private String alias;

  /** Password required to read key entry. */
  private String password;


  /** Creates a new instance. */
  public KeyStoreBasedSecretKeyFactoryBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  keyStore  Key store containing encryption key.
   * @param  alias  Name of encryption key entry in key store.
   * @param  password  Password used to decrypt key entry in keystore.
   */
  public KeyStoreBasedSecretKeyFactoryBean(
    final KeyStore keyStore,
    final String alias,
    final String password)
  {
    setKeyStore(keyStore);
    setAlias(alias);
    setPassword(password);
  }


  /** @return  Keystore that contains the {@link SecretKey}. */
  public KeyStore getKeyStore()
  {
    return keyStore;
  }


  /**
   * Sets the keystore that contains the {@link SecretKey}.
   *
   * @param  keyStore  Non-null keystore.
   */
  public void setKeyStore(final KeyStore keyStore)
  {
    this.keyStore = keyStore;
  }


  /**
   * @return  Alias that specifies the {@link KeyStore} entry containing the
   * {@link SecretKey}.
   */
  public String getAlias()
  {
    return alias;
  }


  /**
   * Sets the alias that specifies the {@link KeyStore} entry containing the
   * {@link SecretKey}.
   *
   * @param  alias  Keystore alias of secret key entry.
   */
  public void setAlias(final String alias)
  {
    this.alias = alias;
  }


  /**
   * Sets the password used to access the {@link SecretKey} entry.
   *
   * @param  password  Key entry password.
   */
  public void setPassword(final String password)
  {
    this.password = password;
  }


  /** {@inheritDoc} */
  @Override
  public SecretKey newInstance()
  {
    final Key key;
    try {
      key = keyStore.getKey(alias, password.toCharArray());
    } catch (Exception e) {
      throw new RuntimeException("Error accessing " + alias, e);
    }
    if (key instanceof SecretKey) {
      return (SecretKey) key;
    }
    throw new RuntimeException(alias + " is not a secret key");
  }
}
