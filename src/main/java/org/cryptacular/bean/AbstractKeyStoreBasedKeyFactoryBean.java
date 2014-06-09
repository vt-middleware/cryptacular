/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.security.KeyStore;

/**
 * Abstract base class for all keystore-based factory beans that produce keys.
 *
 * @author  Middleware Services
 */
public abstract class AbstractKeyStoreBasedKeyFactoryBean
{
  /** Keystore containing secret key. */
  private KeyStore keyStore;

  /** Alias of keystore entry containing secret key. */
  private String alias;

  /** Password required to read key entry. */
  private String password;


  /** @return  Keystore that contains the {@link java.security.Key}. */
  public KeyStore getKeyStore()
  {
    return keyStore;
  }


  /**
   * Sets the keystore that contains the {@link java.security.Key}.
   *
   * @param  keyStore  Non-null keystore.
   */
  public void setKeyStore(final KeyStore keyStore)
  {
    this.keyStore = keyStore;
  }


  /**
   * @return  Alias that specifies the {@link KeyStore} entry containing the
   * {@link java.security.Key}.
   */
  public String getAlias()
  {
    return alias;
  }


  /**
   * Sets the alias that specifies the {@link KeyStore} entry containing the
   * {@link java.security.Key}.
   *
   * @param  alias  Keystore alias of secret key entry.
   */
  public void setAlias(final String alias)
  {
    this.alias = alias;
  }


  /**
   * Sets the password used to access the {@link java.security.Key} entry.
   *
   * @param  password  Key entry password.
   */
  public void setPassword(final String password)
  {
    this.password = password;
  }


  /**
   * @return  Keystore entry associated with {@link #alias}.
   */
  protected KeyStore.Entry getEntry()
  {
    try {
      return keyStore.getEntry(
          alias,
          new KeyStore.PasswordProtection(password.toCharArray()));
    } catch (Exception e) {
      throw new IllegalStateException("Error reading " + alias + " entry", e);
    }
  }
}
