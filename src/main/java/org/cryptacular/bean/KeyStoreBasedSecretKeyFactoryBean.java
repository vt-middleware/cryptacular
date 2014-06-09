/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.security.KeyStore;
import javax.crypto.SecretKey;

/**
 * Factory that produces a {@link SecretKey} from a {@link KeyStore}.
 *
 * @author  Middleware Services
 */
public class KeyStoreBasedSecretKeyFactoryBean
        extends AbstractKeyStoreBasedKeyFactoryBean
        implements FactoryBean<SecretKey>
{
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


    /** {@inheritDoc} */
  @Override
  public SecretKey newInstance()
  {
    final KeyStore.Entry entry = getEntry();
    if (entry instanceof KeyStore.SecretKeyEntry) {
      return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
    }
    throw new RuntimeException("Unexpected entry " + entry);
  }
}
