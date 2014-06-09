/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.security.KeyPair;
import java.security.KeyStore;

/**
 * Factory that produces a {@link KeyPair} from a {@link KeyStore}
 * {@link KeyStore.PrivateKeyEntry}.
 *
 * @author  Middleware Services
 */
public class KeyStoreBasedKeyPairFactoryBean
    extends AbstractKeyStoreBasedKeyFactoryBean
    implements FactoryBean<KeyPair>
{
  /** Creates a new instance. */
  public KeyStoreBasedKeyPairFactoryBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  keyStore  Key store containing encryption key.
   * @param  alias  Name of encryption key entry in key store.
   * @param  password  Password used to decrypt key entry in keystore.
   */
  public KeyStoreBasedKeyPairFactoryBean(
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
  public KeyPair newInstance()
  {
    final KeyStore.Entry entry = getEntry();
    if (entry instanceof KeyStore.PrivateKeyEntry) {
      final KeyStore.PrivateKeyEntry privateKeyEntry =
          (KeyStore.PrivateKeyEntry) entry;
      return new KeyPair(
          privateKeyEntry.getCertificate().getPublicKey(),
          privateKeyEntry.getPrivateKey());
    }
    throw new RuntimeException("Unexpected entry " + entry);
  }
}
