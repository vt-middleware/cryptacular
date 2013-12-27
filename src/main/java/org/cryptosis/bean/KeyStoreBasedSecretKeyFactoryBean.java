package org.cryptosis.bean;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyStore;

/**
 * Factory that produces a {@link SecretKey} from a {@link KeyStore}.
 *
 * @author Marvin S. Addison
 */
public class KeyStoreBasedSecretKeyFactoryBean implements FactoryBean<SecretKey>
{
  /** Keystore containing secret key. */
  private KeyStore keyStore;

  /** Alias of keystore entry containing secret key. */
  private String alias;

  /** Password required to read key entry. */
  private String password;


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
   * Sets the alias that specifies the {@link KeyStore} entry containing the {@link SecretKey}.
   *
   * @param  alias  Keystore alias of secret key entry.
   */
  public void setAlias(String alias)
  {
    this.alias = alias;
  }


  /**
   * Sets the password used to access the {@link SecretKey} entry.
   *
   * @param  password  Key entry password.
   */
  public void setPassword(String password)
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
