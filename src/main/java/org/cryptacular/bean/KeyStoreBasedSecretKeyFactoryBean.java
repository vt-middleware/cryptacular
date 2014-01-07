/*
 * Licensed to Virginia Tech under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Virginia Tech licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.cryptacular.bean;

import java.security.Key;
import java.security.KeyStore;
import javax.crypto.SecretKey;

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
   * @return  Keystore that contains the {@link SecretKey}.
   */
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
   * @return  Alias that specifies the {@link KeyStore} entry containing the {@link SecretKey}.
   */
  public String getAlias()
  {
    return alias;
  }


  /**
   * Sets the alias that specifies the {@link KeyStore} entry containing the {@link SecretKey}.
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
