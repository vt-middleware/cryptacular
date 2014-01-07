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

package org.cryptosis.bean;

import java.security.KeyStore;
import java.security.KeyStoreException;

import org.cryptosis.io.Resource;

/**
 * Factory bean that produces a {@link KeyStore} from a file or URI.
 *
 * @author Marvin S. Addison
 */
public class KeyStoreFactoryBean implements FactoryBean<KeyStore>
{
  /** Default keystore type, {@value #DEFAULT_TYPE} */
  public static final String DEFAULT_TYPE = "JCEKS";

  /** Keystore type, e.g. JKS, JCEKS, BKS. */
  private String type = DEFAULT_TYPE;

  /** Resource that provides encoded keystore data. */
  private Resource resource;

  /** Keystore password. */
  private String password;


  /**
   * @return  Keystore type.
   */
  public String getType()
  {
    return type;
  }


  /**
   * Sets the keystore type.
   *
   * @param  type  JCEKS (default), JKS, PKCS12, or BKS. <strong>NOTE:</strong> BKS type is supported only when BC
   *               provider is installed.
   */
  public void setType(final String type)
  {
    this.type = type;
  }


  /**
   * @return  Resource that provides encoded keystore data.
   */
  public Resource getResource()
  {
    return resource;
  }


  /**
   * Sets the resource that provides encoded keystore data.
   *
   * @param  resource  Keystore resource.
   */
  public void setResource(final Resource resource)
  {
    this.resource = resource;
  }


  /**
   * Sets the keystore password required to decrypt an encrypted keystore.
   *
   * @param  password  Keystore password.
   */
  public void setPassword(final String password)
  {
    this.password = password;
  }


  /** {@inheritDoc} */
  @Override
  public KeyStore newInstance()
  {
    if (resource == null) {
      throw new IllegalStateException("Must provide resource.");
    }
    final KeyStore store;
    try {
      store = KeyStore.getInstance(type);
    } catch (KeyStoreException e) {
      String message = "Unsupported keystore type " + type;
      if ("BKS".equalsIgnoreCase(type)) {
        message += ". Is BC provider installed?";
      }
      throw new IllegalArgumentException(message, e);
    }
    try {
      store.load(resource.getInputStream(), password.toCharArray());
    } catch (Exception e) {
      throw new RuntimeException("Error loading keystore", e);
    }
    return store;
  }
}
