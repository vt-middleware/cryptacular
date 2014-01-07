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

package org.cryptacular.adapter;

import java.security.Key;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * JCE/JDK key base class that wraps a BC native private key.
 *
 * @author Marvin S. Addison
 * @param  <T>  Asymmetric key parameters type wrapped by this class.
 */
public abstract class AbstractWrappedKey<T extends AsymmetricKeyParameter> implements Key
{
  /** Wrapped key. */
  protected final T delegate;


  /**
   * Creates a new instance that wraps the given BC key.
   *
   * @param  wrappedKey  BC key to wrap.
   */
  public AbstractWrappedKey(final T wrappedKey)
  {
    if (wrappedKey == null) {
      throw new IllegalArgumentException("Wrapped key cannot be null.");
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
