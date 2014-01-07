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

package org.cryptosis.adapter;

import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;

import org.bouncycastle.crypto.params.DSAPublicKeyParameters;

/**
 * JCE/JDK DSA public key that wraps the corresponding BC DSA public key type, {@link DSAPublicKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedDSAPublicKey extends AbstractWrappedDSAKey<DSAPublicKeyParameters> implements DSAPublicKey
{
  /**
   * Creates a new instance that wraps the given key.
   *
   * @param  wrappedKey  DSA key to wrap.
   */
  public WrappedDSAPublicKey(final DSAPublicKeyParameters wrappedKey)
  {
    super(wrappedKey);
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getY()
  {
    return delegate.getY();
  }

}
