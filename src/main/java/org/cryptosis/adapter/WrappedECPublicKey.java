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

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * JCE/JDK EC private key that wraps the corresponding BC EC private key type, {@link ECPrivateKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedECPublicKey extends AbstractWrappedECKey<ECPublicKeyParameters> implements ECPublicKey
{
  /**
   * Creates a new instance that wraps the given key.
   *
   * @param  wrappedKey  EC key to wrap.
   */
  public WrappedECPublicKey(final ECPublicKeyParameters wrappedKey)
  {
    super(wrappedKey);
  }


  /** {@inheritDoc} */
  @Override
  public ECPoint getW()
  {
    return new ECPoint(
      delegate.getQ().getX().toBigInteger(),
      delegate.getQ().getY().toBigInteger());
  }

}
