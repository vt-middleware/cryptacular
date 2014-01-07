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

import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * Static factory with methods to convert from BC type to the corresponding JCE type.
 * @author Marvin S. Addison
 */
public final class Converter
{
  /** Private constructor of utility class. */
  private Converter() {}


  /**
   * Produces a {@link PrivateKey} from a BC private key type.
   *
   * @param  bcKey  BC private key.
   *
   * @return  JCE private key.
   */
  public static PrivateKey convertPrivateKey(final AsymmetricKeyParameter bcKey)
  {
    if (!bcKey.isPrivate()) {
      throw new IllegalArgumentException("AsymmetricKeyParameter is not a private key: " + bcKey);
    }
    final PrivateKey key;
    if (bcKey instanceof DSAPrivateKeyParameters) {
      key = new WrappedDSAPrivateKey((DSAPrivateKeyParameters) bcKey);
    } else if (bcKey instanceof ECPrivateKeyParameters) {
      key = new WrappedECPrivateKey((ECPrivateKeyParameters) bcKey);
    } else if (bcKey instanceof RSAPrivateCrtKeyParameters) {
      key = new WrappedRSAPrivateCrtKey((RSAPrivateCrtKeyParameters) bcKey);
    } else {
      throw new IllegalArgumentException("Unsupported private key " + bcKey);
    }
    return key;
  }


  /**
   * Produces a {@link PublicKey} from a BC public key type.
   *
   * @param  bcKey  BC public key.
   *
   * @return  JCE public key.
   */
  public static PublicKey convertPublicKey(final AsymmetricKeyParameter bcKey)
  {
    if (bcKey.isPrivate()) {
      throw new IllegalArgumentException("AsymmetricKeyParameter is not a public key: " + bcKey);
    }
    final PublicKey key;
    if (bcKey instanceof DSAPublicKeyParameters) {
      key = new WrappedDSAPublicKey((DSAPublicKeyParameters) bcKey);
    } else if (bcKey instanceof ECPublicKeyParameters) {
      key = new WrappedECPublicKey((ECPublicKeyParameters) bcKey);
    } else if (bcKey instanceof RSAKeyParameters) {
      key = new WrappedRSAPublicKey((RSAKeyParameters) bcKey);
    } else {
      throw new IllegalArgumentException("Unsupported public key " + bcKey);
    }
    return key;
  }
}
