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

package org.cryptosis.asn;

import java.io.IOException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.cryptosis.util.PemUtil;

/**
 * Decodes public keys formatted in an X.509 SubjectPublicKeyInfo structure in either PEM or DER encoding.
 *
 * @author Marvin S. Addison
 */
public class PublicKeyDecoder implements ASN1Decoder<AsymmetricKeyParameter>
{
  /** {@inheritDoc} */
  @Override
  public AsymmetricKeyParameter decode(final byte[] encoded, final Object... args)
  {
    try {
      if (PemUtil.isPem(encoded)) {
        return PublicKeyFactory.createKey(PemUtil.decode(encoded));
      }
      return PublicKeyFactory.createKey(encoded);
    } catch (IOException e) {
      throw new RuntimeException("ASN.1 decoding error", e);
    }
  }
}
