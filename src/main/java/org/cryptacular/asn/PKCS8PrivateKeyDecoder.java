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

package org.cryptacular.asn;

import java.io.IOException;

import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.cryptacular.pbe.EncryptionScheme;
import org.cryptacular.pbe.PBES1Algorithm;
import org.cryptacular.pbe.PBES1EncryptionScheme;
import org.cryptacular.pbe.PBES2EncryptionScheme;

/**
 * Decodes PEM or DER-encoded PKCS#8 private keys.
 *
 * @author Marvin S. Addison
 */
public class PKCS8PrivateKeyDecoder extends AbstractPrivateKeyDecoder<AsymmetricKeyParameter>
{
  /** {@inheritDoc} */
  @Override
  protected byte[] decryptKey(final byte[] encrypted, final char[] password)
  {
    final EncryptionScheme scheme;
    final EncryptedPrivateKeyInfo ki = EncryptedPrivateKeyInfo.getInstance(tryConvertPem(encrypted));
    final AlgorithmIdentifier alg = ki.getEncryptionAlgorithm();
    if (PKCSObjectIdentifiers.id_PBES2.equals(alg.getAlgorithm())) {
      scheme = new PBES2EncryptionScheme(PBES2Parameters.getInstance(alg.getParameters()), password);
    } else {
      scheme = new PBES1EncryptionScheme(
        PBES1Algorithm.fromOid(alg.getAlgorithm().getId()),
        PBEParameter.getInstance(alg.getParameters()),
        password);
    }
    return scheme.decrypt(ki.getEncryptedData());
  }


  /** {@inheritDoc} */
  @Override
  protected AsymmetricKeyParameter decodeASN1(final byte[] encoded)
  {
    try {
      return PrivateKeyFactory.createKey(encoded);
    } catch (IOException e) {
      throw new RuntimeException("ASN.1 decoding error", e);
    }
  }
}
