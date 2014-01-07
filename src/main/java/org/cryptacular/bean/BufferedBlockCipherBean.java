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

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.cryptacular.CiphertextHeader;
import org.cryptacular.adapter.BufferedBlockCipherAdapter;
import org.cryptacular.spec.Spec;

/**
 * Cipher bean that performs symmetric encryption/decryption using a standard block cipher in a standard mode
 * (e.g. CBC, OFB) with padding to support processing inputs of arbitrary length.
 *
 * @author Marvin S. Addison
 */
public class BufferedBlockCipherBean extends AbstractBlockCipherBean
{
  /** Block cipher specification (algorithm, mode, padding). */
  private Spec<BufferedBlockCipher> blockCipherSpec;


  /**
   * @return  Block cipher specification.
   */
  public Spec<BufferedBlockCipher> getBlockCipherSpec()
  {
    return blockCipherSpec;
  }


  /**
   * Sets the block cipher specification.
   *
   * @param  blockCipherSpec  Describes a block cipher in terms of algorithm, mode, and padding.
   */
  public void setBlockCipherSpec(final Spec<BufferedBlockCipher> blockCipherSpec)
  {
    this.blockCipherSpec = blockCipherSpec;
  }


  /** {@inheritDoc} */
  protected BufferedBlockCipherAdapter newCipher(final CiphertextHeader header, final boolean mode)
  {
    final BufferedBlockCipher cipher = blockCipherSpec.newInstance();
    CipherParameters params = new KeyParameter(lookupKey(header.getKeyName()).getEncoded());
    final String algName = cipher.getUnderlyingCipher().getAlgorithmName();
    if (algName.endsWith("CBC") || algName.endsWith("OFB") || algName.endsWith("CFB")) {
      params = new ParametersWithIV(params, header.getNonce());
    }
    cipher.init(mode, params);
    return new BufferedBlockCipherAdapter(cipher);
  }
}
