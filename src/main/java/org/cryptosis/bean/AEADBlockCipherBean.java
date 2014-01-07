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

import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.cryptosis.CiphertextHeader;
import org.cryptosis.adapter.AEADBlockCipherAdapter;
import org.cryptosis.spec.Spec;

/**
 * Cipher bean that performs encryption with a block cipher in AEAD mode (e.g. GCM, CCM).
 *
 * @author Marvin S. Addison
 */
public class AEADBlockCipherBean extends AbstractBlockCipherBean
{
  /** Mac size in bits. */
  public static final int MAC_SIZE_BITS = 128;

  /** AEAD block cipher specification (algorithm, mode, padding). */
  private Spec<AEADBlockCipher> blockCipherSpec;


  /**
   * Sets the AEAD block cipher specification.
   *
   * @param  blockCipherSpec  Describes a block cipher in terms of algorithm, mode, and padding.
   */
  public void setBlockCipherSpec(final Spec<AEADBlockCipher> blockCipherSpec)
  {
    this.blockCipherSpec = blockCipherSpec;
  }


  /**
   * {@inheritDoc}
   */
  @Override
  public void encrypt(final InputStream input, final OutputStream output)
  {
    if (blockCipherSpec.toString().endsWith("CCM")) {
      throw new UnsupportedOperationException("CCM mode ciphers do not support chunked encryption.");
    }
    super.encrypt(input, output);
  }


  /**
   * {@inheritDoc}
   */
  @Override
  public void decrypt(final InputStream input, final OutputStream output)
  {
    if (blockCipherSpec.toString().endsWith("CCM")) {
      throw new UnsupportedOperationException("CCM mode ciphers do not support chunked decryption.");
    }
    super.decrypt(input, output);
  }


  /** {@inheritDoc} */
  protected AEADBlockCipherAdapter newCipher(final CiphertextHeader header, final boolean mode)
  {
    final AEADBlockCipher cipher = blockCipherSpec.newInstance();
    final SecretKey key = lookupKey(header.getKeyName());
    final AEADParameters params = new AEADParameters(
      new KeyParameter(key.getEncoded()),
      MAC_SIZE_BITS,
      header.getNonce(),
      header.encode());
    cipher.init(mode, params);
    return new AEADBlockCipherAdapter(cipher);
  }
}
