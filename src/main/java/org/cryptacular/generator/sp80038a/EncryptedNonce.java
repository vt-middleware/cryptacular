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

package org.cryptacular.generator.sp80038a;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.cryptacular.generator.LimitException;
import org.cryptacular.generator.Nonce;
import org.cryptacular.spec.Spec;
import org.cryptacular.util.NonceUtil;

/**
 * Nonce generation strategy that produces a random value according to NIST
 * <a href="http://goo.gl/S9z8qF">SP-800-38a</a>, appendix C, method 1 (encrypted nonce),
 * suitable for use with any block cipher mode described in that standard except OFB.
 * <p>
 * Instances of this class are thread safe.
 *
 * @author Marvin S. Addison
 */
public class EncryptedNonce implements Nonce
{
  /** Block cipher. */
  private BlockCipher cipher;

  /** Encryption key. */
  private SecretKey key;


  /**
   * Creates a new instance.
   *
   * @param  cipherSpec  Block cipher specification.
   * @param  key  Symmetric key.
   */
  public EncryptedNonce(final Spec<BlockCipher> cipherSpec, final SecretKey key)
  {
    this(cipherSpec.newInstance(), key);
  }


  /**
   * Creates a new instance.
   *
   * @param  cipher  Block cipher to use.
   * @param  key  Symmetric key.
   */
  public EncryptedNonce(final BlockCipher cipher, final SecretKey key)
  {
    this.cipher = cipher;
    this.key = key;
  }


  /** {@inheritDoc} */
  @Override
  public byte[] generate() throws LimitException
  {
    final byte[] result = new byte[cipher.getBlockSize()];
    final byte[] nonce = NonceUtil.timestampNonce(result.length);
    synchronized (cipher) {
      cipher.init(true, new KeyParameter(key.getEncoded()));
      cipher.processBlock(nonce, 0, result, 0);
      cipher.reset();
    }
    return result;
  }


  /** {@inheritDoc} */
  @Override
  public int getLength()
  {
    return cipher.getBlockSize();
  }
}
