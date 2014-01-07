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
package org.cryptosis.pbe;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.util.io.Streams;

/**
 * Abstract base class for password-based encryption schemes based on salt data and iterated hashing as the basis of
 * the key derivation function.
 *
 * <p>NOTE: Classes derived from this class are not thread safe. In particular,
 * care should be take to prevent multiple threads from performing encryption
 * and/or decryption concurrently.</p>
 *
 * @author  Middleware Services
 * @version  $Revision: 2744 $
 */
public abstract class AbstractEncryptionScheme implements EncryptionScheme
{
  /** Cipher used for encryption and decryption. */
  private BufferedBlockCipher cipher;

  /** Cipher initialization parameters. */
  private CipherParameters parameters;


  /** {@inheritDoc} */
  public byte[] encrypt(final byte[] plaintext)
  {
    cipher.init(true, parameters);
    return process(plaintext);
  }


  /** {@inheritDoc} */
  public void encrypt(final InputStream in, final OutputStream out) throws IOException
  {
    cipher.init(true, parameters);
    Streams.pipeAll(in, new CipherOutputStream(out, cipher));
  }


  /** {@inheritDoc} */
  public byte[] decrypt(final byte[] ciphertext)
  {
    cipher.init(false, parameters);
    return process(ciphertext);
  }


  /** {@inheritDoc} */
  public void decrypt(final InputStream in, final OutputStream out) throws IOException
  {
    cipher.init(false, parameters);
    Streams.pipeAll(new CipherInputStream(in, cipher), out);
  }


  /**
   * Sets the block cipher used for encryption/decryption.
   *
   * @param  bufferedBlockCipher  Buffered block cipher.
   */
  protected void setCipher(final BufferedBlockCipher bufferedBlockCipher)
  {
    if (bufferedBlockCipher == null) {
      throw new IllegalArgumentException("Block cipher cannot be null");
    }
    this.cipher = bufferedBlockCipher;
  }


  /**
   * Sets block cipher initialization parameters.
   *
   * @param  parameters  Cipher-specific init params.
   */
  protected void setCipherParameters(final CipherParameters parameters)
  {
    if (parameters == null) {
      throw new IllegalArgumentException("Cipher parameters cannot be null");
    }
    this.parameters = parameters;
  }


  /**
   * Run the given data through the initialized underlying cipher and return the result.
   *
   * @param  input  Input data.
   *
   * @return  Result of cipher acting on input.
   */
  private byte[] process(final byte[] input)
  {
    final byte[] output = new byte[cipher.getOutputSize(input.length)];
    try {
      cipher.doFinal(output, cipher.processBytes(input, 0, input.length, output, 0));
    } catch (InvalidCipherTextException e) {
      throw new RuntimeException("Encryption failed", e);
    }
    return output;
  }
}
