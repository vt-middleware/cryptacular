/*
  $Id: AbstractEncryptionScheme.java 2744 2013-06-25 20:20:29Z dfisher $

  Copyright (C) 2003-2013 Virginia Tech.
  All rights reserved.

  SEE LICENSE FOR MORE INFORMATION

  Author:  Middleware Services
  Email:   middleware@vt.edu
  Version: $Revision: 2744 $
  Updated: $Date: 2013-06-25 16:20:29 -0400 (Tue, 25 Jun 2013) $
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


  protected void setCipher(final BufferedBlockCipher bufferedBlockCipher)
  {
    if (bufferedBlockCipher == null) {
      throw new IllegalArgumentException("Block cipher cannot be null");
    }
    this.cipher = bufferedBlockCipher;
  }


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
