/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.InputStream;
import java.io.OutputStream;
import org.cryptacular.CryptoException;
import org.cryptacular.StreamException;

/**
 * Bean that performs encryption/decryption using a symmetric cipher.
 *
 * @author  Middleware Services
 */
public interface CipherBean
{

  /**
   * Encrypts the input data using a symmetric cipher.
   *
   * @param  input  Plaintext data to encrypt.
   *
   * @return  Ciphertext output.
   *
   * @throws  CryptoException  on underlying cipher data handling errors.
   */
  byte[] encrypt(byte[] input) throws CryptoException;


  /**
   * Encrypts the data from the input stream onto the output stream using a symmetric cipher.
   *
   * <p>The caller is responsible for providing and managing the streams (e.g. closing them when finished).</p>
   *
   * @param  input  Input stream containing plaintext data to encrypt.
   * @param  output  Output stream containing ciphertext produced by cipher in encryption mode.
   *
   * @throws  CryptoException  on underlying cipher data handling errors.
   * @throws  StreamException  on stream IO errors.
   */
  void encrypt(InputStream input, OutputStream output) throws CryptoException, StreamException;


  /**
   * Decrypts the input data using a block cipher.
   *
   * @param  input  Ciphertext data to encrypt.
   *
   * @return  Plaintext output.
   *
   * @throws  CryptoException  on underlying cipher data handling errors.
   */
  byte[] decrypt(byte[] input) throws CryptoException;


  /**
   * Decrypts the data from the input stream onto the output stream using a symmetric cipher.
   *
   * <p>The caller is responsible for providing and managing the streams (e.g. closing them when finished).</p>
   *
   * @param  input  Input stream containing ciphertext data to decrypt.
   * @param  output  Output stream containing plaintext produced by cipher in decryption mode.
   *
   * @throws  CryptoException  on underlying cipher data handling errors.
   * @throws  StreamException  on stream IO errors.
   */
  void decrypt(InputStream input, OutputStream output) throws CryptoException, StreamException;
}
