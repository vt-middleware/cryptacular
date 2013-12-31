package org.cryptosis.bean;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Bean that performs encryption/decryption using a symmetric cipher.
 *
 * @author Marvin S. Addison
 */
public interface CipherBean
{
  /**
   * Encrypts the input data using a symmetric cipher.
   *
   * @param  input  Plaintext data to encrypt.
   *
   * @return  Ciphertext output.
   */
  byte[] encrypt(byte[] input);


  /**
   * Encrypts the data from the input stream onto the output stream using a symmetric cipher.
   * <p>
   * The caller is responsible for providing and managing the streams (e.g. closing them when finished).
   *
   * @param  input  Input stream containing plaintext data to encrypt.
   * @param  output  Output stream containing ciphertext produced by cipher in encryption mode.
   *
   * @return  Ciphertext output.
   */
  void encrypt(InputStream input, OutputStream output);


  /**
   * Decrypts the input data using a block cipher.
   *
   * @param  input  Ciphertext data to encrypt.
   *
   * @return  Plaintext output.
   */
  byte[] decrypt(byte[] input);


  /**
   * Decrypts the data from the input stream onto the output stream using a symmetric cipher.
   * <p>
   * The caller is responsible for providing and managing the streams (e.g. closing them when finished).
   *
   * @param  input  Input stream containing ciphertext data to decrypt.
   * @param  output  Output stream containing plaintext produced by cipher in decryption mode.
   *
   * @return  Plaintext output.
   */
  void decrypt(InputStream input, OutputStream output);
}
