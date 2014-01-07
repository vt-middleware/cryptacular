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
   */
  void decrypt(InputStream input, OutputStream output);
}
