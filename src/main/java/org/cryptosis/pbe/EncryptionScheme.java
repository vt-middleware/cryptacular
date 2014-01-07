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

/**
 * Describes a password-based encryption scheme.
 *
 * @author  Middleware Services
 * @version  $Revision: 2744 $
 */
public interface EncryptionScheme
{

  /**
   * Encrypts the given plaintext bytes into a byte array of ciphertext using the derived key.
   *
   * @param  plaintext  Input plaintext bytes.
   *
   * @return  Ciphertext resulting from plaintext encryption.
   */
  byte[] encrypt(byte[] plaintext);


  /**
   * Encrypts the data in the given plaintext input stream into ciphertext in the output stream.
   * Use {@link org.cryptosis.io.EncodingOutputStream} to produce ciphertext bytes that encoded as a string data in the
   * output stream.
   *
   * @param  in  Input stream of plaintext.
   * @param  out  Output stream of ciphertext.
   *
   * @throws  IOException  On stream read/write errors.
   */
  void encrypt(InputStream in, OutputStream out) throws IOException;


  /**
   * Decrypts the given ciphertext into plaintext using the derived key.
   *
   * @param  ciphertext  Input ciphertext bytes.
   *
   * @return  Plaintext resulting from ciphertext decryption.
   */
  byte[] decrypt(byte[] ciphertext);


  /**
   * Decrypts ciphertext from an input stream into plaintext in the output stream.
   * Use {@link org.cryptosis.io.DecodingInputStream} to handle input ciphertext encoded as string data.
   *
   * @param  in  Input stream of ciphertext.
   * @param  out  Output stream of plaintext.
   *
   * @throws  IOException  On stream read/write errors.
   */
  void decrypt(InputStream in, OutputStream out) throws IOException;
}
