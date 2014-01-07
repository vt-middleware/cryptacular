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

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Password-based encryption scheme used by OpenSSL for encrypting private keys.
 *
 * @author  Middleware Services
 * @version  $Revision: 2744 $
 */
public class OpenSSLEncryptionScheme extends AbstractEncryptionScheme
{
  /**
   * Creates a new instance using the given parameters.
   *
   * @param  cipher  Buffered block cipher algorithm.
   * @param  salt  Salt data for key generation function.
   * @param  keyBitLength  Size of derived keys in bits.
   * @param  password  Password used to derive key.
   */
  public OpenSSLEncryptionScheme(
    final BufferedBlockCipher cipher, final byte[] salt, final int keyBitLength, final char[] password)
  {
    final OpenSSLPBEParametersGenerator generator = new OpenSSLPBEParametersGenerator();
    generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password), salt);
    setCipher(cipher);
    setCipherParameters(generator.generateDerivedParameters(keyBitLength));
  }


  /**
   * Creates a new instance from an algorithm and salt data.
   *
   * @param  algorithm  OpenSSL key encryption algorithm.
   * @param  iv  Explicit IV; first 8 bytes also used for salt in PBE key generation.
   * @param  password  Password used to derive key.
   */
  public OpenSSLEncryptionScheme(final OpenSSLAlgorithm algorithm, final byte[] iv, final char[] password)
  {
    byte[] salt = iv;
    if (iv.length > 8) {
      salt = new byte[8];
      System.arraycopy(iv, 0, salt, 0, 8);
    }
    final OpenSSLPBEParametersGenerator generator = new OpenSSLPBEParametersGenerator();
    generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password), salt);
    setCipher(algorithm.getCipherSpec().newInstance());
    setCipherParameters(new ParametersWithIV(
      generator.generateDerivedParameters(algorithm.getCipherSpec().getKeyLength()),
      iv));
  }
}
