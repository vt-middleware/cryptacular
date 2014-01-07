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

package org.cryptacular.asn;

import org.cryptacular.util.PemUtil;

/**
 * Base class for all private key decoders.
 *
 * @author Marvin S. Addison
 * @param  <T>  Type produced by decode operation.
 */
public abstract class AbstractPrivateKeyDecoder<T> implements ASN1Decoder<T>
{
  /** {@inheritDoc} */
  @Override
  public T decode(final byte[] encoded, final Object ... args)
  {
    final byte[] asn1Bytes;
    if (args != null && args.length > 0 && args[0] instanceof char[]) {
      asn1Bytes = decryptKey(encoded, (char[]) args[0]);
    } else {
      asn1Bytes = tryConvertPem(encoded);
    }
    return decodeASN1(asn1Bytes);
  }


  /**
   * Tests the given encoded input and converts it to PEM if it is detected, stripping out any header/footer data
   * in the process.
   *
   * @param  input  Encoded data that may be PEM encoded.
   *
   * @return  Decoded data if PEM encoding detected, otherwise original data.
   */
  protected byte[] tryConvertPem(final byte[] input)
  {
    if (PemUtil.isPem(input)) {
      return PemUtil.decode(input);
    }
    return input;
  }


  /**
   * Decrypts an encrypted key in either PKCS#8 or OpenSSL "traditional" format.
   * Both PEM and DER encodings are supported.
   *
   * @param  encrypted  Encoded encrypted key data.
   * @param  password  Password to decrypt key.
   *
   * @return  Decrypted key.
   */
  protected abstract byte[] decryptKey(byte[] encrypted, char[] password);


  /**
   * Decodes the given raw ASN.1 encoded data into a private key of the type supported by this class.
   *
   * @param  encoded  Encoded ASN.1 data.
   *
   * @return  Private key object.
   */
  protected abstract T decodeASN1(byte[] encoded);
}
