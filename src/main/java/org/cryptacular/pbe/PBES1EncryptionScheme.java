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
package org.cryptacular.pbe;

import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S1ParametersGenerator;

/**
 * Implements the PBES1 encryption scheme defined in PKCS#5v2.
 *
 * @author  Middleware Services
 * @version  $Revision: 2744 $
 */
public class PBES1EncryptionScheme extends AbstractEncryptionScheme
{
  /** Number of bits in derived key. */
  public static final int KEY_LENGTH = 64;

  /** Number of bits IV. */
  public static final int IV_LENGTH = 64;


  /**
   * Creates a new instance with the given parameters.
   *
   * @param  alg  Describes hash/algorithm pair suitable for PBES1 scheme.
   * @param  params  Key generation function salt and iteration count.
   * @param  password  Password used to derive key.
   */
  public PBES1EncryptionScheme(final PBES1Algorithm alg, final PBEParameter params, final char[] password)
  {
    final byte[] salt = params.getSalt();
    final int iterations = params.getIterationCount().intValue();
    final PKCS5S1ParametersGenerator generator = new PKCS5S1ParametersGenerator(alg.getDigestSpec().newInstance());
    generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password), salt, iterations);
    setCipher(alg.getCipherSpec().newInstance());
    setCipherParameters(generator.generateDerivedParameters(KEY_LENGTH, IV_LENGTH));
  }
}
