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

package org.cryptosis.generator;

import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.cryptosis.util.NonceUtil;

/**
 * Factory class with static methods for generating {@link SecretKey}s.
 *
 * @author Marvin S. Addison
 */
public final class SecretKeyGenerator
{
  /** Private constructor of static class. */
  private SecretKeyGenerator() {}


  /**
   * Generates a symmetric encryption key whose size is equal to the cipher block size.
   *
   * @param  cipher  Cipher with with key will be used.
   *
   * @return  Symmetric encryption key.
   */
  public static SecretKey generate(final BlockCipher cipher)
  {
    return generate(cipher.getBlockSize() * 8, cipher);
  }


  /**
   * Generates a symmetric encryption key of the given length.
   *
   * @param  bitLength  Desired key length in bits.
   * @param  cipher  Cipher with with key will be used.
   *
   * @return  Symmetric encryption key.
   */
  public static SecretKey generate(final int bitLength, final BlockCipher cipher)
  {
    // Want as much nonce data as key bits
    final byte[] nonce = NonceUtil.timestampNonce((bitLength + 7) / 8);
    return generate(
      bitLength,
      cipher,
      new SP800SecureRandomBuilder().buildHash(new SHA256Digest(), nonce, false));
  }


  /**
   * Generates a symmetric encryption key of the given length.
   *
   * @param  bitLength  Desired key length in bits.
   * @param  cipher  Cipher with with key will be used.
   * @param  random  Randomness provider for key generation.
   *
   * @return  Symmetric encryption key.
   */
  public static SecretKey generate(final int bitLength, final BlockCipher cipher, final SecureRandom random)
  {
    // Round up for bit lengths that are not a multiple of 8
    final byte[] key = new byte[(bitLength + 7) / 8];
    random.nextBytes(key);
    return new SecretKeySpec(key, cipher.getAlgorithmName());
  }
}
