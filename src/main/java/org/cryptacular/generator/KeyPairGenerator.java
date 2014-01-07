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

package org.cryptacular.generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

/**
 * Static factory that generates various types of asymmetric key pairs.

 * @author Marvin S. Addison
 */
public final class KeyPairGenerator
{
  /** Private constructor of static factory. */
  private KeyPairGenerator() {}


  /**
   * Generates a DSA key pair.
   *
   * @param  random  Random source required for key generation.
   * @param  bitLength  Desired key size in bits.
   *
   * @return  DSA key pair of desired size.
   */
  public static KeyPair generateDSA(final SecureRandom random, final int bitLength)
  {
    final org.bouncycastle.jcajce.provider.asymmetric.dsa.KeyPairGeneratorSpi generator =
      new org.bouncycastle.jcajce.provider.asymmetric.dsa.KeyPairGeneratorSpi();
    generator.initialize(bitLength, random);
    return generator.generateKeyPair();
  }


  /**
   * Generates a RSA key pair.
   *
   * @param  random  Random source required for key generation.
   * @param  bitLength  Desired key size in bits.
   *
   * @return  RSA key pair of desired size.
   */
  public static KeyPair generateRSA(final SecureRandom random, final int bitLength)
  {
    final org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi generator =
      new org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi();
    generator.initialize(bitLength, random);
    return generator.generateKeyPair();
  }


  /**
   * Generates a EC key pair.
   *
   * @param  random  Random source required for key generation.
   * @param  bitLength  Desired key size in bits.
   *
   * @return  EC key pair of desired size.
   */
  public static KeyPair generateEC(final SecureRandom random, final int bitLength)
  {
    final org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.EC generator =
      new org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.EC();
    generator.initialize(bitLength, random);
    return generator.generateKeyPair();
  }


  /**
   * Generates a EC key pair.
   *
   * @param  random  Random source required for key generation.
   * @param  namedCurve  Well-known elliptic curve name that includes domain parameters including key size.
   *
   * @return  EC key pair according to named curve.
   */
  public static KeyPair generateEC(final SecureRandom random, final String namedCurve)
  {
    final org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.EC generator =
      new org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.EC();
    try {
      generator.initialize(new ECNamedCurveGenParameterSpec(namedCurve), random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new IllegalArgumentException("Invalid EC curve " + namedCurve, e);
    }
    return generator.generateKeyPair();
  }
}
