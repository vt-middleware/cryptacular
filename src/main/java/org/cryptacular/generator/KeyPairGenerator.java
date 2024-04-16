/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

/**
 * Static factory that generates various types of asymmetric key pairs.
 *
 * @author  Middleware Services
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
   * Generates an RSA key pair.
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
   * Generates an EC key pair.
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
   * Generates an EC key pair.
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
