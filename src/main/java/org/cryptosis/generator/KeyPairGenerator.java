package org.cryptosis.generator;

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


  public static KeyPair generateDSA(final SecureRandom random, final int bitLength)
  {
    final org.bouncycastle.jcajce.provider.asymmetric.dsa.KeyPairGeneratorSpi generator =
      new org.bouncycastle.jcajce.provider.asymmetric.dsa.KeyPairGeneratorSpi();
    generator.initialize(bitLength, random);
    return generator.generateKeyPair();
  }


  public static KeyPair generateRSA(final SecureRandom random, final int bitLength)
  {
    final org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi generator =
      new org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi();
    generator.initialize(bitLength, random);
    return generator.generateKeyPair();
  }


  public static KeyPair generateEC(final SecureRandom random, final int bitLength)
  {
    final org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.EC generator =
      new org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.EC();
    generator.initialize(bitLength, random);
    return generator.generateKeyPair();
  }


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
