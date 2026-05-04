/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.cryptacular.CryptUtil;
import org.cryptacular.util.CertUtil;

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
    CryptUtil.assertNotNullArg(random, "Secure random cannot be null");
    if (bitLength < 1) {
      throw new IllegalArgumentException("Bit length must be positive");
    }
    try {
      final java.security.KeyPairGenerator generator =
        java.security.KeyPairGenerator.getInstance("DSA", CertUtil.bouncyCastleProvider());
      generator.initialize(bitLength, random);
      return generator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("DSA algorithm not available", e);
    }
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
    CryptUtil.assertNotNullArg(random, "Secure random cannot be null");
    if (bitLength < 1) {
      throw new IllegalArgumentException("Bit length must be positive");
    }
    try {
      final java.security.KeyPairGenerator generator =
        java.security.KeyPairGenerator.getInstance("RSA", CertUtil.bouncyCastleProvider());
      generator.initialize(bitLength, random);
      return generator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("RSA algorithm not available", e);
    }
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
    CryptUtil.assertNotNullArg(random, "Secure random cannot be null");
    if (bitLength < 1) {
      throw new IllegalArgumentException("Bit length must be positive");
    }
    try {
      final java.security.KeyPairGenerator generator =
        java.security.KeyPairGenerator.getInstance("EC", CertUtil.bouncyCastleProvider());
      generator.initialize(bitLength, random);
      return generator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("EC algorithm not available", e);
    }
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
    CryptUtil.assertNotNullArg(random, "Secure random cannot be null");
    CryptUtil.assertNotNullArg(namedCurve, "Named curve cannot be null");
    try {
      final java.security.KeyPairGenerator generator =
        java.security.KeyPairGenerator.getInstance("EC", CertUtil.bouncyCastleProvider());
      generator.initialize(new ECNamedCurveGenParameterSpec(namedCurve), random);
      return generator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("EC algorithm not available", e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new IllegalArgumentException("Invalid EC curve " + namedCurve, e);
    }
  }
}
