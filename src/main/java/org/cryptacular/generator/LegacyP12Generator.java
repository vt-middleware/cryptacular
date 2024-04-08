/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.cryptacular.spec.DigestSpec;

/**
 * Generates PKCS12 containers using DES3+SHA1 for private keys and 40-bit RC2+SHA1 for encrypted data.
 * These algorithms are considered unsecure by today's standards (2024), but are needed for interoperability
 * in some cases. Importing a keypair into the Mac keychain is a notable use case.
 *
 * @author Marvin S. Addison
 */
public class LegacyP12Generator extends AbstractP12Generator
{
  /** Number of hashing rounds. */
  private final int iterations;

  /** Key encryptor builder. */
  private final BcPKCS12PBEOutputEncryptorBuilder keyEncryptorBuilder;

  /** Data encryptor builder. */
  private final BcPKCS12PBEOutputEncryptorBuilder dataEncryptorBuilder;


  /**
   * Creates a new instance that encrypts with 1024 rounds of hashing.
   */
  public LegacyP12Generator()
  {
    this(1024);
  }

  /**
   * Creates a new instance that encrypts with the given number of hashing rounds.
   *
   * @param iterations Number of hashing rounds.
   */
  public LegacyP12Generator(final int iterations)
  {
    this.iterations = iterations;
    this.keyEncryptorBuilder = new BcPKCS12PBEOutputEncryptorBuilder(
      PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, CBCBlockCipher.newInstance(new DESedeEngine()))
      .setIterationCount(iterations);
    this.dataEncryptorBuilder = new BcPKCS12PBEOutputEncryptorBuilder(
      PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC, CBCBlockCipher.newInstance(new RC2Engine()))
      .setIterationCount(iterations);
  }

  @Override
  public int getIterations()
  {
    return iterations;
  }

  @Override
  protected ASN1ObjectIdentifier getDigestAlgorithmId()
  {
    return OIWObjectIdentifiers.idSHA1;
  }

  @Override
  protected DigestSpec getDigestSpec()
  {
    return new DigestSpec("SHA1");
  }

  @Override
  protected OutputEncryptor keyOutputEncryptor(final char[] password)
  {
    return keyEncryptorBuilder.build(password);
  }

  @Override
  protected OutputEncryptor dataOutputEncryptor(final char[] password)
  {
    return dataEncryptorBuilder.build(password);
  }
}
