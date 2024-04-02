/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.cryptacular.CryptoException;
import org.cryptacular.spec.DigestSpec;

/**
 * Base class for all PKCS12 generation components.
 *
 * @author Marvin S. Addison
 */
public abstract class AbstractP12Generator implements P12Generator
{
  @Override
  public PKCS12PfxPdu generate(final char[] password, final PrivateKey key, final X509Certificate... certificates)
  {
    if (certificates.length < 1) {
      throw new IllegalArgumentException("At least one certificate must be provided");
    }
    final PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();
    final PKCS12SafeBag[] certBags = new PKCS12SafeBag[certificates.length];
    final JcaX509ExtensionUtils extUtils;
    try {
      extUtils = new JcaX509ExtensionUtils();
      String label = "end-entity-cert";
      final PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(
        key, keyOutputEncryptor(password));
      keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(label));
      keyBagBuilder.addBagAttribute(
        PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
        extUtils.createSubjectKeyIdentifier(certificates[0].getPublicKey()));
      certBags[0] = new JcaPKCS12SafeBagBuilder(certificates[0])
        .addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(label))
        .addBagAttribute(
          PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
          extUtils.createSubjectKeyIdentifier(certificates[0].getPublicKey()))
        .build();
      for (int i = 1; i < certificates.length; i++) {
        label = "ca-cert-" + i;
        certBags[i] = new JcaPKCS12SafeBagBuilder(certificates[i])
          .addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(label))
          .build();
      }
      // Add certificates before private key as is the usual ordering produced by OpenSSL
      pfxPduBuilder.addEncryptedData(dataOutputEncryptor(password), certBags);
      pfxPduBuilder.addData(keyBagBuilder.build());
      final DigestSpec digestSpec = getDigestSpec();
      final PKCS12MacCalculatorBuilder macCalculatorBuilder = new BcPKCS12MacCalculatorBuilder(
        (ExtendedDigest) digestSpec.newInstance(),
        new AlgorithmIdentifier(getDigestAlgorithmId(), DERNull.INSTANCE)
      ).setIterationCount(getIterations());
      return pfxPduBuilder.build(macCalculatorBuilder, password);
    } catch (IOException | NoSuchAlgorithmException | PKCSException e) {
      throw new CryptoException("P12 generation failed", e);
    }
  }

  /** @return Number of hashing rounds. */
  public abstract int getIterations();

  /** @return Digest algorithm object identifier. */
  protected abstract ASN1ObjectIdentifier getDigestAlgorithmId();

  /** @return Digest specification. */
  protected abstract DigestSpec getDigestSpec();

  /**
   * Builds a new output encryptor that performs password-based encryption on keys in the P12 file.
   *
   * @param password Password tha will the basis of an encryption key.
   *
   * @return Output encryptor.
   */
  protected abstract OutputEncryptor keyOutputEncryptor(char[] password);


  /**
   * Builds a new output encryptor that performs password-based encryption on encrypted data in the P12 file.
   *
   * @param password Password tha will the basis of an encryption key.
   *
   * @return Output encryptor.
   */
  protected abstract OutputEncryptor dataOutputEncryptor(char[] password);
}
