/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.util.PBKDF2Config;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OutputEncryptor;
import org.cryptacular.pbe.PBES2Algorithm;
import org.cryptacular.pbe.PBES2EncryptionScheme;
import org.cryptacular.spec.DigestSpec;


/**
 * Generates PKCS12 containers using the PBES2 algorithm with the AES-256-CBC cipher for encryption, which is the
 * most portable and secure algorithm in use with PKCS12 at this time.
 *
 * @author Marvin S. Addison
 */
public class AESP12Generator extends AbstractP12Generator
{
  /** Set of supported digest algorithms. */
  public static final Set<ASN1ObjectIdentifier> SUPPORTED_DIGEST_ALGORITHMS = Collections.unmodifiableSet(
    new HashSet<>(Arrays.asList(
      NISTObjectIdentifiers.id_sha256,
      NISTObjectIdentifiers.id_sha512,
      NISTObjectIdentifiers.id_sha3_256,
      NISTObjectIdentifiers.id_sha3_384,
      NISTObjectIdentifiers.id_sha3_512
    )));

  /** Map of digest algorithm identifiers to digest specifications. */
  private static final Map<ASN1ObjectIdentifier, DigestSpec> DIGEST_ID_TO_DIGEST_SPEC_MAP = new HashMap<>();

  /** Map of digest algorithm identifiers to HMAC algorithm IDs. */
  private static final Map<ASN1ObjectIdentifier, ASN1ObjectIdentifier> DIGEST_ID_TO_HMAC_ID_MAP = new HashMap<>();

  /** Digest algorithm used for all HMAC operations. */
  private final ASN1ObjectIdentifier digestAlgorithm;

  /** PBKDF2 configuration. */
  private final PBKDF2Config pbkdf2Config;

  /** Produces encryptors that use the PBES2 algorithm. */
  private final PBES2OutputEncryptorBuilder outputEncryptorBuilder;


  static
  {
    DIGEST_ID_TO_DIGEST_SPEC_MAP.put(NISTObjectIdentifiers.id_sha256, new DigestSpec("SHA256"));
    DIGEST_ID_TO_DIGEST_SPEC_MAP.put(NISTObjectIdentifiers.id_sha512, new DigestSpec("SHA512"));
    DIGEST_ID_TO_DIGEST_SPEC_MAP.put(NISTObjectIdentifiers.id_sha3_256, new DigestSpec("SHA3", 256));
    DIGEST_ID_TO_DIGEST_SPEC_MAP.put(NISTObjectIdentifiers.id_sha3_384, new DigestSpec("SHA3", 384));
    DIGEST_ID_TO_DIGEST_SPEC_MAP.put(NISTObjectIdentifiers.id_sha3_512, new DigestSpec("SHA3", 512));
    DIGEST_ID_TO_HMAC_ID_MAP.put(NISTObjectIdentifiers.id_sha256, PKCSObjectIdentifiers.id_hmacWithSHA256);
    DIGEST_ID_TO_HMAC_ID_MAP.put(NISTObjectIdentifiers.id_sha512, PKCSObjectIdentifiers.id_hmacWithSHA512);
    DIGEST_ID_TO_HMAC_ID_MAP.put(NISTObjectIdentifiers.id_sha3_256, NISTObjectIdentifiers.id_hmacWithSHA3_256);
    DIGEST_ID_TO_HMAC_ID_MAP.put(NISTObjectIdentifiers.id_sha3_384, NISTObjectIdentifiers.id_hmacWithSHA3_384);
    DIGEST_ID_TO_HMAC_ID_MAP.put(NISTObjectIdentifiers.id_sha3_512, NISTObjectIdentifiers.id_hmacWithSHA3_512);
  }


  /**
   * Creates a new instance that encrypts with AES-256-CBC and SHA256 using 2048 rounds of hashing.
   */
  public AESP12Generator()
  {
    this(NISTObjectIdentifiers.id_sha256, 2048);
  }

  /**
   * Creates a new instance that encrypts with AES-256-CBC and SHA256 using the given number of hashing rounds.
   *
   * @param iterations Number of rounds of encryption.
   */
  public AESP12Generator(final int iterations)
  {
    this(NISTObjectIdentifiers.id_sha256, iterations);
  }

  /**
   * Creates a new instances that uses AES-256-CBC and the given digest algorithm to encrypt data.
   *
   * @param digestAlgId Digest algorithm identifier.
   * @param iterations Number of rounds of hashing.
   */
  public AESP12Generator(final ASN1ObjectIdentifier digestAlgId, final int iterations)
  {
    if (!SUPPORTED_DIGEST_ALGORITHMS.contains(digestAlgId)) {
      throw new IllegalArgumentException("Unsupported digest algorithm");
    }
    if (iterations < 1) {
      throw new IllegalArgumentException("Iterations must be positive");
    }
    digestAlgorithm = digestAlgId;
    final ASN1ObjectIdentifier hmacAlgId = DIGEST_ID_TO_HMAC_ID_MAP.get(digestAlgId);
    // The default behavior of the builder is to select salt size based on HMAC algorithm,
    // which is the desirable behavior here
    pbkdf2Config = new PBKDF2Config.Builder()
      .withIterationCount(iterations)
      .withPRF(new AlgorithmIdentifier(hmacAlgId, DERNull.INSTANCE))
      .build();
    outputEncryptorBuilder = new PBES2OutputEncryptorBuilder(PBES2Algorithm.AES256, pbkdf2Config);
  }

  @Override
  public int getIterations()
  {
    return pbkdf2Config.getIterationCount();
  }

  @Override
  protected ASN1ObjectIdentifier getDigestAlgorithmId()
  {
    return digestAlgorithm;
  }

  @Override
  protected DigestSpec getDigestSpec()
  {
    return DIGEST_ID_TO_DIGEST_SPEC_MAP.get(digestAlgorithm);
  }

  @Override
  protected OutputEncryptor keyOutputEncryptor(final char[] password)
  {
    return outputEncryptorBuilder.build(password);
  }

  @Override
  protected OutputEncryptor dataOutputEncryptor(final char[] password)
  {
    return outputEncryptorBuilder.build(password);
  }

  /**
   * Builds an output encryptor based on PBKDF2 domain parameters.
   */
  static class PBES2OutputEncryptorBuilder
  {
    /** Source of cryptographically-strong randomness. */
    private final SecureRandom random = new SecureRandom();

    /** PBES2 encryption algorithm. */
    private final PBES2Algorithm encryptionAlg;

    /** PBKDF2 domain parameters. */
    private final PBKDF2Config pbkdf2Config;


    PBES2OutputEncryptorBuilder(final PBES2Algorithm encAlg, final PBKDF2Config config)
    {
      this.encryptionAlg = encAlg;
      this.pbkdf2Config = config;
    }

    OutputEncryptor build(final char[] password)
    {
      final byte[] salt = new byte[pbkdf2Config.getSaltLength()];
      random.nextBytes(salt);
      final byte[] iv = new byte[encryptionAlg.getBlockSize() / 8];
      random.nextBytes(iv);
      final ASN1ObjectIdentifier encryptionAlgId = new ASN1ObjectIdentifier(encryptionAlg.getOid());
      final EncryptionScheme encryptionScheme = new EncryptionScheme(encryptionAlgId, new DEROctetString(iv));
      final PBKDF2Params pbkdf2Params = new PBKDF2Params(salt, pbkdf2Config.getIterationCount(), pbkdf2Config.getPRF());
      final PBES2Parameters pbes2Parameters = new PBES2Parameters(
        new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, pbkdf2Params),
        encryptionScheme);
      final PBES2EncryptionScheme scheme = new PBES2EncryptionScheme(pbes2Parameters, password);
      return new OutputEncryptor()
      {
        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
          return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, pbes2Parameters);
        }

        public OutputStream getOutputStream(final OutputStream out)
        {
          return scheme.wrap(true, out);
        }

        public GenericKey getKey()
        {
          return null;
        }
      };
    }
  }
}
