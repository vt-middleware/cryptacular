/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.pbe;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.engines.RC532Engine;
import org.bouncycastle.crypto.engines.RC564Engine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RC2Parameters;
import org.bouncycastle.crypto.params.RC5Parameters;
import org.cryptacular.CryptUtil;
import org.cryptacular.spec.DigestSpec;

/**
 * Implements the PBES2 encryption scheme defined in PKCS#5v2.
 *
 * @author  Middleware Services
 * @version  $Revision: 2744 $
 */
public class PBES2EncryptionScheme extends AbstractEncryptionScheme
{
  /** Map of HMAC algorithm identifiers to digest specifications. */
  private static final Map<ASN1ObjectIdentifier, DigestSpec> HMAC_ID_TO_DIGEST_SPEC_MAP = new HashMap<>();

  /** Size of derived key in bits. */
  private int keyLength;


  static
  {
    HMAC_ID_TO_DIGEST_SPEC_MAP.put(PKCSObjectIdentifiers.id_hmacWithSHA1, new DigestSpec("SHA1"));
    HMAC_ID_TO_DIGEST_SPEC_MAP.put(PKCSObjectIdentifiers.id_hmacWithSHA256, new DigestSpec("SHA256"));
    HMAC_ID_TO_DIGEST_SPEC_MAP.put(PKCSObjectIdentifiers.id_hmacWithSHA512, new DigestSpec("SHA512"));
    HMAC_ID_TO_DIGEST_SPEC_MAP.put(NISTObjectIdentifiers.id_hmacWithSHA3_256, new DigestSpec("SHA3", 256));
    HMAC_ID_TO_DIGEST_SPEC_MAP.put(NISTObjectIdentifiers.id_hmacWithSHA3_384, new DigestSpec("SHA3", 384));
    HMAC_ID_TO_DIGEST_SPEC_MAP.put(NISTObjectIdentifiers.id_hmacWithSHA3_512, new DigestSpec("SHA3", 512));
  }


  /**
   * Creates a new instance with the given parameters.
   *
   * @param  params  PBES2 parameters describing the key derivation function and encryption scheme.
   * @param  password  Password used to derive key.
   */
  public PBES2EncryptionScheme(final PBES2Parameters params, final char[] password)
  {
    CryptUtil.assertNotNullArg(params, "Parameters cannot be null");
    final PBKDF2Params kdfParams = PBKDF2Params.getInstance(params.getKeyDerivationFunc().getParameters());
    final byte[] salt = kdfParams.getSalt();
    final int iterations = kdfParams.getIterationCount().intValue();
    if (kdfParams.getKeyLength() != null) {
      keyLength = kdfParams.getKeyLength().intValue() * 8;
    }
    final DigestSpec digestSpec = HMAC_ID_TO_DIGEST_SPEC_MAP.get(kdfParams.getPrf().getAlgorithm());
    if (digestSpec == null) {
      throw new IllegalArgumentException("Unsupported PBKDF2 PRF HMAC algorithm");
    }
    final PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(digestSpec.newInstance());
    generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password), salt, iterations);
    initCipher(generator, params.getEncryptionScheme());
  }


  /**
   * Initializes the block cipher and sets up its initialization parameters.
   *
   * @param  generator  Derived key generator.
   * @param  scheme  PKCS#5 encryption scheme.
   */
  private void initCipher(
    final PKCS5S2ParametersGenerator generator,
    final org.bouncycastle.asn1.pkcs.EncryptionScheme scheme)
  {
    final PBES2Algorithm alg = PBES2Algorithm.fromOid(scheme.getAlgorithm().getId());
    if (keyLength == 0) {
      keyLength = alg.getKeySize();
    }

    byte[] iv = null;
    CipherParameters cipherParameters = generator.generateDerivedParameters(keyLength);
    switch (alg) {

    case RC2:
      setCipher(alg.getCipherSpec().newInstance());

      final ASN1Sequence rc2Params = ASN1Sequence.getInstance(scheme.getParameters());
      if (rc2Params.size() > 1) {
        cipherParameters = new RC2Parameters(
          ((KeyParameter) cipherParameters).getKey(),
          ASN1Integer.getInstance(rc2Params.getObjectAt(0)).getValue().intValue());
        iv = ASN1OctetString.getInstance(rc2Params.getObjectAt(0)).getOctets();
      }
      break;

    case RC5:

      final ASN1Sequence rc5Params = ASN1Sequence.getInstance(scheme.getParameters());
      final int rounds = ASN1Integer.getInstance(rc5Params.getObjectAt(1)).getValue().intValue();
      final int blockSize = ASN1Integer.getInstance(rc5Params.getObjectAt(2)).getValue().intValue();
      if (blockSize == 64) {
        setCipher(new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(new RC564Engine()), new PKCS7Padding()));
      } else if (blockSize == 32) {
        setCipher(new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(new RC532Engine()), new PKCS7Padding()));
      } else {
        throw new IllegalArgumentException("Invalid RC5 block size: " + blockSize);
      }
      cipherParameters = new RC5Parameters(((KeyParameter) cipherParameters).getKey(), rounds);
      if (rc5Params.size() > 3) {
        iv = ASN1OctetString.getInstance(rc5Params.getObjectAt(3)).getOctets();
      }
      break;

    default:
      setCipher(alg.getCipherSpec().newInstance());
      iv = ASN1OctetString.getInstance(scheme.getParameters()).getOctets();
    }
    if (iv != null) {
      cipherParameters = new ParametersWithIV(cipherParameters, iv);
    }
    setCipherParameters(cipherParameters);
  }
}
