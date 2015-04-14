/* See LICENSE for licensing and NOTICE for copyright. */
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
