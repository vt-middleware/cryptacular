/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.spec;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.cryptacular.CryptUtil;

/**
 * Describes an AEAD block cipher in terms of a (algorithm, mode) tuple and provides a facility to create a new instance
 * of the cipher via the {@link #newInstance()} method.
 *
 * @author  Middleware Services
 * @version  $Revision: 2744 $
 */
public class AEADBlockCipherSpec implements Spec<AEADBlockCipher>
{

  /** String specification format, <code>algorithm/mode</code>. */
  public static final Pattern FORMAT = Pattern.compile("(?<alg>[A-Za-z0-9_-]+)/(?<mode>\\w+)");

  /** Cipher algorithm. */
  private final String algorithm;

  /** Cipher mode, e.g. GCM, CCM. */
  private final String mode;


  /**
   * Creates a new instance from a cipher algorithm and mode.
   *
   * @param  algName  Cipher algorithm name.
   * @param  cipherMode  Cipher mode, e.g. GCM, CCM.
   */
  public AEADBlockCipherSpec(final String algName, final String cipherMode)
  {
    this.algorithm = CryptUtil.assertNotNullArg(algName, "Algorithm name cannot be null.");
    this.mode = CryptUtil.assertNotNullArg(cipherMode, "Cipher mode cannot be null.");
  }


  @Override
  public String getAlgorithm()
  {
    return algorithm;
  }


  /**
   * Gets the cipher mode.
   *
   * @return  Cipher mode, e.g. CBC, OFB.
   */
  public String getMode()
  {
    return mode;
  }


  /**
   * Creates a new AEAD block cipher from the specification in this instance.
   *
   * @return  New AEAD block cipher instance.
   */
  @Override
  public AEADBlockCipher newInstance()
  {
    final BlockCipher blockCipher = new BlockCipherSpec(algorithm).newInstance();
    final AEADBlockCipher aeadBlockCipher;
    switch (mode) {

    case "GCM":
      aeadBlockCipher = GCMBlockCipher.newInstance(blockCipher);
      break;

    case "CCM":
      aeadBlockCipher = CCMBlockCipher.newInstance(blockCipher);
      break;

    case "OCB":
      aeadBlockCipher = new OCBBlockCipher(blockCipher, new BlockCipherSpec(algorithm).newInstance());
      break;

    case "EAX":
      aeadBlockCipher = new EAXBlockCipher(blockCipher);
      break;

    default:
      throw new IllegalStateException("Unsupported mode " + mode);
    }
    return aeadBlockCipher;
  }


  @Override
  public String toString()
  {
    return algorithm + '/' + mode;
  }


  /**
   * Parses a string representation of a AEAD block cipher specification into an instance of this class.
   *
   * @param  specification  AEAD block cipher specification of the form <code>algorithm/mode</code>.
   *
   * @return  Buffered block cipher specification instance.
   */
  public static AEADBlockCipherSpec parse(final String specification)
  {
    final Matcher m = FORMAT.matcher(CryptUtil.assertNotNullArg(specification, "Specification cannot be null."));
    if (!m.matches()) {
      throw new IllegalArgumentException("Invalid specification " + specification);
    }
    return new AEADBlockCipherSpec(m.group("alg"), m.group("mode"));
  }
}
