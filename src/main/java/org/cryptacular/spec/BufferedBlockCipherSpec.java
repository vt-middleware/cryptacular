/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.spec;

import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DefaultBufferedBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO10126d2Padding;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.TBCPadding;
import org.bouncycastle.crypto.paddings.X923Padding;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.cryptacular.CryptUtil;

/**
 * Describes a block cipher in terms of a (algorithm, mode, padding) tuple and provides a facility to create a new
 * instance of the cipher via the {@link #newInstance()} method.
 *
 * @author  Middleware Services
 * @version  $Revision: 2744 $
 */
public class BufferedBlockCipherSpec implements Spec<BufferedBlockCipher>, Serializable
{

  /** String specification format, <code>algorithm/mode/padding</code>. */
  public static final Pattern FORMAT = Pattern.compile("(?<alg>[A-Za-z0-9_-]+)/(?<mode>\\w+)/(?<padding>\\w+)");

  /** serialVersionUID. */
  private static final long serialVersionUID = 2900237827716742605L;

  /** Cipher algorithm. */
  private final String algorithm;

  /** Cipher mode, e.g. CBC, OFB. */
  private final String mode;

  /** Cipher padding scheme, e.g. PKCS5Padding. */
  private final String padding;


  /**
   * Creates a new instance from an algorithm name.
   *
   * @param  algName  Cipher algorithm name.
   */
  public BufferedBlockCipherSpec(final String algName)
  {
    this(algName, null, null);
  }


  /**
   * Creates a new instance from a cipher algorithm and mode.
   *
   * @param  algName  Cipher algorithm name.
   * @param  cipherMode  Cipher mode.
   */
  public BufferedBlockCipherSpec(final String algName, final String cipherMode)
  {
    this(algName, cipherMode, null);
  }


  /**
   * Creates a new instance from the given cipher specifications.
   *
   * @param  algName  Cipher algorithm name.
   * @param  cipherMode  Cipher mode.
   * @param  cipherPadding  Cipher padding scheme algorithm.
   */
  public BufferedBlockCipherSpec(final String algName, final String cipherMode, final String cipherPadding)
  {
    this.algorithm = CryptUtil.assertNotNullArg(algName, "Algorithm cannot be null");
    this.mode = CryptUtil.assertNotNullArg(cipherMode, "Cipher mode cannot be null");
    this.padding = CryptUtil.assertNotNullArg(cipherPadding, "Cipher padding cannot be null");
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
   * Gets the cipher padding scheme.
   *
   * @return  Padding scheme algorithm, e.g. PKCS5Padding. The following names are equivalent for no padding: NULL,
   *          Zero, None.
   */
  public String getPadding()
  {
    return padding;
  }


  /**
   * Gets the simple block cipher specification corresponding to this instance.
   *
   * @return  Simple block cipher specification.
   */
  public BlockCipherSpec getBlockCipherSpec()
  {
    return new BlockCipherSpec(this.algorithm);
  }


  /**
   * Creates a new buffered block cipher from the specification in this instance.
   *
   * @return  New buffered block cipher instance.
   */
  @Override
  public BufferedBlockCipher newInstance()
  {
    BlockCipher cipher = getBlockCipherSpec().newInstance();

    switch (mode) {

    case "CBC":
      cipher = CBCBlockCipher.newInstance(cipher);
      break;

    case "OFB":
      cipher = new OFBBlockCipher(cipher, cipher.getBlockSize());
      break;

    case "CFB":
      cipher = CFBBlockCipher.newInstance(cipher, cipher.getBlockSize());
      break;

    default:
      break;
    }

    if (padding != null) {
      return new PaddedBufferedBlockCipher(cipher, getPadding(padding));
    }
    return new DefaultBufferedBlockCipher(cipher);
  }


  @Override
  public String toString()
  {
    return algorithm + '/' + mode + '/' + padding;
  }


  /**
   * Parses a string representation of a buffered block cipher specification into an instance of this class.
   *
   * @param  specification  Block cipher specification of the form <code>algorithm/mode/padding</code>.
   *
   * @return  Buffered block cipher specification instance.
   */
  public static BufferedBlockCipherSpec parse(final String specification)
  {
    final Matcher m = FORMAT.matcher(specification);
    if (!m.matches()) {
      throw new IllegalArgumentException("Invalid specification " + specification);
    }
    return new BufferedBlockCipherSpec(m.group("alg"), m.group("mode"), m.group("padding"));
  }


  /**
   * Gets an instance of block cipher padding from a padding name string.
   *
   * @param  padding  Name of padding algorithm.
   *
   * @return  Block cipher padding instance.
   */
  private static BlockCipherPadding getPadding(final String padding)
  {
    final String name;
    final int pIndex = padding.indexOf("Padding");
    if (pIndex > -1) {
      name = padding.substring(0, pIndex);
    } else {
      name = padding;
    }

    final BlockCipherPadding blockCipherPadding;
    if ("ISO7816d4".equalsIgnoreCase(name) || "ISO7816".equalsIgnoreCase(name)) {
      blockCipherPadding = new ISO7816d4Padding();
    } else if ("ISO10126".equalsIgnoreCase(name) || "ISO10126-2".equalsIgnoreCase(name)) {
      blockCipherPadding = new ISO10126d2Padding();
    } else if ("PKCS7".equalsIgnoreCase(name) || "PKCS5".equalsIgnoreCase(name)) {
      blockCipherPadding = new PKCS7Padding();
    } else if ("TBC".equalsIgnoreCase(name)) {
      blockCipherPadding = new TBCPadding();
    } else if ("X923".equalsIgnoreCase(name)) {
      blockCipherPadding = new X923Padding();
    } else if ("NULL".equalsIgnoreCase(name) || "Zero".equalsIgnoreCase(name) || "None".equalsIgnoreCase(name)) {
      blockCipherPadding = new ZeroBytePadding();
    } else {
      throw new IllegalArgumentException("Invalid padding " + padding);
    }
    return blockCipherPadding;
  }
}
