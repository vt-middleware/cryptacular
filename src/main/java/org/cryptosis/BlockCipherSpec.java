/*
  $Id: AlgorithmSpec.java 2744 2013-06-25 20:20:29Z dfisher $

  Copyright (C) 2003-2013 Virginia Tech.
  All rights reserved.

  SEE LICENSE FOR MORE INFORMATION

  Author:  Middleware Services
  Email:   middleware@vt.edu
  Version: $Revision: 2744 $
  Updated: $Date: 2013-06-25 16:20:29 -0400 (Tue, 25 Jun 2013) $
*/
package org.cryptosis;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.engines.NoekeonEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.engines.RC564Engine;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.engines.SkipjackEngine;
import org.bouncycastle.crypto.engines.TEAEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.engines.XTEAEngine;
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

/**
 * Describes a block cipher in terms of a (algorithm, mode, padding) tuple and provides a facility to create a
 * new instance of the cipher via the {@link #newInstance()} method.
 *
 * @author  Middleware Services
 * @version  $Revision: 2744 $
 */
public class BlockCipherSpec
{

  /** Cipher algorithm algorithm. */
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
  public BlockCipherSpec(final String algName)
  {
    this(algName, null, null);
  }


  /**
   * Creates a new instance from a cipher algorithm and mode.
   *
   * @param  algName  Cipher algorithm name.
   * @param  cipherMode  Cipher mode.
   */
  public BlockCipherSpec(final String algName, final String cipherMode)
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
  public BlockCipherSpec(final String algName, final String cipherMode, final String cipherPadding)
  {
    this.algorithm = algName;
    this.mode = cipherMode;
    this.padding = cipherPadding;
  }


  /**
   * Gets the cipher algorithm.
   *
   * @return  Algorithm algorithm.
   */
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
   * @return  Padding scheme algorithm, e.g. PKCS5Padding.
   */
  public String getPadding()
  {
    return padding;
  }


  public BufferedBlockCipher newInstance()
  {
    BlockCipher cipher;
    if ("AES".equals(algorithm)) {
      cipher = new AESFastEngine();
    } else if ("Blowfish".equals(algorithm)) {
      cipher = new BlowfishEngine();
    } else if ("Camellia".equals(algorithm)) {
      cipher = new CamelliaEngine();
    } else if ("CAST5".equals(algorithm)) {
      cipher = new CAST5Engine();
    } else if ("CAST6".equals(algorithm)) {
      cipher = new CAST6Engine();
    } else if ("DES".equals(algorithm)) {
      cipher = new DESEngine();
    } else if ("DESede".equals(algorithm)) {
      cipher = new DESedeEngine();
    } else if ("GOST".equals(algorithm) || "GOST28147".equals(algorithm)) {
      cipher = new GOST28147Engine();
    } else if ("Noekeon".equals(algorithm)) {
      cipher = new NoekeonEngine();
    } else if ("RC2".equals(algorithm)) {
      cipher = new RC2Engine();
    } else if ("RC5".equals(algorithm)) {
      cipher = new RC564Engine();
    } else if ("RC6".equals(algorithm)) {
      cipher = new RC6Engine();
    } else if ("SEED".equals(algorithm)) {
      cipher = new SEEDEngine();
    } else if ("Serpent".equals(algorithm)) {
      cipher = new SerpentEngine();
    } else if ("Skipjack".equals(algorithm)) {
      cipher = new SkipjackEngine();
    } else if ("TEA".equals(algorithm)) {
      cipher = new TEAEngine();
    } else if ("Twofish".equals(algorithm)) {
      cipher = new TwofishEngine();
    } else if ("XTEA".equals(algorithm)) {
      cipher = new XTEAEngine();
    } else {
      throw new IllegalStateException("Unsupported cipher algorithm " + algorithm);
    }

    if ("CBC".equals(mode)) {
      cipher = new CBCBlockCipher(cipher);
    } else if ("OFB".equals(mode)) {
      cipher = new OFBBlockCipher(cipher, 128);
    } else if ("CFB".equals(mode)) {
      cipher = new CFBBlockCipher(cipher, 128);
    }

    if (padding != null) {
      return new PaddedBufferedBlockCipher(cipher, getPadding(padding));
    }
    return new BufferedBlockCipher(cipher);
  }

  private static BlockCipherPadding getPadding(final String padding)
  {
    final String name;
    final int pIndex = padding.indexOf("Padding");
    if (pIndex > -1) {
      name = padding.substring(0, pIndex);
    } else {
      name = padding;
    }
    BlockCipherPadding blockCipherPadding;
    if ("ISO7816d4".equalsIgnoreCase(name) | "ISO7816".equalsIgnoreCase(name)) {
      blockCipherPadding = new ISO7816d4Padding();
    } else if ("ISO10126".equalsIgnoreCase(padding) || "ISO10126-2".equalsIgnoreCase(padding)) {
      blockCipherPadding = new ISO10126d2Padding();
    } else if ("PKCS7".equalsIgnoreCase(padding) || "PKCS5".equalsIgnoreCase(padding)) {
      blockCipherPadding = new PKCS7Padding();
    } else if ("TBC".equalsIgnoreCase(padding)) {
      blockCipherPadding = new TBCPadding();
    } else if ("X923".equalsIgnoreCase(padding)) {
      blockCipherPadding = new X923Padding();
    } else if ("NULL".equalsIgnoreCase(padding) || "Zero".equalsIgnoreCase(padding)) {
      blockCipherPadding = new ZeroBytePadding();
    } else {
      throw new IllegalArgumentException("Invalid padding " + padding);
    }
    return blockCipherPadding;
  }
}
