package org.cryptosis.spec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.*;

/**
 * Block cipher specification.
 *
 * @author Marvin S. Addison
 */
public class BlockCipherSpec implements Spec<BlockCipher>
{
  /** Cipher algorithm algorithm. */
  private final String algorithm;


  /**
   * Creates a new instance that describes the given block cipher algorithm.
   *
   * @param  algName  Block cipher algorithm.
   */
  public BlockCipherSpec(final String algName)
  {
    this.algorithm = algName;
  }


  /** {@inheritDoc} */
  public String getAlgorithm()
  {
    return algorithm;
  }


  /** {@inheritDoc} */
  public BlockCipher newInstance()
  {
    BlockCipher cipher;
    if ("AES".equalsIgnoreCase(algorithm)) {
      cipher = new AESFastEngine();
    } else if ("Blowfish".equalsIgnoreCase(algorithm)) {
      cipher = new BlowfishEngine();
    } else if ("Camellia".equalsIgnoreCase(algorithm)) {
      cipher = new CamelliaEngine();
    } else if ("CAST5".equalsIgnoreCase(algorithm)) {
      cipher = new CAST5Engine();
    } else if ("CAST6".equalsIgnoreCase(algorithm)) {
      cipher = new CAST6Engine();
    } else if ("DES".equalsIgnoreCase(algorithm)) {
      cipher = new DESEngine();
    } else if ("DESede".equalsIgnoreCase(algorithm) || "DES3".equalsIgnoreCase(algorithm)) {
      cipher = new DESedeEngine();
    } else if ("GOST".equalsIgnoreCase(algorithm) || "GOST28147".equals(algorithm)) {
      cipher = new GOST28147Engine();
    } else if ("Noekeon".equalsIgnoreCase(algorithm)) {
      cipher = new NoekeonEngine();
    } else if ("RC2".equalsIgnoreCase(algorithm)) {
      cipher = new RC2Engine();
    } else if ("RC5".equalsIgnoreCase(algorithm)) {
      cipher = new RC564Engine();
    } else if ("RC6".equalsIgnoreCase(algorithm)) {
      cipher = new RC6Engine();
    } else if ("SEED".equalsIgnoreCase(algorithm)) {
      cipher = new SEEDEngine();
    } else if ("Serpent".equalsIgnoreCase(algorithm)) {
      cipher = new SerpentEngine();
    } else if ("Skipjack".equalsIgnoreCase(algorithm)) {
      cipher = new SkipjackEngine();
    } else if ("TEA".equalsIgnoreCase(algorithm)) {
      cipher = new TEAEngine();
    } else if ("Twofish".equalsIgnoreCase(algorithm)) {
      cipher = new TwofishEngine();
    } else if ("XTEA".equalsIgnoreCase(algorithm)) {
      cipher = new XTEAEngine();
    } else {
      throw new IllegalStateException("Unsupported cipher algorithm " + algorithm);
    }
    return cipher;
  }


  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    return algorithm;
  }

}
