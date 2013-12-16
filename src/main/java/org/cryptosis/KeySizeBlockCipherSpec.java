package org.cryptosis;

/**
 * Describes a block cipher algorithm with a known key size.
 *
 * @author Marvin S. Addison
 */
public class KeySizeBlockCipherSpec extends BlockCipherSpec
{
  /** Key length in bits. */
  private final int keyLength;


  /**
   * Creates a new instance from the given cipher specifications.
   *
   * @param  algName  Cipher algorithm name.
   * @param  cipherMode  Cipher mode.
   * @param  cipherPadding  Cipher padding scheme algorithm.
   * @param  keyBitLength  Key length in bits.
   */
  public KeySizeBlockCipherSpec(
    final String algName, final String cipherMode, final String cipherPadding, final int keyBitLength)
  {
    super(algName, cipherMode, cipherPadding);
    if (keyBitLength < 0) {
      throw new IllegalArgumentException("Key length must be non-negative");
    }
    this.keyLength = keyBitLength;
  }


  /**
   * Gets the cipher key length in bits.
   *
   * @return  Key length in bits.
   */
  public int getKeyLength()
  {
    return keyLength;
  }
}
