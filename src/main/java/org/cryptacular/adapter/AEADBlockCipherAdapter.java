/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.cryptacular.CryptUtil;
import org.cryptacular.CryptoException;

/**
 * Adapts a {@link AEADBlockCipherAdapter}.
 *
 * @author  Middleware Services
 */
public class AEADBlockCipherAdapter implements BlockCipherAdapter
{

  /** All methods delegate to this instance. */
  private final AEADBlockCipher cipherDelegate;


  /**
   * Creates a new instance that delegates to the given cipher.
   *
   * @param  delegate  Adapted cipher.
   */
  public AEADBlockCipherAdapter(final AEADBlockCipher delegate)
  {
    cipherDelegate = CryptUtil.assertNotNullArg(delegate, "Cipher delegate cannot be null");
  }


  @Override
  public int getOutputSize(final int len)
  {
    return cipherDelegate.getOutputSize(len);
  }


  @Override
  public void init(final boolean forEncryption, final CipherParameters params) throws CryptoException
  {
    try {
      cipherDelegate.init(forEncryption, params);
    } catch (RuntimeException e) {
      throw new CryptoException("Cipher initialization error", e);
    }
  }


  @Override
  public int processBytes(final byte[] in, final int inOff, final int len, final byte[] out, final int outOff)
      throws CryptoException
  {
    try {
      return cipherDelegate.processBytes(in, inOff, len, out, outOff);
    } catch (RuntimeException e) {
      throw new CryptoException("Cipher processing error", e);
    }
  }


  @Override
  public int doFinal(final byte[] out, final int outOff) throws CryptoException
  {
    try {
      return cipherDelegate.doFinal(out, outOff);
    } catch (InvalidCipherTextException e) {
      throw new CryptoException("Error finalizing cipher", e);
    }
  }


  @Override
  public void reset()
  {
    cipherDelegate.reset();
  }
}
