/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;

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
    cipherDelegate = delegate;
  }


  /** {@inheritDoc} */
  @Override
  public int getOutputSize(final int len)
  {
    return cipherDelegate.getOutputSize(len);
  }


  /** {@inheritDoc} */
  @Override
  public void init(final boolean forEncryption, final CipherParameters params)
  {
    cipherDelegate.init(forEncryption, params);
  }


  /** {@inheritDoc} */
  @Override
  public int processBytes(
    final byte[] in,
    final int inOff,
    final int len,
    final byte[] out,
    final int outOff)
  {
    return cipherDelegate.processBytes(in, inOff, len, out, outOff);
  }


  /** {@inheritDoc} */
  @Override
  public int doFinal(final byte[] out, final int outOff)
  {
    try {
      return cipherDelegate.doFinal(out, outOff);
    } catch (InvalidCipherTextException e) {
      throw new RuntimeException("Error finalizing cipher", e);
    }
  }


  /** {@inheritDoc} */
  @Override
  public void reset()
  {
    cipherDelegate.reset();
  }
}
