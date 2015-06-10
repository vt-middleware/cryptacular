/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.adapter;

import org.bouncycastle.crypto.CipherParameters;
import org.cryptacular.CryptoException;

/**
 * Provides a consistent interface for cipher operations against dissimilar BC cipher types.
 *
 * @author  Middleware Services
 */
public interface CipherAdapter
{

  /**
   * Initialize the underlying cipher.
   *
   * @param  forEncryption  True for encryption mode, false for decryption mode.
   * @param  params  Cipher initialization parameters.
   *
   * @throws  CryptoException  on underlying cipher initialization errors.
   */
  void init(boolean forEncryption, CipherParameters params) throws CryptoException;


  /**
   * Process an array of bytes, producing output if necessary.
   *
   * @param  in  Input data.
   * @param  inOff  Offset at which the input data starts.
   * @param  len  The number of bytes in the input data to process.
   * @param  out  Array to receive any data produced by cipher.
   * @param  outOff  Offset into output array.
   *
   * @return  The number of bytes produced by the cipher.
   *
   * @throws  CryptoException  on underlying cipher data handling errors.
   */
  int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws CryptoException;


  /**
   * Reset the cipher. After resetting the cipher is in the same state as it was after the last init (if there was one).
   */
  void reset();
}
