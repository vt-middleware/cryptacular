package org.cryptosis.bean.adapter;

/**
 * Adapter for all block cipher types.
 *
 * @author Marvin S. Addison
 */
public interface BlockCipherAdapter extends CipherAdapter
{
  /**
   * Gets the size of the output buffer required to hold the output of an input buffer of the given size.
   *
   * @param  len  Length of input buffer.
   *
   * @return  Size of output buffer.
   */
  int getOutputSize(int len);


  /**
   * Finish the encryption/decryption operation (e.g. apply padding).
   *
   * @param  out  Output buffer to receive final processing output.
   * @param  outOff  Offset into output buffer where processed data should start.
   *
   * @return  Number of bytes written to output buffer.
   */
  int doFinal(byte[] out, int outOff);
}
