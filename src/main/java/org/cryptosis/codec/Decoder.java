package org.cryptosis.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * Describes a potentially stateful character-to-byte decoder.
 *
 * @author Marvin S. Addison
 */
public interface Decoder
{
  /**
   * Decodes characters in input buffer into bytes placed in the output buffer.
   * This method may be called multiple times, followed by {@link #finalize(java.nio.CharBuffer)}
   * after all input bytes have been provided.
   *
   * @param  input  Input character buffer.
   * @param  output  Output byte buffer.
   */
  void decode(CharBuffer input, ByteBuffer output);


  /**
   * Performs final output decoding (e.g. padding) after all input characters have been provided.
   *
   * @param  output  Output byte buffer.
   */
  void finalize(ByteBuffer output);


  /**
   * Expected number of bytes in the output buffer for an input buffer of the given size.
   *
   * @param  inputSize  Size of input buffer in characters.
   *
   * @return  Minimum byte buffer size required to store all decoded characters in input buffer.
   */
  int outputSize(int inputSize);
}
