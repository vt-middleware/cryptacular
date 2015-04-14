/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * Describes a potentially stateful byte-to-character encoder.
 *
 * @author  Middleware Services
 */
public interface Encoder
{

  /**
   * Encodes bytes in input buffer into characters placed in the output buffer. This method may be called multiple
   * times, followed by {@link #finalize(java.nio.CharBuffer)} after all input bytes have been provided.
   *
   * @param  input  Input byte buffer.
   * @param  output  Output character buffer.
   */
  void encode(ByteBuffer input, CharBuffer output);


  /**
   * Performs final output encoding (e.g. padding) after all input bytes have been provided.
   *
   * @param  output  Output character buffer.
   */
  void finalize(CharBuffer output);


  /**
   * Expected number of characters in the output buffer for an input buffer of the given size.
   *
   * @param  inputSize  Size of input buffer in bytes.
   *
   * @return  Minimum character buffer size required to store all encoded input bytes.
   */
  int outputSize(int inputSize);
}
