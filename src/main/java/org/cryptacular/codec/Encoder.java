/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import org.cryptacular.EncodingException;

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
   *
   * @throws  EncodingException  on encoding errors.
   */
  void encode(ByteBuffer input, CharBuffer output) throws EncodingException;


  /**
   * Performs final output encoding (e.g. padding) after all input bytes have been provided.
   *
   * @param  output  Output character buffer.
   *
   * @throws  EncodingException  on encoding errors.
   */
  void finalize(CharBuffer output) throws EncodingException;


  /**
   * Expected number of characters in the output buffer for an input buffer of the given size.
   *
   * @param  inputSize  Size of input buffer in bytes.
   *
   * @return  Minimum character buffer size required to store all encoded input bytes.
   */
  int outputSize(int inputSize);
}
