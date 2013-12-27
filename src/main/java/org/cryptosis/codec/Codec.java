package org.cryptosis.codec;

/**
 * Container for an encoder/decoder pair.
 *
 * @author Marvin S. Addison
 */
public interface Codec
{
  /**
   * @return  The byte-to-char encoder of the codec pair.
   */
  Encoder getEncoder();


  /**
   * @return  The char-to-byte decoder of the codec pair.
   */
  Decoder getDecoder();
}
