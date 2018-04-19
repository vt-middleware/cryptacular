/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

/**
 * Container for an encoder/decoder pair.
 *
 * @author  Middleware Services
 */
public interface Codec
{


  /** @return  The byte-to-char encoder of the codec pair. */
  Encoder getEncoder();


  /** @return  The char-to-byte decoder of the codec pair. */
  Decoder getDecoder();


  /** @return  A new instance of the byte-to-char encoder of the codec pair. */
  Encoder newEncoder();


  /** @return  A new instance of the char-to-byte decoder of the codec pair. */
  Decoder newDecoder();
}
