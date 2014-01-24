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
}
