/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

/**
 * Contract interface for converting encoded bytes to an object.
 *
 * @param  <T>  Type of object to produce on decode.
 *
 * @author  Middleware Services
 */
public interface KeyDecoder<T>
{

  /**
   * Produces an object from an encoded representation.
   *
   * @param  encoded  data.
   * @param  args  Additional data required to perform decoding.
   *
   * @return  Decoded object.
   *
   * @throws  EncodingException  on encoding errors.
   */
  T decode(byte[] encoded, Object... args) throws EncodingException;

}
