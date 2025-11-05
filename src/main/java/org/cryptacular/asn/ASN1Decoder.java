/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.asn;

import org.cryptacular.EncodingException;

/**
 * Strategy interface for converting encoded ASN.1 bytes to an object.
 *
 * @param  <T>  Type of object to produce on decode.
 *
 * @author  Middleware Services
 */
public interface ASN1Decoder<T>
{

  /**
   * Produces an object from an encoded representation.
   *
   * @param  encoded  ASN.1 encoded data.
   * @param  args  Additional data required to perform decoding.
   *
   * @return  Decoded object.
   *
   * @throws  EncodingException  on encoding errors.
   */
  T decode(byte[] encoded, Object... args) throws EncodingException;
}
