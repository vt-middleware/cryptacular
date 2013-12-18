package org.cryptosis.asn;

/**
 * Strategy interface for converting encoded ASN.1 bytes to an object.
 *
 * @author Marvin S. Addison
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
   */
  T decode(byte[] encoded, Object ... args);
}
