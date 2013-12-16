package org.cryptosis.util;

/**
 * Handles decoding of private keys from a binary encoding.
 *
 * @author Marvin S. Addison
 */
public interface PrivateKeyDecoder<T>
{
  /**
   * Produces a private key object from an encoded representation.
   *
   * @param  encoded  Encoded key data.
   *
   * @return  Decoded key.
   */
  T decode(byte[] encoded);


  /**
   * Produces a private key object from an encrypted encoded representation.
   *
   * @param  encoded  Encrypted encoded key data.
   *
   * @return  Decoded key.
   */
  T decode(byte[] encrypted, char[] password);
}
