/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

/**
 * Describes a cleartext header prepended to ciphertext providing data required for decryption.
 *
 * @author  Middleware Services
 */
public interface CiphertextHeader
{
  /**
   * Gets the header length in bytes.
   *
   * @return Header length in bytes.
   */
  int getLength();

  /**
   * Gets the bytes of the nonce/IV.
   *
   * @return Nonce bytes.
   */
  byte[] getNonce();

  /**
   * Gets the encryption key name stored in the header.
   *
   * @return Encryption key name.
   */
  String getKeyName();


  /**
   * Encodes the header into bytes.
   *
   * @return Byte representation of header.
   */
  byte[] encode();
}
