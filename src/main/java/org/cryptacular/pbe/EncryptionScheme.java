/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.pbe;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Describes a password-based encryption scheme.
 *
 * @author  Middleware Services
 * @version  $Revision: 2744 $
 */
public interface EncryptionScheme
{

  /**
   * Encrypts the given plaintext bytes into a byte array of ciphertext using
   * the derived key.
   *
   * @param  plaintext  Input plaintext bytes.
   *
   * @return  Ciphertext resulting from plaintext encryption.
   */
  byte[] encrypt(byte[] plaintext);


  /**
   * Encrypts the data in the given plaintext input stream into ciphertext in
   * the output stream. Use {@link org.cryptacular.io.EncodingOutputStream} to
   * produce ciphertext bytes that encoded as a string data in the output
   * stream.
   *
   * @param  in  Input stream of plaintext.
   * @param  out  Output stream of ciphertext.
   *
   * @throws  IOException  On stream read/write errors.
   */
  void encrypt(InputStream in, OutputStream out)
    throws IOException;


  /**
   * Decrypts the given ciphertext into plaintext using the derived key.
   *
   * @param  ciphertext  Input ciphertext bytes.
   *
   * @return  Plaintext resulting from ciphertext decryption.
   */
  byte[] decrypt(byte[] ciphertext);


  /**
   * Decrypts ciphertext from an input stream into plaintext in the output
   * stream. Use {@link org.cryptacular.io.DecodingInputStream} to handle input
   * ciphertext encoded as string data.
   *
   * @param  in  Input stream of ciphertext.
   * @param  out  Output stream of plaintext.
   *
   * @throws  IOException  On stream read/write errors.
   */
  void decrypt(InputStream in, OutputStream out)
    throws IOException;
}
