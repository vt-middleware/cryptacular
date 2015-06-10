/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

/**
 * Runtime error describing an encoding problem of a cryptographic primitive (e.g. private key, X.509 certificate).
 *
 * @author  Middleware Services
 */
public class EncodingException extends RuntimeException
{
  /**
   * Creates a new instance with the given error message.
   *
   * @param  message  Error message.
   */
  public EncodingException(final String message)
  {
    super(message);
  }


  /**
   * Creates a new instance with the given error message and cause.
   *
   * @param  message  Error message.
   * @param  cause  Error cause.
   */
  public EncodingException(final String message, final Throwable cause)
  {
    super(message, cause);
  }
}
