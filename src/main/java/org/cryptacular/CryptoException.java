/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

/**
 * Runtime error describing a generic cryptographic problem (e.g. bad padding, unsupported cipher).
 *
 * @author  Middleware Services
 */
public class CryptoException extends RuntimeException
{
  /**
   * Creates a new instance with the given error message.
   *
   * @param  message  Error message.
   */
  public CryptoException(final String message)
  {
    super(message);
  }


  /**
   * Creates a new instance with the given cause.
   *
   * @param  cause  Error cause.
   */
  public CryptoException(final Throwable cause)
  {
    super(cause);
  }


  /**
   * Creates a new instance with the given error message and cause.
   *
   * @param  message  Error message.
   * @param  cause  Error cause.
   */
  public CryptoException(final String message, final Throwable cause)
  {
    super(message, cause);
  }
}
