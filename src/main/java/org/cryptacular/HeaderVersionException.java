/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

/**
 * Describes an unsupported ciphertext header version.
 *
 * @author  Middleware Services
 */
public class HeaderVersionException extends EncodingException
{
  /**
   * Creates a new instance with the given error message.
   *
   * @param  message  Error message.
   */
  public HeaderVersionException(final String message)
  {
    super(message);
  }


  /**
   * Creates a new instance with the given error message and cause.
   *
   * @param  message  Error message.
   * @param  cause  Error cause.
   */
  public HeaderVersionException(final String message, final Throwable cause)
  {
    super(message, cause);
  }
}
