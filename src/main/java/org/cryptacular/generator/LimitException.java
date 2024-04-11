/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

/**
 * Runtime exception that describes a condition where some fundamental limit imposed by the implementation or
 * specification of a generator has been exceeded.
 *
 * @author  Middleware Services
 */
public class LimitException extends RuntimeException
{

  /**
   * Creates a new instance with the given error description.
   *
   * @param  message  Error message.
   */
  public LimitException(final String message)
  {
    super(message);
  }
}
