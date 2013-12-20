package org.cryptosis.generator;

/**
 * Runtime exception that describes a condition where some fundamental limit imposed by the implementation or
 * specification of a generator has been exceeded.
 *
 * @author Marvin S. Addison
 */
public class LimitException extends RuntimeException
{
  /**
   * Creates a new instance with the given error description..
   *
   * @param  message  Error message.
   */
  public LimitException(final String message) {
    super(message);
  }
}
