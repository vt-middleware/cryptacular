/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

import java.io.IOException;

/**
 * Runtime exception thrown on stream IO errors. Effectively a runtime equivalent of {@link java.io.IOException}.
 *
 * @author  Middleware Services
 */
public class StreamException extends RuntimeException
{


  /**
   * Creates a new instance with the given error message.
   *
   * @param  message  Error message.
   */
  public StreamException(final String message)
  {
    super(message);
  }


  /**
   * Creates a new instance with causing IO exception.
   *
   * @param  cause  IO exception to wrap.
   */
  public StreamException(final IOException cause)
  {
    super("IO error", cause);
  }


  /**
   * Creates a new instance with causing IO exception and message.
   *
   * @param  message  Error message.
   * @param  cause  IO exception to wrap.
   */
  public StreamException(final String message, final IOException cause)
  {
    super(message, cause);
  }
}
