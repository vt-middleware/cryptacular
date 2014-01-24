/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

/**
 * Nonce generation strategy.
 *
 * @author  Middleware Services
 */
public interface Nonce
{

  /**
   * Generates a nonce value.
   *
   * @return  Nonce bytes.
   *
   * @throws  LimitException  When a limit imposed by the nonce generation
   * strategy, if any, is exceeded.
   */
  byte[] generate()
    throws LimitException;


  /** @return  Length in bytes of generated nonce values. */
  int getLength();
}
