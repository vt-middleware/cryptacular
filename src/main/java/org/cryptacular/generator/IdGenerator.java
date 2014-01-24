/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

/**
 * Generation strategy for random identifiers.
 *
 * @author  Middleware Services
 */
public interface IdGenerator
{

  /**
   * Generates a random identifier.
   *
   * @return  Random identifier.
   */
  String generate();
}
