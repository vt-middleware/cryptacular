/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.spec;

/**
 * Specification for a cryptographic primitive, e.g. block cipher, message
 * digest, etc.
 *
 * @param  <T>  Type of specification.
 *
 * @author  Middleware Services
 */
public interface Spec<T>
{

  /** @return  Cryptographic algorithm name. */
  String getAlgorithm();


  /**
   * Creates a new instance of the cryptographic primitive described by this
   * specification.
   *
   * @return  New instance of cryptographic primitive.
   */
  T newInstance();
}
