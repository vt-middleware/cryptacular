package org.cryptosis.spec;

/**
 * Specification for a cryptographic primitive, e.g. block cipher, message digest, etc.
 *
 * @author Marvin S. Addison
 */
public interface Spec<T>
{
  /**
   * @return  Cryptographic algorithm name.
   */
  String getAlgorithm();


  /**
   * Creates a new instance of the cryptographic primitive described by this specification.
   *
   * @return  New instance of cryptographic primitive.
   */
  T newInstance();
}
