package org.cryptosis.generator;

/**
 * Nonce generation strategy.
 *
 * @author Marvin S. Addison
 */
public interface Nonce
{
  /**
   * Generates a nonce value.
   *
   * @return  Nonce bytes.
   *
   * @throws LimitException  When a limit imposed by the nonce generation strategy, if any, is exceeded.
   */
  byte[] generate() throws LimitException;


  /**
   * @return  Length in bytes of generated nonce values.
   */
  int getLength();
}
