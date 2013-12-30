package org.cryptosis.bean;

import java.io.InputStream;

/**
 * Strategy interface to support beans that produce hash outputs in various formats, e.g. raw bytes, hex output, etc.
 *
 * @author Marvin S. Addison
 */
public interface HashBean<T>
{
  /**
   * Hashes the given data.
   *
   * @param  input  Data to hash.
   *
   * @return  Raw digest output.
   */
  T hash(byte[] input);


  /**
   * Hashes the given data.
   *
   * @param  input  Data to hash.
   *
   * @return  Raw digest output.
   */
  T hash(InputStream input);
}
