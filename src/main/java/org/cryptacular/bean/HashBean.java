/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

/**
 * Strategy interface to support beans that produce hash outputs in various
 * formats, e.g. raw bytes, hex output, etc.
 *
 * @param  <T>  Type of output (e.g. byte[], string) produced by hash bean.
 *
 * @author  Middleware Services
 */
public interface HashBean<T>
{

  /**
   * Hashes the given data.
   *
   * @param  data  Data to hash. Callers should expect support for at least the
   * following types: <code>byte[]</code>, {@link CharSequence}, {@link
   * java.io.InputStream}, and {@link org.cryptacular.io.Resource}. Unless
   * otherwise noted, character data is processed in the <code>UTF-8</code>
   * character set; if another character set is desired, the caller should
   * convert to <code>byte[]</code> and provide the resulting bytes.
   *
   * @return  Digest output.
   */
  T hash(Object... data);


  /**
   * Compares a known hash value with the hash of the given data.
   *
   * @param  hash  Known hash value.
   * @param  data  Data to hash.
   *
   * @return  True if the hashed data matches the given hash, false otherwise.
   */
  boolean compare(final T hash, Object... data);
}
