/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

import javax.crypto.SecretKey;

/**
 * Interface to allow custom implementations of secret key lookups.
 *
 * @deprecated  In newer versions, KeyLookup is replaced by java.util.Function&lt;String, SecretKey&gt; instances.
 *
 * @author  Middleware Services
 */
@Deprecated
public interface KeyLookup
{

  /**
   * Looks up the key with the provided key name.
   *
   * @param  keyName  Name of secret key entry.
   * @return  Secret key.
   */
  SecretKey lookupKey(String keyName);
}
