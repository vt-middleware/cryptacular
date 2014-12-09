/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import org.bouncycastle.crypto.Digest;
import org.cryptacular.spec.Spec;

/**
 * Computes a hash using an instance of {@link Digest} specified by {@link
 * #setDigestSpec(org.cryptacular.spec.Spec)}.
 *
 * @author  Middleware Services
 */
public class SimpleHashBean extends AbstractHashBean implements HashBean<byte[]>
{

  /** Creates a new instance. */
  public SimpleHashBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  digestSpec  Digest specification.
   * @param  iterations  Number of hash rounds.
   */
  public SimpleHashBean(final Spec<Digest> digestSpec, final int iterations)
  {
    super(digestSpec, iterations);
  }


  @Override
  public byte[] hash(final Object... data)
  {
    return hashInternal(data);
  }


  /**
   * Compares a known hash value with the hash of the given data.
   *
   * @param  hash  Known hash value. If the length of the array is greater than
   *               the length of the digest output, anything beyond the digest
   *               length is considered salt data that is hashed <strong>
   *               after</strong> the input data.
   * @param  data  Data to hash.
   *
   * @return  True if the hashed data matches the given hash, false otherwise.
   */
  @Override
  public boolean compare(final byte[] hash, final Object... data)
  {
    return compareInternal(hash, data);
  }
}
