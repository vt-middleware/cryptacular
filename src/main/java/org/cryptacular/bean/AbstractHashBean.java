/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import org.bouncycastle.crypto.Digest;
import org.cryptacular.CryptUtil;
import org.cryptacular.spec.Spec;
import org.cryptacular.util.HashUtil;

/**
 * Abstract base class for all hash beans.
 *
 * @author  Middleware Services
 */
public abstract class AbstractHashBean
{

  /** Digest specification. */
  private final Spec<Digest> digestSpec;

  /** Number of hash rounds. */
  private final int iterations;


  /**
   * Creates a new abstract hash bean.
   *
   * @param  digestSpec  Digest specification.
   */
  public AbstractHashBean(final Spec<Digest> digestSpec)
  {
    this(digestSpec, 1);
  }


  /**
   * Creates a new abstract hash bean.
   *
   * @param  digestSpec  Digest specification.
   * @param  iterations  Number of hash rounds.
   */
  public AbstractHashBean(final Spec<Digest> digestSpec, final int iterations)
  {
    if (iterations < 1) {
      throw new IllegalArgumentException("Iterations must be positive");
    }
    this.digestSpec = CryptUtil.assertNotNullArg(digestSpec, "Digest spec cannot be null");
    this.iterations = iterations;
  }


  /** @return  Digest specification that determines the instance of {@link Digest} used to compute the hash. */
  public Spec<Digest> getDigestSpec()
  {
    return digestSpec;
  }


  /** @return  Number of iterations the digest function is applied to the input data. */
  public int getIterations()
  {
    return iterations;
  }


  /**
   * Hashes the given data.
   *
   * @param  data  Data to hash.
   *
   * @return  Digest output.
   */
  protected byte[] hashInternal(final Object... data)
  {
    return HashUtil.hash(digestSpec.newInstance(), iterations, data);
  }


  /**
   * Compares the hash of the given data against a known hash output.
   *
   * @param  hash  Known hash value. If the length of the array is greater than the length of the digest output,
   *               anything beyond the digest length is considered salt data that is hashed <strong>after</strong> the
   *               input data.
   * @param  data  Data to hash.
   *
   * @return  True if hashed data equals known hash output, false otherwise.
   */
  protected boolean compareInternal(final byte[] hash, final Object... data)
  {
    return HashUtil.compareHash(digestSpec.newInstance(), hash, iterations, data);
  }
}
