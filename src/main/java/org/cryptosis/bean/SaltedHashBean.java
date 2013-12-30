package org.cryptosis.bean;

import org.cryptosis.generator.Nonce;
import org.cryptosis.util.HashUtil;

/**
 * Computes a salted hash from a random salt source.
 *
 * @author Marvin S. Addison
 */
public class SaltedHashBean extends EncodingHashBean
{
  /** Random salt source. */
  private Nonce saltSource;

  /** Number of hash iterations. */
  private int iterations = 1;


  /**
   * Sets the random salt source.
   *
   * @param  saltSource  Source of random salt data.
   */
  public void setSaltSource(final Nonce saltSource)
  {
    this.saltSource = saltSource;
  }


  /**
   * Sets the number of iterations the digest function is applied to the input data.
   *
   * @param  iterations  Digest function iterations. Default value is 1.
   */
  public void setIterations(final int iterations)
  {
    this.iterations = iterations;
  }


  /** {@inheritDoc} */
  @Override
  protected byte[] computeHash(final byte[] input)
  {
    return HashUtil.hash(digestSpec.newInstance(), input, saltSource.generate(), iterations);
  }
}
