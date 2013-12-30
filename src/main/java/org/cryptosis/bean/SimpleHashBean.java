package org.cryptosis.bean;

import org.bouncycastle.crypto.Digest;
import org.cryptosis.spec.Spec;
import org.cryptosis.util.HashUtil;

import java.io.InputStream;

/**
 * Computes a hash using an instance of {@link Digest} specified by
 * {@link #setDigestSpec(org.cryptosis.spec.Spec)}.
 *
 * @author Marvin S. Addison
 */
public class SimpleHashBean implements HashBean<byte[]>
{
  /** Digest specification. */
  private Spec<Digest> digestSpec;


  /**
   * Sets the digest specification that determines the instance of {@link Digest} used to compute the hash.
   *
   * @param  digestSpec  Digest algorithm specification.
   */
  public void setDigestSpec(final Spec<Digest> digestSpec)
  {
    this.digestSpec = digestSpec;
  }


  /** {@inheritDoc} */
  @Override
  public byte[] hash(final byte[] input)
  {
    return HashUtil.hash(digestSpec.newInstance(), input);
  }


  /** {@inheritDoc} */
  @Override
  public byte[] hash(final InputStream input)
  {
    return HashUtil.hash(digestSpec.newInstance(), input);
  }
}
