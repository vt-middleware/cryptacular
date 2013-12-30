package org.cryptosis.bean;

import org.cryptosis.spec.DigestSpec;
import org.cryptosis.util.HashUtil;

import java.io.InputStream;

/**
 * Computes a hash using an instance of {@link org.bouncycastle.crypto.Digest} specified by
 * {@link #setDigestSpec(org.cryptosis.spec.DigestSpec)}.
 *
 * @author Marvin S. Addison
 */
public class SimpleHashBean implements HashBean<byte[]>
{
  /** Digest specification. */
  private DigestSpec digestSpec;


  /**
   * Sets the digest specification that determines the instance of {@link org.bouncycastle.crypto.Digest} used to
   * compute the hash.
   *
   * @param  digestSpec  Digest algorithm specification.
   */
  public void setDigestSpec(final DigestSpec digestSpec)
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
