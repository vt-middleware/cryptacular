package org.cryptosis.bean;

import org.cryptosis.spec.CodecSpec;
import org.cryptosis.spec.DigestSpec;
import org.cryptosis.util.CodecUtil;
import org.cryptosis.util.HashUtil;
import org.cryptosis.util.StreamUtil;

import java.io.InputStream;

/**
 * Computes a hash in an encoded format, e.g. hex, base64.
 *
 * @author Marvin S. Addison
 */
public class EncodingHashBean implements HashBean<String>
{
  /** Digest specification. */
  protected DigestSpec digestSpec;

  /** Determines kind of encoding. */
  private CodecSpec codecSpec;


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


  /**
   * Sets the codec specification that determines the encoding applied to the hash output bytes.
   *
   * @param  codecSpec  Codec specification, e.g. {@link CodecSpec#BASE64}, {@link CodecSpec#HEX}.
   */
  public void setCodecSpec(CodecSpec codecSpec)
  {
    this.codecSpec = codecSpec;
  }


  /** {@inheritDoc} */
  @Override
  public String hash(final byte[] input)
  {
    return CodecUtil.encode(codecSpec.newInstance().getEncoder(), computeHash(input));
  }


  /** {@inheritDoc} */
  @Override
  public String hash(final InputStream input)
  {
    return CodecUtil.encode(codecSpec.newInstance().getEncoder(), computeHash(StreamUtil.readAll(input)));
  }


  /**
   * Computes the hash.
   *
   * @return  Unencoded digest bytes.
   */
  protected byte[] computeHash(final byte[] input)
  {
    return HashUtil.hash(digestSpec.newInstance(), input);
  }
}
