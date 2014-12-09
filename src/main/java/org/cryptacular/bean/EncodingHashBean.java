/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import org.bouncycastle.crypto.Digest;
import org.cryptacular.codec.Codec;
import org.cryptacular.spec.Spec;
import org.cryptacular.util.CodecUtil;

/**
 * Computes a hash in an encoded format, e.g. hex, base64.
 *
 * @author  Middleware Services
 */
public class EncodingHashBean extends AbstractHashBean
  implements HashBean<String>
{

  /** Determines kind of encoding. */
  private Spec<Codec> codecSpec;


  /** Creates a new instance. */
  public EncodingHashBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  codecSpec  Digest specification.
   * @param  digestSpec  Digest specification.
   * @param  iterations  Number of hash rounds.
   */
  public EncodingHashBean(
    final Spec<Codec> codecSpec,
    final Spec<Digest> digestSpec,
    final int iterations)
  {
    super(digestSpec, iterations);
    setCodecSpec(codecSpec);
  }


  /**
   * @return  Codec specification that determines the encoding applied to the
   *          hash output bytes.
   */
  public Spec<Codec> getCodecSpec()
  {
    return codecSpec;
  }


  /**
   * Sets the codec specification that determines the encoding applied to the
   * hash output bytes.
   *
   * @param  codecSpec  Codec specification, e.g. {@link
   *                    org.cryptacular.spec.CodecSpec#BASE64}, {@link
   *                    org.cryptacular.spec.CodecSpec#HEX}.
   */
  public void setCodecSpec(final Spec<Codec> codecSpec)
  {
    this.codecSpec = codecSpec;
  }


  @Override
  public String hash(final Object... data)
  {
    return
      CodecUtil.encode(
        codecSpec.newInstance().getEncoder(),
        hashInternal(data));
  }


  /**
   * Compares a known hash value with the hash of the given data.
   *
   * @param  hash  Known encoded hash value. If the length of the hash bytes
   *               after decoding is greater than the length of the digest
   *               output, anything beyond the digest length is considered salt
   *               data that is hashed <strong>after</strong> the input data.
   * @param  data  Data to hash.
   *
   * @return  True if the hashed data matches the given hash, false otherwise.
   */
  @Override
  public boolean compare(final String hash, final Object... data)
  {
    return
      compareInternal(
        CodecUtil.decode(codecSpec.newInstance().getDecoder(), hash),
        data);
  }
}
