/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;
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

  /** Whether data provided to this bean includes a salt. */
  private boolean salted;


  /** Creates a new instance. */
  public EncodingHashBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  codecSpec  Digest specification.
   * @param  digestSpec  Digest specification.
   * @param  iterations  Number of hash rounds.
   * @param  salted  Whether hash data will be salted.
   */
  public EncodingHashBean(
    final Spec<Codec> codecSpec,
    final Spec<Digest> digestSpec,
    final int iterations,
    final boolean salted)
  {
    super(digestSpec, iterations);
    setCodecSpec(codecSpec);
    setSalted(salted);
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


  /**
   * Whether data provided to {@link #hash(Object...)} includes a salt as the
   * last parameter.
   *
   * @return  whether hash data includes a salt
   */
  public boolean isSalted()
  {
    return salted;
  }


  /**
   * Sets whether {@link #hash(Object...)} should expect a salt as the last
   * parameter.
   *
   * @param  salted  whether hash data includes a salt
   */
  public void setSalted(final boolean salted)
  {
    this.salted = salted;
  }


  /**
   * Hashes the given data. If {@link #isSalted()} is true then the last
   * parameter must be a byte array containing the salt. The salt value will be
   * appended to the encoded hash that is returned.
   *
   * @param  data  Data to hash.
   *
   * @return  Encoded digest output, including a salt if provided.
   */
  @Override
  public String hash(final Object... data)
  {
    if (salted) {
      if (data.length < 2 || !(data[data.length - 1] instanceof byte[])) {
        throw new IllegalArgumentException(
          "Last parameter must be a salt of type byte[]");
      }
      final byte[] hashSalt = (byte[]) data[data.length - 1];
      return
        CodecUtil.encode(
          codecSpec.newInstance().getEncoder(),
          Arrays.concatenate(hashInternal(data), hashSalt));
    }
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
