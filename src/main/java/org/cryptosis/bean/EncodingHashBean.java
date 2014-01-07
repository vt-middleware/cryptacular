/*
 * Licensed to Virginia Tech under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Virginia Tech licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.cryptosis.bean;

import java.io.InputStream;

import org.bouncycastle.crypto.Digest;
import org.cryptosis.codec.Codec;
import org.cryptosis.spec.DigestSpec;
import org.cryptosis.spec.Spec;
import org.cryptosis.util.CodecUtil;
import org.cryptosis.util.HashUtil;
import org.cryptosis.util.StreamUtil;

/**
 * Computes a hash in an encoded format, e.g. hex, base64.
 *
 * @author Marvin S. Addison
 */
public class EncodingHashBean implements HashBean<String>
{
  /** Digest specification. */
  protected Spec<Digest> digestSpec;

  /** Determines kind of encoding. */
  private Spec<Codec> codecSpec;


  /**
   * Sets the digest specification that determines the instance of {@link Digest} used to compute the hash.
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
   * @param  codecSpec  Codec specification, e.g. {@link org.cryptosis.spec.CodecSpec#BASE64},
   *                    {@link org.cryptosis.spec.CodecSpec#HEX}.
   */
  public void setCodecSpec(final Spec<Codec> codecSpec)
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
   * @param  input  Input data to hash.
   *
   * @return  Unencoded digest bytes.
   */
  protected byte[] computeHash(final byte[] input)
  {
    return HashUtil.hash(digestSpec.newInstance(), input);
  }
}
