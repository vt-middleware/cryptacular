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

package org.cryptacular.bean;

import org.cryptacular.codec.Codec;
import org.cryptacular.spec.Spec;
import org.cryptacular.util.CodecUtil;

/**
 * Computes a hash in an encoded format, e.g. hex, base64.
 *
 * @author Marvin S. Addison
 */
public class EncodingHashBean extends AbstractHashBean implements HashBean<String>
{
  /** Determines kind of encoding. */
  private Spec<Codec> codecSpec;


  /**
   * @return  Codec specification that determines the encoding applied to the hash output bytes.
   */
  public Spec<Codec> getCodecSpec()
  {
    return codecSpec;
  }


  /**
   * Sets the codec specification that determines the encoding applied to the hash output bytes.
   *
   * @param  codecSpec  Codec specification, e.g. {@link org.cryptacular.spec.CodecSpec#BASE64},
   *                    {@link org.cryptacular.spec.CodecSpec#HEX}.
   */
  public void setCodecSpec(final Spec<Codec> codecSpec)
  {
    this.codecSpec = codecSpec;
  }


  /** {@inheritDoc} */
  @Override
  public String hash(final Object ... data)
  {
    return CodecUtil.encode(codecSpec.newInstance().getEncoder(), hashInternal(data));
  }


  /**
   * Compares a known hash value with the hash of the given data.
   *
   * @param  hash  Known encoded hash value. If the length of the hash bytes after decoding is greater than the length
   *               of the digest output, anything beyond the digest length is considered salt data that is hashed
   *               <strong>after</strong> the input data.
   * @param  data  Data to hash.
   *
   * @return  True if the hashed data matches the given hash, false otherwise.
   */
  @Override
  public boolean compare(final String hash, final Object ... data)
  {
    return compareInternal(CodecUtil.decode(codecSpec.newInstance().getDecoder(), hash), data);
  }
}
