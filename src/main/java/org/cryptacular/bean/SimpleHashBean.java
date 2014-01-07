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

import java.io.InputStream;

import org.bouncycastle.crypto.Digest;
import org.cryptacular.spec.Spec;
import org.cryptacular.util.HashUtil;

/**
 * Computes a hash using an instance of {@link Digest} specified by
 * {@link #setDigestSpec(org.cryptacular.spec.Spec)}.
 *
 * @author Marvin S. Addison
 */
public class SimpleHashBean implements HashBean<byte[]>
{
  /** Digest specification. */
  private Spec<Digest> digestSpec;


  /**
   * @return  Digest specification that determines the instance of {@link Digest} used to compute the hash.
   */
  public Spec<Digest> getDigestSpec()
  {
    return digestSpec;
  }


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


  /** {@inheritDoc} */
  @Override
  public boolean compare(final byte[] input, final byte[] hash)
  {
    return HashUtil.compareHash(digestSpec.newInstance(), input, hash);
  }


  /** {@inheritDoc} */
  @Override
  public boolean compare(final InputStream input, final byte[] hash)
  {
    return HashUtil.compareHash(digestSpec.newInstance(), input, hash);
  }
}
