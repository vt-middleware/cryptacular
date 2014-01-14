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

import org.bouncycastle.crypto.Digest;
import org.cryptacular.spec.Spec;
import org.cryptacular.util.HashUtil;

/**
 * Abstract base class for all hash beans.
 *
 * @author Marvin S. Addison
 */
public abstract class AbstractHashBean
{
  /** Digest specification. */
  private Spec<Digest> digestSpec;

  /** Number of hash rounds. */
  private int iterations = 1;


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


  /**
   * @return  Number of iterations the digest function is applied to the input data.
   */
  public int getIterations()
  {
    return iterations;
  }


  /**
   * Sets the number of iterations the digest function is applied to the input data.
   *
   * @param  iterations  Number of hash rounds. Default value is 1.
   */
  public void setIterations(final int iterations)
  {
    if (iterations < 1) {
      throw new IllegalArgumentException("Iterations must be positive");
    }
    this.iterations = iterations;
  }


  /**
   * Hashes the given data.
   *
   * @param  data  Data to hash.
   *
   * @return  Digest output.
   */
  protected byte[] hashInternal(final Object ... data)
  {
    return HashUtil.hash(digestSpec.newInstance(), iterations, data);
  }


  /**
   * Compares the hash of the given data against a known hash output.
   *
   * @param  hash  Known hash value. If the length of the array is greater than the length of the
   *               digest output, anything beyond the digest length is considered salt data that is hashed
   *               <strong>after</strong> the input data.
   * @param  data  Data to hash.
   *
   * @return  True if hashed data equals known hash output, false otherwise.
   */
  protected boolean compareInternal(final byte[] hash, final Object ... data)
  {
    return HashUtil.compareHash(digestSpec.newInstance(), hash, iterations, data);
  }
}
