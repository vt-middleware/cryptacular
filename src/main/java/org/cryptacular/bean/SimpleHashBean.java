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

/**
 * Computes a hash using an instance of {@link Digest} specified by
 * {@link #setDigestSpec(org.cryptacular.spec.Spec)}.
 *
 * @author Marvin S. Addison
 */
public class SimpleHashBean extends AbstractHashBean implements HashBean<byte[]>
{
  /** {@inheritDoc} */
  @Override
  public byte[] hash(final Object ... data)
  {
    return hashInternal(data);
  }


  /**
   * Compares a known hash value with the hash of the given data.
   *
   * @param  hash  Known hash value. If the length of the array is greater than the length of the
   *               digest output, anything beyond the digest length is considered salt data that is hashed
   *               <strong>after</strong> the input data.
   * @param  data  Data to hash.
   *
   * @return  True if the hashed data matches the given hash, false otherwise.
   */
  @Override
  public boolean compare(final byte[] hash, final Object ... data)
  {
    return compareInternal(hash, data);
  }
}
