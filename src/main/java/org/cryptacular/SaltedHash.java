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

package org.cryptacular;

import org.cryptacular.codec.Encoder;
import org.cryptacular.util.CodecUtil;

/**
 * Container for the output of a salted hash operation that includes both the digest output and salt value.
 *
 * @author Marvin S. Addison
 */
public class SaltedHash
{
  /** Digest output. */
  private final byte[] hash;

  /** Salt value. */
  private final byte[] salt;


  /**
   * Creates a new instance with digest and salt data.
   *
   * @param  hash  Digest output.
   * @param  salt  Salt value used to compute salt.
   */
  public SaltedHash(final byte[] hash, final byte[] salt)
  {
    this.hash = hash;
    this.salt = salt;
  }


  /**
   * Creates a new instance from byte input that contains the concatenation of digest output and salt.
   *
   * @param  hashWithSalt  Concatenation of hash and salt.
   * @param  digestLength  Number of bytes in digest output.
   * @param  toEnd  True if salt is appended to end of hash, false if salt is prepended to hash.
   */
  public SaltedHash(final byte[] hashWithSalt, final int digestLength, final boolean toEnd)
  {
    this.hash = new byte[digestLength];
    this.salt = new byte[hashWithSalt.length - digestLength];
    if (toEnd) {
      System.arraycopy(hashWithSalt, 0, hash, 0, hash.length);
      System.arraycopy(hashWithSalt, hash.length, salt, 0, salt.length);
    } else {
      System.arraycopy(hashWithSalt, 0, salt, 0, salt.length);
      System.arraycopy(hashWithSalt, salt.length, hash, 0, hash.length);
    }
  }


  /**
   * @return  Digest output.
   */
  public byte[] getHash()
  {
    return hash;
  }


  /**
   * @return  Salt value.
   */
  public byte[] getSalt()
  {
    return salt;
  }


  /**
   * Gets an encoded string of the concatenation of digest output and salt.
   *
   * @param  toEnd  True to append salt to end of hash, false to prefix hash with salt.
   * @param  encoder  Encodes concatenated bytes to a string.
   *
   * @return  Salt concatenated to hash encoded as a string.
   */
  public String concatenateSalt(final boolean toEnd, final Encoder encoder)
  {
    return CodecUtil.encode(encoder, concatenateSalt(toEnd));
  }


  /**
   * Gets a byte array containing the concatenation of digest output and salt.
   *
   * @param  toEnd  True to append salt to end of hash, false to prefix hash with salt.
   *
   * @return  Salt concatenated to hash.
   */
  public byte[] concatenateSalt(final boolean toEnd)
  {
    final byte[] output = new byte[hash.length + salt.length];
    if (toEnd) {
      System.arraycopy(hash, 0, output, 0, hash.length);
      System.arraycopy(salt, 0, output, hash.length, salt.length);
    } else {
      System.arraycopy(salt, 0, output, 0, salt.length);
      System.arraycopy(hash, 0, output, salt.length, hash.length);
    }
    return output;
  }
}
