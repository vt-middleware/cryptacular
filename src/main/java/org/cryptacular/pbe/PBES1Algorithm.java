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
package org.cryptacular.pbe;

import org.cryptacular.spec.BufferedBlockCipherSpec;
import org.cryptacular.spec.DigestSpec;

/**
 * Password-based encryption algorithms defined in PKCS#5 for PBES1 scheme.
 *
 * @author  Middleware Services
 * @version  $Revision: 2745 $
 */
public enum PBES1Algorithm {

  /** PBES1 encryption method with MD2 hash and DES CBC cipher. */
  PbeWithMD2AndDES_CBC(
    "1.2.840.113549.1.5.1",
    new BufferedBlockCipherSpec("DES", "CBC", "PKCS5"),
    new DigestSpec("MD2")),

  /** PBES1 encryption method with MD2 hash and RC2 CBC cipher. */
  PbeWithMD2AndRC2_CBC(
    "1.2.840.113549.1.5.4",
    new BufferedBlockCipherSpec("RC2", "CBC", "PKCS5"),
    new DigestSpec("MD2")),

  /** PBES1 encryption method with MD5 hash and DES CBC cipher. */
  PbeWithMD5AndDES_CBC(
    "1.2.840.113549.1.5.3",
    new BufferedBlockCipherSpec("DES", "CBC", "PKCS5"),
    new DigestSpec("MD5")),

  /** PBES1 encryption method with MD5 hash and RC2 CBC cipher. */
  PbeWithMD5AndRC2_CBC(
    "1.2.840.113549.1.5.6",
    new BufferedBlockCipherSpec("RC2", "CBC", "PKCS5"),
    new DigestSpec("MD5")),

  /** PBES1 encryption method with SHA1 hash and DES CBC cipher. */
  PbeWithSHA1AndDES_CBC(
    "1.2.840.113549.1.5.10",
    new BufferedBlockCipherSpec("DES", "CBC", "PKCS5"),
    new DigestSpec("SHA1")),

  /** PBES1 encryption method with SHA1 hash and RC2 CBC cipher. */
  PbeWithSHA1AndRC2_CBC(
    "1.2.840.113549.1.5.11",
    new BufferedBlockCipherSpec("RC2", "CBC", "PKCS5"),
    new DigestSpec("SHA1"));


  /** Algorithm identifier OID. */
  private final String oid;

  /** Cipher algorithm specification. */
  private final BufferedBlockCipherSpec cipherSpec;

  /** Pseudorandom function digest specification. */
  private final DigestSpec digestSpec;


  /**
   * Creates a new instance with given parameters.
   *
   * @param  id  Algorithm OID.
   * @param  cipherSpec Cipher algorithm specification.
   * @param  digestSpec Digest specification used for pseudorandom function.
   */
  PBES1Algorithm(final String id, final BufferedBlockCipherSpec cipherSpec, final DigestSpec digestSpec)
  {
    this.oid = id;
    this.cipherSpec = cipherSpec;
    this.digestSpec = digestSpec;
  }


  /**
   * Gets the PBE algorithm for the given object identifier.
   *
   * @param  oid  PBE algorithm OID.
   *
   * @return  Algorithm whose identifier equals given value.
   *
   * @throws  IllegalArgumentException  If no matching algorithm found.
   */
  public static PBES1Algorithm fromOid(final String oid)
  {
    for (PBES1Algorithm a : PBES1Algorithm.values()) {
      if (a.getOid().equals(oid)) {
        return a;
      }
    }
    throw new IllegalArgumentException("Unknown PBES1Algorithm for OID " + oid);
  }


  /** @return  the oid */
  public String getOid()
  {
    return oid;
  }


  /** @return  Cipher algorithm specification. */
  public BufferedBlockCipherSpec getCipherSpec()
  {
    return cipherSpec;
  }


  /** @return  Digest algorithm. */
  public DigestSpec getDigestSpec()
  {
    return digestSpec;
  }
}
