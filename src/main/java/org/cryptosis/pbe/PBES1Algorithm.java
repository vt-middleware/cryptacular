/*
  $Id: PBES1Algorithm.java 2745 2013-06-25 21:16:10Z dfisher $

  Copyright (C) 2003-2013 Virginia Tech.
  All rights reserved.

  SEE LICENSE FOR MORE INFORMATION

  Author:  Middleware Services
  Email:   middleware@vt.edu
  Version: $Revision: 2745 $
  Updated: $Date: 2013-06-25 17:16:10 -0400 (Tue, 25 Jun 2013) $
*/
package org.cryptosis.pbe;

import org.cryptosis.BlockCipherSpec;
import org.cryptosis.DigestSpec;

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
    new BlockCipherSpec("DES", "CBC", "PKCS5"),
    new DigestSpec("MD2")),

  /** PBES1 encryption method with MD2 hash and RC2 CBC cipher. */
  PbeWithMD2AndRC2_CBC(
    "1.2.840.113549.1.5.4",
    new BlockCipherSpec("RC2", "CBC", "PKCS5"),
    new DigestSpec("MD2")),

  /** PBES1 encryption method with MD5 hash and DES CBC cipher. */
  PbeWithMD5AndDES_CBC(
    "1.2.840.113549.1.5.3",
    new BlockCipherSpec("DES", "CBC", "PKCS5"),
    new DigestSpec("MD5")),

  /** PBES1 encryption method with MD5 hash and RC2 CBC cipher. */
  PbeWithMD5AndRC2_CBC(
    "1.2.840.113549.1.5.6",
    new BlockCipherSpec("RC2", "CBC", "PKCS5"),
    new DigestSpec("MD5")),

  /** PBES1 encryption method with SHA1 hash and DES CBC cipher. */
  PbeWithSHA1AndDES_CBC(
    "1.2.840.113549.1.5.10",
    new BlockCipherSpec("DES", "CBC", "PKCS5"),
    new DigestSpec("SHA1")),

  /** PBES1 encryption method with SHA1 hash and RC2 CBC cipher. */
  PbeWithSHA1AndRC2_CBC(
    "1.2.840.113549.1.5.11",
    new BlockCipherSpec("RC2", "CBC", "PKCS5"),
    new DigestSpec("SHA1"));


  /** Algorithm identifier OID. */
  private final String oid;

  /** Cipher algorithm specification. */
  private final BlockCipherSpec cipherSpec;

  /** Pseudorandom function digest specification. */
  private final DigestSpec digestSpec;


  /**
   * Creates a new instance with given parameters.
   *
   * @param  id  Algorithm OID.
   * @param  cipherSpec Cipher algorithm specification.
   * @param  digestSpec Digest specification used for pseudorandom function.
   */
  PBES1Algorithm(final String id, final BlockCipherSpec cipherSpec, final DigestSpec digestSpec)
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
  public BlockCipherSpec getCipherSpec()
  {
    return cipherSpec;
  }


  /** @return  Digest algorithm. */
  public DigestSpec getDigestSpec()
  {
    return digestSpec;
  }
}
