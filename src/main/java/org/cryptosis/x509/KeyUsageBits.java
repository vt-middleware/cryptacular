/*
  $Id: KeyUsageBits.java 2745 2013-06-25 21:16:10Z dfisher $

  Copyright (C) 2003-2013 Virginia Tech.
  All rights reserved.

  SEE LICENSE FOR MORE INFORMATION

  Author:  Middleware Services
  Email:   middleware@vt.edu
  Version: $Revision: 2745 $
  Updated: $Date: 2013-06-25 17:16:10 -0400 (Tue, 25 Jun 2013) $
*/
package org.cryptosis.x509;

import java.util.BitSet;
import java.util.List;

import org.bouncycastle.asn1.x509.KeyUsage;

/**
 * Representation of the bit meanings in the <code>KeyUsage</code> BIT STRING
 * type defined in section 4.2.1.3 of RFC 2459.
 *
 * @author  Middleware Services
 * @version  $Revision: 2745 $
 */
public enum KeyUsageBits
{

  /** digitalSignature bit. */
  DigitalSignature(7),

  /** nonRepudiation bit. */
  NonRepudiation(6),

  /** keyEncipherment bit. */
  KeyEncipherment(5),

  /** dataEncipherment bit. */
  DataEncipherment(4),

  /** keyAgreement bit. */
  KeyAgreement(3),

  /** keyCertSign bit. */
  KeyCertSign(2),

  /** cRLSign bit. */
  CRLSign(1),

  /** encipherOnly bit. */
  EncipherOnly(0),

  /** decipherOnly bit. */
  DecipherOnly(15);


  /** Bit mask offset. */
  private final int offset;


  /**
   * Creates a bit flag with the given bit mask offset.
   *
   * @param  offset  Bit mask offset.
   */
  KeyUsageBits(final int offset)
  {
    this.offset = offset;
  }


  /** @return  Bit mask value. */
  public int getMask()
  {
    return 1 << offset;
  }


  /**
   * Determines whether this key usage bit is set in the given key usage value.
   *
   * @param  keyUsage  BC key usage object.
   *
   * @return  True if bit is set, false otherwise.
   */
  public boolean isSet(final KeyUsage keyUsage)
  {
    return isSet(keyUsage.getBytes());
  }


  /**
   * Determines whether this key usage bit is set in the given key usage bit string.
   *
   * @param  bitString  Key usage bit string as a byte array.
   *
   * @return  True if bit is set, false otherwise.
   */
  public boolean isSet(final byte[] bitString)
  {
    return BitSet.valueOf(bitString).get(offset);
  }


  /**
   * Determines whether this key usage bit is set in the given key usage bit string.
   *
   * @param  bitString  Key usage bit string as a big endian integer.
   *
   * @return  True if bit is set, false otherwise.
   */
  public boolean isSet(final int bitString)
  {
    return (bitString & getMask()) >> offset == 1;
  }


  /**
   * Computes the key usage value from one or more key usage bits.
   *
   * @param  bits  One ore more key usage bits.
   *
   * @return  Key usage bit string as an integer.
   */
  public static int usage(final KeyUsageBits ... bits)
  {
    int usage = 0;
    for (KeyUsageBits bit : bits) {
      usage |= bit.getMask();
    }
    return usage;
  }
}
