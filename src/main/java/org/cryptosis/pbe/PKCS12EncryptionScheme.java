/*
  $Id: PKCS12EncryptionScheme.java 2744 2013-06-25 20:20:29Z dfisher $

  Copyright (C) 2003-2013 Virginia Tech.
  All rights reserved.

  SEE LICENSE FOR MORE INFORMATION

  Author:  Middleware Services
  Email:   middleware@vt.edu
  Version: $Revision: 2744 $
  Updated: $Date: 2013-06-25 16:20:29 -0400 (Tue, 25 Jun 2013) $
*/
package org.cryptosis.pbe;

import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;

/**
 * Implements the password-based encryption scheme in section B of PKCS#12.
 *
 * @author  Middleware Services
 * @version  $Revision: 2744 $
 */
public class PKCS12EncryptionScheme extends AbstractEncryptionScheme
{

  /**
   * Creates a new instance with the given parameters.
   *
   * @param  params  PKCS12 PBE parameters.
   * @param  password  Password used to derive key.
   */
  public PKCS12EncryptionScheme(final PKCS12PBEParams params, final char[] password)
  {
    //TODO: implement
  }
}
