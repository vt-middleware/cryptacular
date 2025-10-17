/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.cryptacular.CryptUtil;

/**
 * OTP generator component that implements the HOTP scheme described in <a href="https://tools.ietf.org/html/rfc4226">
 * RFC 4226</a>.
 *
 * @author  Middleware Services
 */
public class HOTPGenerator extends AbstractOTPGenerator
{

  /**
   * Creates a new HOTP generator.
   */
  public HOTPGenerator()
  {
    this(DEFAULT_NUMBER_OF_DIGITS);
  }


  /**
   * Creates a new HOTP generator.
   *
   * @param  numberOfDigits  Number of digits in generated OTP. MUST be in the range 6 - 9.
   */
  public HOTPGenerator(final int numberOfDigits)
  {
    super(numberOfDigits);
  }


  /**
   * Generates the OTP given a per-user key and invocation count.
   *
   * @param  key  Per-user key.
   * @param  count  Counter moving factor.
   *
   * @return  Integer OTP.
   */
  public int generate(final byte[] key, final long count)
  {
    return generateInternal(CryptUtil.assertNotNullArg(key, "Key cannot be null"), count);
  }


  @Override
  protected Digest getDigest()
  {
    return new SHA1Digest();
  }
}
