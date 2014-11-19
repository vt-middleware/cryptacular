/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.cryptacular.util.ByteUtil;

/**
 * Abstract base class for <a href="https://tools.ietf.org/html/rfc4226">
 * HOTP</a> and <a href="https://tools.ietf.org/html/rfc6238">TOTP</a> OTP
 * generation schemes.
 *
 * @author  Middleware Services
 */
public abstract class AbstractOTPGenerator
{

  /** Array of modulus values indexed per number of digits in OTP output. */
  private static final int[] MODULUS = new int[] {
    1,
    10,
    100,
    1000,
    10000,
    100000,
    1000000,
    10000000,
    100000000,
    1000000000,
  };

  /** Number of digits in generated OTP. */
  private int numberOfDigits = 6;


  /** @return  Number of digits in generated OTP. */
  public int getNumberOfDigits()
  {
    return numberOfDigits;
  }


  /**
   * Sets the numbers in the generated OTP.
   *
   * @param  digits  Number of digits in generated OTP. MUST be in the range 6 -
   *                 9. Default is 6.
   */
  public void setNumberOfDigits(final int digits)
  {
    if (digits < 6 || digits > 9) {
      throw new IllegalArgumentException(
        "Number of generated digits must be in range 6-9.");
    }
    this.numberOfDigits = digits;
  }


  /**
   * Internal OTP generation method.
   *
   * @param  key  Per-user key.
   * @param  count  Counter moving factor.
   *
   * @return  Integer OTP.
   */
  protected int generateInternal(final byte[] key, final long count)
  {
    final HMac hmac = new HMac(getDigest());
    final byte[] output = new byte[hmac.getMacSize()];
    hmac.init(new KeyParameter(key));
    hmac.update(ByteUtil.toBytes(count), 0, 8);
    hmac.doFinal(output, 0);
    return truncate(output) % MODULUS[numberOfDigits];
  }


  /** @return  Digest algorithm used for HMAC operation. */
  protected abstract Digest getDigest();


  /**
   * Truncates HMAC output onto an unsigned (i.e. 31-bit) integer.
   *
   * @param  hmac  HMAC output.
   *
   * @return  Truncated output.
   */
  private int truncate(final byte[] hmac)
  {
    final int offset = hmac[19] & 0xf;
    return
      (hmac[offset] & 0x7f) << 24 |
      (hmac[offset + 1] & 0xff) << 16 |
      (hmac[offset + 2] & 0xff) << 8 |
      (hmac[offset + 3] & 0xff);
  }

}
