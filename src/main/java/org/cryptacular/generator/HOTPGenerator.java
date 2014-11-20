/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;

/**
 * OTP generator component that implements the HOTP scheme described in <a
 * href="https://tools.ietf.org/html/rfc4226">RFC 4226</a>.
 *
 * @author  Middleware Services
 */
public class HOTPGenerator extends AbstractOTPGenerator
{

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
    return generateInternal(key, count);
  }


  /** {@inheritDoc} */
  @Override
  protected Digest getDigest()
  {
    return new SHA1Digest();
  }
}
