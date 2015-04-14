/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator.sp80038a;

import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
import org.cryptacular.generator.LimitException;
import org.cryptacular.generator.Nonce;
import org.cryptacular.util.NonceUtil;

/**
 * Nonce generation strategy that produces a random value according to NIST <a href="http://goo.gl/S9z8qF">
 * SP-800-38a</a>, appendix C, method 2 (random number generator), suitable for use with any block cipher mode described
 * in that standard except OFB.
 *
 * <p>Instances of this class are thread safe.</p>
 *
 * @author  Middleware Services
 */
public class RBGNonce implements Nonce
{

  /** Length of generated nonces. */
  private final int length;

  /** Random bit generator. */
  private final SP80090DRBG rbg;


  /** Creates a new instance that produces 16-bytes (128-bits) of random data. */
  public RBGNonce()
  {
    this(16);
  }


  /**
   * Creates a new instance that produces length bytes of random data.
   *
   * @param  length  Number of bytes in generated nonce values.
   */
  public RBGNonce(final int length)
  {
    if (length < 1) {
      throw new IllegalArgumentException("Length must be positive");
    }
    this.length = length;
    this.rbg = NonceUtil.newRBG(length);
  }


  @Override
  public byte[] generate()
    throws LimitException
  {
    final byte[] random = new byte[length];
    synchronized (rbg) {
      rbg.generate(random, null, false);
    }
    return random;
  }


  @Override
  public int getLength()
  {
    return length;
  }
}
