/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import org.bouncycastle.crypto.Digest;
import org.cryptacular.spec.DigestSpec;
import org.cryptacular.spec.Spec;

/**
 * OTP generator component that implements the TOTP scheme described in <a href="https://tools.ietf.org/html/rfc6238">
 * RFC 6238</a>.
 *
 * @author  Middleware Services
 */
public class TOTPGenerator extends AbstractOTPGenerator
{

  /** Digest algorithm specification. */
  private Spec<Digest> digestSpecification = new DigestSpec("SHA1");

  /**
   * Current system time in seconds since the start of the epoch, 1970-01-01T00:00:00.
   * This value is used if and only if it is a non-negative value; otherwise the current system time is used.
   */
  private long currentTime = -1;

  /** Reference start time, T0. Default 0, i.e. 1970-01-01T00:00:00. */
  private int startTime;

  /** Time step in seconds, X. Default is 30 seconds. */
  private int timeStep = 30;


  /** @return  Digest algorithm used with the HMAC function. */
  public Spec<Digest> getDigestSpecification()
  {
    return digestSpecification;
  }


  /**
   * Sets the digest algorithm used with the HMAC function.
   *
   * @param  specification  SHA-1, SHA-256, or SHA-512 digest specification.
   */
  public void setDigestSpecification(final Spec<Digest> specification)
  {
    if ("SHA1".equalsIgnoreCase(specification.getAlgorithm()) ||
        "SHA-1".equalsIgnoreCase(specification.getAlgorithm()) ||
        "SHA256".equalsIgnoreCase(specification.getAlgorithm()) ||
        "SHA-256".equalsIgnoreCase(specification.getAlgorithm()) ||
        "SHA512".equalsIgnoreCase(specification.getAlgorithm()) ||
        "SHA-512".equalsIgnoreCase(specification.getAlgorithm())) {
      this.digestSpecification = specification;
      return;
    }
    throw new IllegalArgumentException("Unsupported digest algorithm " + specification);
  }


  /** @return  Reference start time. */
  public int getStartTime()
  {
    return startTime;
  }


  /**
   * Sets the reference start time, T0. Default 0, i.e. 1970-01-01T00:00:00.
   *
   * @param  seconds  Start time in seconds.
   */
  public void setStartTime(final int seconds)
  {
    this.startTime = seconds;
  }


  /** @return  Time step in seconds. */
  public int getTimeStep()
  {
    return timeStep;
  }


  /**
   * Sets the time step, X.
   *
   * @param  seconds  Time step in seconds. Default is 30. This value determines the validity window of generated OTP
   *                  values.
   */
  public void setTimeStep(final int seconds)
  {
    this.timeStep = seconds;
  }


  /**
   * Generates the OTP given a per-user key.
   *
   * @param  key  Per-user key.
   *
   * @return  Integer OTP.
   */
  public int generate(final byte[] key)
  {
    final long t = (currentTime() - startTime) / timeStep;
    return generateInternal(key, t);
  }


  @Override
  protected Digest getDigest()
  {
    return digestSpecification.newInstance();
  }


  /**
   * Sets the current time (supports testing). This value is used if and only if it is a non-negative value; otherwise
   * the current system time is used.
   *
   * @param epochSeconds Seconds since the start of the epoch, 1970-01-01T00:00:00.
   */
  protected void setCurrentTime(final long epochSeconds)
  {
    currentTime = epochSeconds;
  }


  /**
   * @return Current system time in seconds since the start of epoch, 1970-01-01T00:00:00.
   */
  protected long currentTime()
  {
    if (currentTime >= 0) {
      return currentTime;
    }
    return System.currentTimeMillis() / 1000;
  }
}
