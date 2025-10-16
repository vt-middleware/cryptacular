/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.bouncycastle.crypto.Digest;
import org.cryptacular.CryptUtil;
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

  /** Default start time. */
  private static final Instant DEFAULT_START_TIME = Instant.EPOCH;

  /** Default time step. */
  private static final Duration DEFAULT_TIME_STEP = Duration.ofSeconds(30);

  /** Digest algorithm specification. */
  private final Spec<Digest> digestSpecification;

  /** Reference start time, T0. Default is 1970-01-01T00:00:00. */
  private final Instant startTime;

  /** Time step duration, X. Default is 30 seconds. */
  private final Duration timeStep;

  /**
   * Current system time. This value is used if and only if it is a non-null value;
   * otherwise the current system time is used.
   */
  private Instant currentTime;


  /**
   * Creates a new TOTP generator that uses a SHA-1 digest.
   */
  public TOTPGenerator()
  {
    this(new DigestSpec("SHA1"), DEFAULT_NUMBER_OF_DIGITS, DEFAULT_START_TIME, DEFAULT_TIME_STEP);
  }


  /**
   * Creates a new TOTP generator that uses a SHA-1 digest.
   *
   * @param  numberOfDigits  Number of digits in generated OTP. MUST be in the range 6 - 9.
   */
  public TOTPGenerator(final int numberOfDigits)
  {
    this(new DigestSpec("SHA1"), numberOfDigits, DEFAULT_START_TIME, DEFAULT_TIME_STEP);
  }


  /**
   * Creates a new TOTP generator.
   *
   * @param  specification  SHA-1, SHA-256, or SHA-512 digest specification.
   */
  public TOTPGenerator(final Spec<Digest> specification)
  {
    this(specification, DEFAULT_NUMBER_OF_DIGITS, DEFAULT_START_TIME, DEFAULT_TIME_STEP);
  }


  /**
   * Creates a new TOTP generator.
   *
   * @param  specification  SHA-1, SHA-256, or SHA-512 digest specification.
   * @param  numberOfDigits  Number of digits in generated OTP. MUST be in the range 6 - 9.
   */
  public TOTPGenerator(final Spec<Digest> specification, final int numberOfDigits)
  {
    this(specification, numberOfDigits, DEFAULT_START_TIME, DEFAULT_TIME_STEP);
  }


  /**
   * Creates a new TOTP generator.
   *
   * @param  specification  SHA-1, SHA-256, or SHA-512 digest specification.
   * @param  numberOfDigits  Number of digits in generated OTP. MUST be in the range 6 - 9. Default is 6.
   * @param  startTime  Start time instant. Input is truncated to seconds.
   */
  public TOTPGenerator(
    final Spec<Digest> specification, final int numberOfDigits, final Instant startTime)
  {
    this(specification, numberOfDigits, startTime, DEFAULT_TIME_STEP);
  }


  /**
   * Creates a new TOTP generator.
   *
   * @param  specification  SHA-1, SHA-256, or SHA-512 digest specification.
   * @param  numberOfDigits  Number of digits in generated OTP. MUST be in the range 6 - 9. Default is 6.
   * @param  timeStep  Time step duration. Default is 30s. This value determines the validity window of generated OTP
   *                   values.
   */
  public TOTPGenerator(
    final Spec<Digest> specification, final int numberOfDigits, final Duration timeStep)
  {
    this(specification, numberOfDigits, DEFAULT_START_TIME, timeStep);
  }


  /**
   * Creates a new TOTP generator.
   *
   * @param  specification  SHA-1, SHA-256, or SHA-512 digest specification.
   * @param  numberOfDigits  Number of digits in generated OTP. MUST be in the range 6 - 9. Default is 6.
   * @param  startTime  Start time instant. Input is truncated to seconds.
   * @param  timeStep  Time step duration. Default is 30s. This value determines the validity window of generated OTP
   *                   values.
   */
  public TOTPGenerator(
    final Spec<Digest> specification, final int numberOfDigits, final Instant startTime, final Duration timeStep)
  {
    super(numberOfDigits);
    CryptUtil.assertNotNullArg(specification, "Specification cannot be null");
    CryptUtil.assertNotNullArg(startTime, "Start time cannot be null");
    CryptUtil.assertNotNullArg(timeStep, "Time step cannot be null");
    if ("SHA1".equalsIgnoreCase(specification.getAlgorithm()) ||
        "SHA-1".equalsIgnoreCase(specification.getAlgorithm()) ||
        "SHA256".equalsIgnoreCase(specification.getAlgorithm()) ||
        "SHA-256".equalsIgnoreCase(specification.getAlgorithm()) ||
        "SHA512".equalsIgnoreCase(specification.getAlgorithm()) ||
        "SHA-512".equalsIgnoreCase(specification.getAlgorithm()))
    {
      this.digestSpecification = specification;
    } else {
      throw new IllegalArgumentException("Unsupported digest algorithm " + specification);
    }
    this.startTime = startTime.truncatedTo(ChronoUnit.SECONDS);
    this.timeStep = timeStep;
  }


  /** @return  Digest algorithm used with the HMAC function. */
  public Spec<Digest> getDigestSpecification()
  {
    return digestSpecification;
  }


  /** @return  Reference start time. */
  public Instant getStartTime()
  {
    return startTime;
  }


  /** @return  Time step in seconds. */
  public Duration getTimeStep()
  {
    return timeStep;
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
    CryptUtil.assertNotNullArg(key, "Key cannot be null");
    final long t = (currentTime().toEpochMilli() - startTime.toEpochMilli()) / timeStep.getSeconds();
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
   * @param time to override the current time with
   */
  void setCurrentTime(final Instant time)
  {
    currentTime = time;
  }


  /**
   * @return Current system time in seconds since the start of epoch, 1970-01-01T00:00:00.
   */
  Instant currentTime()
  {
    if (currentTime != null) {
      return currentTime;
    }
    return Instant.now().truncatedTo(ChronoUnit.SECONDS);
  }
}
