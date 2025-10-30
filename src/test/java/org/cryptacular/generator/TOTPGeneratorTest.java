/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.cryptacular.FailListener;
import org.cryptacular.spec.DigestSpec;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link HOTPGenerator}.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class TOTPGeneratorTest
{
  /** Test vectors from RFC 6238, appendix B. */
  @DataProvider(name = "test-data-rfc6238")
  public Object[][] getTestDataRfc6238()
  {
    // Key size is equal to hash length for test vectors in RFC-6238
    // (via careful review of the main method in the reference implementation under Appendix A)
    final String sha1Key = "12345678901234567890";
    final String sha256Key = "12345678901234567890123456789012";
    final String sha512Key = "1234567890123456789012345678901234567890123456789012345678901234";
    return
      new Object[][] {
        {new DigestSpec("SHA1"), sha1Key, Instant.ofEpochSecond(59), 8, 94287082},
        {new DigestSpec("SHA256"), sha256Key, Instant.ofEpochSecond(59), 8, 46119246},
        {new DigestSpec("SHA512"), sha512Key, Instant.ofEpochSecond(59), 8, 90693936},
        {new DigestSpec("SHA1"), sha1Key, Instant.ofEpochSecond(1111111109), 8, 7081804},
        {new DigestSpec("SHA256"), sha256Key, Instant.ofEpochSecond(1111111109), 8, 68084774},
        {new DigestSpec("SHA512"), sha512Key, Instant.ofEpochSecond(1111111109), 8, 25091201},
        {new DigestSpec("SHA1"), sha1Key, Instant.ofEpochSecond(1111111111), 8, 14050471},
        {new DigestSpec("SHA256"), sha256Key, Instant.ofEpochSecond(1111111111), 8, 67062674},
        {new DigestSpec("SHA512"), sha512Key, Instant.ofEpochSecond(1111111111), 8, 99943326},
        {new DigestSpec("SHA1"), sha1Key, Instant.ofEpochSecond(1234567890), 8, 89005924},
        {new DigestSpec("SHA256"), sha256Key, Instant.ofEpochSecond(1234567890), 8, 91819424},
        {new DigestSpec("SHA512"), sha512Key, Instant.ofEpochSecond(1234567890), 8, 93441116},
        {new DigestSpec("SHA1"), sha1Key, Instant.ofEpochSecond(2000000000), 8, 69279037},
        {new DigestSpec("SHA256"), sha256Key, Instant.ofEpochSecond(2000000000), 8, 90698825},
        {new DigestSpec("SHA512"), sha512Key, Instant.ofEpochSecond(2000000000), 8, 38618901},
        {new DigestSpec("SHA1"), sha1Key, Instant.ofEpochSecond(20000000000L), 8, 65353130},
        {new DigestSpec("SHA256"), sha256Key, Instant.ofEpochSecond(20000000000L), 8, 77737706},
        {new DigestSpec("SHA512"), sha512Key, Instant.ofEpochSecond(20000000000L), 8, 47863826},
      };
  }


  @Test(dataProvider = "test-data-rfc6238")
  public void testGenerate(
    final DigestSpec digestSpec,
    final String asciiKey,
    final Instant currentTime,
    final int otpSize,
    final int expected)
  {
    final TOTPGenerator generator = new TOTPGenerator(digestSpec, otpSize);
    generator.setCurrentTime(currentTime);
    assertThat(generator.generate(asciiKey.getBytes(StandardCharsets.US_ASCII))).isEqualTo(expected);
  }

  /** Ensure the system time is used by default. */
  @Test
  public void testTimeBehavior() throws Exception
  {
    final TOTPGenerator generator = new TOTPGenerator();
    final Instant t1 = generator.currentTime();
    Thread.sleep(1001);
    final Instant t2 = generator.currentTime();
    assertThat(t2.isAfter(t1)).isTrue();
  }
}
