/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.cryptacular.generator.sp80038a.RBGNonce;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link CiphertextHeader}.
 *
 * @author Middleware Services
 */
public class CiphertextHeaderTest
{
  /** Test HMAC key. */
  private final SecretKey key = new SecretKeySpec(new RBGNonce().generate(), "AES");

  @Test(
      expectedExceptions = IllegalArgumentException.class,
      expectedExceptionsMessageRegExp = "Nonce exceeds size limit in bytes.*")
  public void testNonceLimitConstructor()
  {
    new CiphertextHeader(new byte[256], "key2");
  }

  @Test
  public void testEncodeDecodeSuccess()
  {
    final byte[] nonce = new byte[255];
    Arrays.fill(nonce, (byte) 7);
    final CiphertextHeader expected = new CiphertextHeader(nonce, "aleph", this::getKey);
    final byte[] encoded = expected.encode();
    assertThat(encoded.length).isEqualTo(expected.getLength());
    final CiphertextHeader actual = CiphertextHeader.decode(encoded, this::getKey);
    assertThat(actual.getNonce()).isEqualTo(expected.getNonce());
    assertThat(actual.getKeyName()).isEqualTo(expected.getKeyName());
    assertThat(actual.getLength()).isEqualTo(expected.getLength());
  }

  @Test(
      expectedExceptions = EncodingException.class,
      expectedExceptionsMessageRegExp = "Ciphertext header HMAC verification failed")
  public void testEncodeDecodeFailBadHMAC()
  {
    final byte[] nonce = new byte[16];
    Arrays.fill(nonce, (byte) 3);
    final CiphertextHeader expected = new CiphertextHeader(nonce, "aleph");
    // Tamper with computed HMAC
    final byte[] encoded = expected.encode(key);
    final int index = encoded.length - 3;
    final byte b = encoded[index];
    encoded[index] = (byte) (b + 1);
    CiphertextHeader.decode(encoded, this::getKey);
  }

  private SecretKey getKey(final String alias)
  {
    if ("aleph".equals(alias)) {
      return key;
    }
    return null;
  }
}
