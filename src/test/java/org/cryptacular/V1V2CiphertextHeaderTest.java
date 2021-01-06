/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.cryptacular.generator.sp80038a.RBGNonce;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link V2CiphertextHeader}.
 *
 * @author Middleware Services
 */
public class V1V2CiphertextHeaderTest
{
  /** Test HMAC key. */
  private final SecretKey key = new SecretKeySpec(new RBGNonce().generate(), "AES");

  @Test(
      expectedExceptions = IllegalArgumentException.class,
      expectedExceptionsMessageRegExp = "Nonce exceeds size limit in bytes.*")
  public void testNonceLimitConstructor()
  {
    new V2CiphertextHeader(new byte[256], "key2");
  }

  @Test
  public void testEncodeDecodeSuccess()
  {
    final byte[] nonce = new byte[255];
    Arrays.fill(nonce, (byte) 7);
    final V2CiphertextHeader expected = new V2CiphertextHeader(nonce, "aleph");
    expected.setKeyLookup(this::getKey);
    final byte[] encoded = expected.encode();
    assertEquals(expected.getLength(), encoded.length);
    final CiphertextHeader actual = CiphertextHeaderFactory.decode(encoded, this::getKey);
    assertEquals(expected.getNonce(), actual.getNonce());
    assertEquals(expected.getKeyName(), actual.getKeyName());
    assertEquals(expected.getLength(), actual.getLength());
  }

  @Test(
      expectedExceptions = EncodingException.class,
      expectedExceptionsMessageRegExp = "Ciphertext header HMAC verification failed")
  public void testEncodeDecodeFailBadHMAC()
  {
    final byte[] nonce = new byte[16];
    Arrays.fill(nonce, (byte) 3);
    final V2CiphertextHeader expected = new V2CiphertextHeader(nonce, "aleph");
    // Tamper with computed HMAC
    final byte[] encoded = expected.encode(key);
    final int index = encoded.length - 3;
    final byte b = encoded[index];
    encoded[index] = (byte) (b + 1);
    CiphertextHeaderFactory.decode(encoded, this::getKey);
  }

  private SecretKey getKey(final String alias)
  {
    if ("aleph".equals(alias)) {
      return key;
    }
    return null;
  }
}
