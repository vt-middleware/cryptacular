/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

import java.util.Arrays;
import org.cryptacular.util.CodecUtil;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Unit test for {@link V1CiphertextHeader}.
 *
 * @author Middleware Services
 */
public class V1CiphertextHeaderTest
{

  @Test(
      expectedExceptions = IllegalArgumentException.class,
      expectedExceptionsMessageRegExp = "Nonce exceeds size limit in bytes.*")
  public void testNonceLimitConstructor()
  {
    new V1CiphertextHeader(new byte[256], "key2");
  }

  @Test
  public void testEncodeDecodeSuccess()
  {
    final byte[] nonce = new byte[255];
    Arrays.fill(nonce, (byte) 7);
    final V1CiphertextHeader expected = new V1CiphertextHeader(nonce, "aleph");
    final byte[] encoded = expected.encode();
    assertEquals(expected.getLength(), encoded.length);
    final CiphertextHeader actual = CiphertextHeaderFactory.decode(encoded, null);
    assertTrue(actual instanceof V1CiphertextHeader);
    assertEquals(expected.getNonce(), actual.getNonce());
    assertEquals(expected.getKeyName(), actual.getKeyName());
    assertEquals(expected.getLength(), actual.getLength());
  }

  @Test(
    expectedExceptions = EncodingException.class,
    expectedExceptionsMessageRegExp = "Bad ciphertext header: maximum nonce length exceeded")
  public void testDecodeFailNonceLengthExceeded()
  {
    // https://github.com/vt-middleware/cryptacular/issues/52
    CiphertextHeaderFactory.decode(CodecUtil.hex("000000347ffffffd"), null);
  }

  @Test(
      expectedExceptions = EncodingException.class,
      expectedExceptionsMessageRegExp = "Bad ciphertext header: maximum key length exceeded")
  public void testDecodeFailKeyLengthExceeded()
  {
    CiphertextHeaderFactory.decode(CodecUtil.hex("000000F300000004DEADBEEF00FFFFFF"), null);
  }
}
