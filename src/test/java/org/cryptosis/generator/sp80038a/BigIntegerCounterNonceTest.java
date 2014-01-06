package org.cryptosis.generator.sp80038a;

import java.math.BigInteger;

import org.cryptosis.util.ByteUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link BigIntegerCounterNonce}.
 *
 * @author Marvin S. Addison
 */
public class BigIntegerCounterNonceTest
{
  @DataProvider(name = "test-data")
  public Object[][] getTestData() {
    return new Object[][] {
      new Object[] { 1, 8 },
      new Object[] { 2199023255552L, 16 },
    };
  };

  @Test(dataProvider = "test-data")
  public void testGenerate(final long start, final int expectedLength) throws Exception
  {
    final BigIntegerCounterNonce nonce = new BigIntegerCounterNonce(
      new BigInteger(ByteUtil.toBytes(start)), expectedLength);
    final byte[] value = nonce.generate();
    assertEquals(value.length, expectedLength);
    assertEquals(new BigInteger(value), new BigInteger(ByteUtil.toBytes(start + 1)));
  }
}
