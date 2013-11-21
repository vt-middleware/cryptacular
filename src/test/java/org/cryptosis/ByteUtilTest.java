package org.cryptosis;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * @author Marvin S. Addison
 */
public class ByteUtilTest
{
  @DataProvider(name = "integers")
  public Object[][] getIntegers()
  {
    return new Object[][] {
      new Object[] { 64 },
      new Object[] { -89 },
      new Object[] { 255 },
      new Object[] { 256 },
      new Object[] { 210983498 },
      new Object[] { -417234198 },
    };
  }

  @DataProvider(name = "longs")
  public Object[][] getLongs()
  {
    return new Object[][] {
      new Object[] { 128 },
      new Object[] { 110374187198L },
      new Object[] { -8987189751341L },
    };
  }

  @Test(dataProvider = "integers")
  public void testIntToBytesAndBack(final int value) throws Exception
  {
    final byte[] bytes = new byte[4];
    ByteUtil.toBytes(value, bytes, 0);
    assertEquals(ByteUtil.toInt(bytes), value);
  }

  @Test(dataProvider = "longs")
  public void testLongToBytesAndBack(final long value) throws Exception
  {
    final byte[] bytes = new byte[8];
    ByteUtil.toBytes(value, bytes, 0);
    assertEquals(ByteUtil.toLong(bytes), value);
  }
}
