/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import org.cryptacular.util.CodecUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link HOTPGenerator}.
 *
 * @author  Middleware Services
 */
public class HOTPGeneratorTest
{
  @DataProvider(name = "test-data")
  public Object[][] getTestData()
  {
    return
      new Object[][] {
        {"0x3132333435363738393031323334353637383930", 0, 755224},
        {"0x3132333435363738393031323334353637383930", 1, 287082},
        {"0x3132333435363738393031323334353637383930", 2, 359152},
        {"0x3132333435363738393031323334353637383930", 3, 969429},
        {"0x3132333435363738393031323334353637383930", 4, 338314},
        {"0x3132333435363738393031323334353637383930", 5, 254676},
        {"0x3132333435363738393031323334353637383930", 6, 287922},
        {"0x3132333435363738393031323334353637383930", 7, 162583},
        {"0x3132333435363738393031323334353637383930", 8, 399871},
        {"0x3132333435363738393031323334353637383930", 9, 520489},
      };
  }


  @Test(dataProvider = "test-data")
  public void testGenerate(
    final String hexKey,
    final int count,
    final int expected)
    throws Exception
  {
    final HOTPGenerator generator = new HOTPGenerator();
    assertEquals(generator.generate(CodecUtil.hex(hexKey), count), expected);
  }
}
