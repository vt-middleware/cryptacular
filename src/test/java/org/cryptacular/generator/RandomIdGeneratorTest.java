/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;

/**
 * Unit test for {@link RandomIdGenerator}.
 *
 * @author  Middleware Services
 */
public class RandomIdGeneratorTest
{
  @DataProvider(name = "generators")
  public Object[][] getGenerators()
  {
    return
      new Object[][] {
        {
          new RandomIdGenerator(10),
          Pattern.compile("\\w{10}"),
        },
        {
          new RandomIdGenerator(128),
          Pattern.compile("\\w{128}"),
        },
        {
          new RandomIdGenerator(20, "abcdefg"),
          Pattern.compile("[abcdefg]{20}"),
        },
      };
  }

  @Test(dataProvider = "generators")
  public void testGenerate(
    final RandomIdGenerator generator,
    final Pattern expected)
    throws Exception
  {
    for (int i = 0; i < 100; i++) {
      final Matcher m = expected.matcher(generator.generate());
      assertTrue(m.matches());
    }
  }
}
