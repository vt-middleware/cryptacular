/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.cryptacular.FailListener;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit test for {@link RandomIdGenerator}.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
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
  public void testGenerate(final RandomIdGenerator generator, final Pattern expected)
    throws Exception
  {
    for (int i = 0; i < 100; i++) {
      final Matcher m = expected.matcher(generator.generate());
      assertTrue(m.matches());
    }
  }

  @Test
  public void testConcurrentGeneration()
    throws Exception
  {
    final ExecutorService executor = Executors.newFixedThreadPool(20);
    final RandomIdGenerator generator = new RandomIdGenerator(50);
    final Collection<Callable<String>> tasks = new ArrayList<>();
    for (int i = 0; i < 20; i++) {
      tasks.add(() -> generator.generate());
    }

    final List<Future<String>> results = executor.invokeAll(tasks);
    for (Future<String> result : results) {
      assertNotNull(result.get(1, TimeUnit.SECONDS));
    }
  }
}
