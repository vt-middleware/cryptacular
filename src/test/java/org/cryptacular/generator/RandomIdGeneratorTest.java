/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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
import static org.testng.Assert.assertEquals;
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
  {
    for (int i = 0; i < 100; i++) {
      final Matcher m = expected.matcher(generator.generate());
      assertTrue(m.matches());
    }
  }

  /**
   * Test concurrent random ID generation on a shared instance.
   *
   * @throws Exception on test errors
   */
  @Test
  public void testConcurrentGeneration()
    throws Exception
  {
    final int poolSize = 100;
    final ExecutorService executor = Executors.newFixedThreadPool(poolSize);
    final RandomIdGenerator generator = new RandomIdGenerator(50);
    final Collection<Callable<String>> tasks = new ArrayList<>();
    for (int i = 0; i < poolSize; i++) {
      tasks.add(new Callable<String>() {
        @Override
        public String call() throws Exception
        {
          return generator.generate();
        }
      });
    }
    // Ensure all generated IDs are unique
    final Set<String> identifiers = new HashSet<>(poolSize);
    final List<Future<String>> results = executor.invokeAll(tasks);
    for (Future<String> result : results) {
      final String id = result.get(1, TimeUnit.SECONDS);
      assertNotNull(id);
      identifiers.add(id);
    }
    assertEquals(poolSize, identifiers.size());
  }

  /**
   * Test creating new instances and calling generate on them concurrently.
   *
   * @throws Exception on test errors
   */
  @Test
  public void testConcurrentGeneration2()
      throws Exception
  {
    final int poolSize = 100;
    final ExecutorService executor = Executors.newFixedThreadPool(poolSize);
    final Collection<Callable<String>> tasks = new ArrayList<>();
    for (int i = 0; i < poolSize; i++) {
      tasks.add(new Callable<String>() {
        @Override
        public String call() throws Exception
        {
          return new RandomIdGenerator(50).generate();
        }
      });
    }
    // Ensure all generated IDs are unique
    final Set<String> identifiers = new HashSet<>(poolSize);
    final List<Future<String>> results = executor.invokeAll(tasks);
    for (Future<String> result : results) {
      final String id = result.get(1, TimeUnit.SECONDS);
      assertNotNull(id);
      identifiers.add(id);
    }
    assertEquals(poolSize, identifiers.size());
  }
}
