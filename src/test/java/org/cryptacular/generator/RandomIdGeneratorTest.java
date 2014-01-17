/*
 * Licensed to Virginia Tech under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Virginia Tech licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.cryptacular.generator;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;

/**
 * Unit test for {@link RandomIdGenerator}.
 *
 * @author Marvin S. Addison
 */
public class RandomIdGeneratorTest
{
  @DataProvider(name = "generators")
  public Object[][] getGenerators()
  {
    return new Object[][] {
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
  public void testGenerate(final RandomIdGenerator generator, final Pattern expected) throws Exception
  {
    for (int i = 0; i < 100; i++) {
      final Matcher m = expected.matcher(generator.generate());
      assertTrue(m.matches());
    }
  }
}
