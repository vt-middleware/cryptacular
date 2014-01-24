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

package org.cryptacular.generator.sp80038a;

import java.math.BigInteger;

import org.cryptacular.util.ByteUtil;
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
  public Object[][] getTestData()
  {
    return new Object[][] {
      new Object[] {1, 8},
      new Object[] {2199023255552L, 16},
    };
  }

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
