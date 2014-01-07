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

package org.cryptacular.util;

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
