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

package org.cryptacular.bean;

import org.cryptacular.spec.CodecSpec;
import org.cryptacular.spec.DigestSpec;
import org.cryptacular.util.CodecUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link EncodingHashBean}.
 *
 * @author Marvin S. Addison
 */
public class EncodingHashBeanTest
{
  @DataProvider(name = "test-data")
  public Object[][] getTestData()
  {
    return new Object[][] {
      {
        new DigestSpec("SHA1"),
        CodecSpec.BASE64,
        new Object[] {
          CodecUtil.b64("7FHsteHnm6XQsJT1TTKbxw=="),
          CodecUtil.b64("ehp6PCnojSegFpRvStqQ9A=="),
        },
        1,
        "Oadnuuj7QsRPUuMBiu+dmlT6qzU=",
      },
      {
        new DigestSpec("SHA256"),
        CodecSpec.HEX,
        new Object[] {
          CodecUtil.b64("7FHsteHnm6XQsJT1TTKbxw=="),
          CodecUtil.b64("ehp6PCnojSegFpRvStqQ9A=="),
        },
        3,
        "3a1edec6aef6d1736bec63130755690c07f04d7e7139d8fd685cc2d989961b79",
      },
    };
  }

  @Test(dataProvider = "test-data")
  public void testHash(
    final DigestSpec digest,
    final CodecSpec codec,
    final Object[] input,
    final int iterations,
    final String expected)
    throws Exception
  {
    final EncodingHashBean bean = new EncodingHashBean();
    bean.setDigestSpec(digest);
    bean.setCodecSpec(codec);
    bean.setIterations(iterations);
    assertEquals(bean.hash(input), expected);
  }
}
