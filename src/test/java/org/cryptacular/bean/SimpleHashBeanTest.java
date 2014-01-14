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

import org.cryptacular.spec.DigestSpec;
import org.cryptacular.util.CodecUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link SimpleHashBean}.
 *
 * @author Marvin S. Addison
 */
public class SimpleHashBeanTest
{
  @DataProvider(name = "test-data")
  public Object[][] getTestData()
  {
    return new Object[][] {
      {
        new DigestSpec("SHA1"),
        new Object[] {
          CodecUtil.b64("7FHsteHnm6XQsJT1TTKbxw=="),
          CodecUtil.b64("ehp6PCnojSegFpRvStqQ9A=="),
        },
        1,
        "Oadnuuj7QsRPUuMBiu+dmlT6qzU=",
      },
      {
        new DigestSpec("SHA256"),
        new Object[] {
          CodecUtil.b64("7FHsteHnm6XQsJT1TTKbxw=="),
          CodecUtil.b64("ehp6PCnojSegFpRvStqQ9A=="),
        },
        3,
        "Oh7exq720XNr7GMTB1VpDAfwTX5xOdj9aFzC2YmWG3k=",
      },
    };
  }

  @Test(dataProvider = "test-data")
  public void testHash(
    final DigestSpec digest, final Object[] input, final int iterations, final String expectedBase64)
    throws Exception
  {
    final SimpleHashBean bean = new SimpleHashBean();
    bean.setDigestSpec(digest);
    bean.setIterations(iterations);
    assertEquals(CodecUtil.b64(bean.hash(input)), expectedBase64);
  }
}
