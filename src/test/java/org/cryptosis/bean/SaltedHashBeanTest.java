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

package org.cryptosis.bean;

import org.cryptosis.generator.LimitException;
import org.cryptosis.generator.Nonce;
import org.cryptosis.spec.CodecSpec;
import org.cryptosis.spec.DigestSpec;
import org.cryptosis.util.CodecUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link SaltedHashBean}.
 *
 * @author Marvin S. Addison
 */
public class SaltedHashBeanTest
{
  @DataProvider(name = "test-data")
  public Object[][] getTestData()
  {
    return new Object[][] {
      new Object[] {
        CodecUtil.b64("7FHsteHnm6XQsJT1TTKbxw=="),
        new DigestSpec("SHA1"),
        CodecSpec.BASE64,
        2,
        "xNnVXeRl3w5AWJBIdXSkmU1hFj16Gno8KeiNJ6AWlG9K2pD0",
      },
    };
  }

  @Test(dataProvider = "test-data")
  public void testHash(
    final byte[] input, final DigestSpec digest, final CodecSpec codec, final int iterations, final String expected)
    throws Exception
  {

    final SaltedHashBean bean = new SaltedHashBean();
    bean.setDigestSpec(digest);
    bean.setCodecSpec(codec);
    bean.setIterations(iterations);
    bean.setSaltSource(new Nonce()
    {
      @Override
      public byte[] generate() throws LimitException
      {
        return CodecUtil.b64("ehp6PCnojSegFpRvStqQ9A==");
      }

      @Override
      public int getLength()
      {
        return 16;
      }
    });
    assertEquals(bean.hash(input), expected);
  }
}
