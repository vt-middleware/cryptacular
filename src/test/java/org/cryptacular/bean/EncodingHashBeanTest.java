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
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.CodecUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

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
      new Object[] {
        ByteUtil.toBytes("Vilkommen"),
        new DigestSpec("SHA-256"),
        CodecSpec.BASE64,
        "Kmgr/A02GIvA6ztYHTw4IX/Pffwp3endHokKRjat2pM=",
      },
      new Object[] {
        CodecUtil.b64("gDu8UYjC0xP2YGpUtm9qEA=="),
        new DigestSpec("MD5"),
        CodecSpec.HEX,
        "e258a74f91e30662a42ccb5a8d904eed",
      },
    };
  }

  @Test(dataProvider = "test-data")
  public void testHash(
      final byte[] input, final DigestSpec digest, final CodecSpec codec, final String expected) throws Exception
  {
    final EncodingHashBean bean = new EncodingHashBean();
    bean.setDigestSpec(digest);
    bean.setCodecSpec(codec);
    assertEquals(bean.hash(input), expected);
  }


  @Test(dataProvider = "test-data")
  public void testCompare(
    final byte[] input, final DigestSpec digest, final CodecSpec codec, final String expected) throws Exception
  {
    final EncodingHashBean bean = new EncodingHashBean();
    bean.setDigestSpec(digest);
    bean.setCodecSpec(codec);
    assertTrue(bean.compare(input, expected));
  }
}
