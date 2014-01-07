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

package org.cryptacular.codec;

import java.io.File;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;

import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.HashUtil;
import org.cryptacular.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link Base64Decoder} class.
 *
 * @author Marvin S. Addison
 */
public class Base64DecoderTest
{

  @DataProvider(name = "b64-data")
  public Object[][] getTextData()
  {
    return new Object[][] {
      new Object[] {
        "QWJsZSB3YXMgSSBlcmUgSSBzYXcgZWxiYQ==",
        ByteUtil.toBytes("Able was I ere I saw elba"),
      },
      new Object[] {
        "QWJsZSB3YXMgSSBlcmUgSSBzYXcgZWxiYS4=",
        ByteUtil.toBytes("Able was I ere I saw elba."),
      },
      new Object[] {
        "safx/LW8+SsSy/o3PmCNy4VEm5s=",
        HashUtil.sha1(ByteUtil.toBytes("t3stUs3r01")),
      },
    };
  }


  @DataProvider(name = "plaintext-files")
  public Object[][] getPlaintextFiles()
  {
    return new Object[][] {
      new Object[] {"src/test/resources/plaintexts/lorem-1190.txt"},
      new Object[] {"src/test/resources/plaintexts/lorem-1200.txt"},
      new Object[] {"src/test/resources/plaintexts/lorem-5000.txt"},
    };
  }


  @Test(dataProvider = "b64-data")
  public void testDecode(final String data, final byte[] expected) throws Exception
  {
    final Base64Decoder decoder = new Base64Decoder();
    final CharBuffer input = CharBuffer.wrap(data);
    final ByteBuffer output = ByteBuffer.allocate(decoder.outputSize(input.length()));
    decoder.decode(input, output);
    decoder.finalize(output);
    output.flip();
    assertEquals(ByteUtil.toArray(output), expected);
  }


  @Test(dataProvider = "plaintext-files")
  public void testDecodeFile(final String path) throws Exception
  {
    final String expected = StreamUtil.readAll(StreamUtil.makeReader(new File(path)));
    final File file = new File(path + ".b64");
    final StringBuilder actual = new StringBuilder(expected.length());
    final Reader reader = StreamUtil.makeReader(file);
    final Base64Decoder decoder = new Base64Decoder();
    try {
      final CharBuffer bufIn = CharBuffer.allocate(1024);
      final ByteBuffer bufOut = ByteBuffer.allocate(decoder.outputSize(bufIn.capacity()));
      while (reader.read(bufIn) > 0) {
        bufIn.flip();
        decoder.decode(bufIn, bufOut);
        bufOut.flip();
        actual.append(ByteUtil.toCharBuffer(bufOut));
        bufOut.clear();
        bufIn.clear();
      }
      decoder.finalize(bufOut);
      bufOut.flip();
      actual.append(ByteUtil.toCharBuffer(bufOut));
    } finally {
      StreamUtil.closeReader(reader);
    }
    assertEquals(actual.toString(), expected);
  }
}
