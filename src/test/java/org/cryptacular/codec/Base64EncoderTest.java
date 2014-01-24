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
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.FileChannel;

import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.HashUtil;
import org.cryptacular.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link Base64Encoder} class.
 *
 * @author Marvin S. Addison
 */
public class Base64EncoderTest
{
  @DataProvider(name = "text-data")
  public Object[][] getTextData()
  {
    return new Object[][] {
      new Object[] {
        ByteUtil.toBytes("Able was I ere I saw elba"),
        "QWJsZSB3YXMgSSBlcmUgSSBzYXcgZWxiYQ==",
      },
      new Object[] {
        ByteUtil.toBytes("Able was I ere I saw elba."),
        "QWJsZSB3YXMgSSBlcmUgSSBzYXcgZWxiYS4=",
      },
      new Object[] {
        HashUtil.sha1(ByteUtil.toBytes("t3stUs3r01")),
        "safx/LW8+SsSy/o3PmCNy4VEm5s=",
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


  @Test(dataProvider = "text-data")
  public void testEncode(final byte[] inBytes, final String expected) throws Exception
  {
    final ByteBuffer input = ByteBuffer.wrap(inBytes);
    final Base64Encoder encoder = new Base64Encoder();
    final CharBuffer output = CharBuffer.allocate(encoder.outputSize(input.limit()));
    encoder.encode(input, output);
    encoder.finalize(output);
    assertEquals(output.flip().toString(), expected);
  }


  @Test(dataProvider = "plaintext-files")
  public void testEncodeFile(final String path) throws Exception
  {
    final File file = new File(path);
    String expectedPath = path + ".b64";
    if ("\r\n".equals(System.lineSeparator())) {
      expectedPath += ".crlf";
    }
    final String expected = new String(StreamUtil.readAll(expectedPath));
    final StringBuilder actual = new StringBuilder(expected.length());
    final Base64Encoder encoder = new Base64Encoder(64);
    try (FileInputStream input = new FileInputStream(file)) {
      final ByteBuffer bufIn = ByteBuffer.allocate(512);
      final CharBuffer bufOut = CharBuffer.allocate(encoder.outputSize(512));
      final FileChannel chIn = input.getChannel();
      while (chIn.read(bufIn) > 0) {
        bufIn.flip();
        encoder.encode(bufIn, bufOut);
        bufOut.flip();
        actual.append(bufOut);
        bufOut.clear();
        bufIn.clear();
      }
      encoder.finalize(bufOut);
      bufOut.flip();
      actual.append(bufOut);
    }
    assertEquals(actual.toString(), expected);
  }
}
