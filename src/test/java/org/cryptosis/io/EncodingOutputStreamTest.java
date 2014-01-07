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

package org.cryptosis.io;

import java.io.ByteArrayOutputStream;
import java.io.File;

import org.bouncycastle.util.io.Streams;
import org.cryptosis.util.ByteUtil;
import org.cryptosis.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link EncodingOutputStream} class.
 *
 * @author Marvin S. Addison
 */
public class EncodingOutputStreamTest
{
  @DataProvider(name = "plaintext-files")
  public Object[][] getPlaintextFiles()
  {
    return new Object[][] {
      new Object[] {"src/test/resources/plaintexts/lorem-1200.txt"},
      new Object[] {"src/test/resources/plaintexts/lorem-5000.txt"},
    };
  }

  @Test(dataProvider = "plaintext-files")
  public void testEncode(final String path) throws Exception
  {
    final File file = new File(path);
    String expectedPath = path + ".b64";
    if ("\r\n".equals(System.lineSeparator())) {
      expectedPath += ".crlf";
    }
    final String expected = new String(StreamUtil.readAll(expectedPath));
    final ByteArrayOutputStream bufOut = new ByteArrayOutputStream((int) file.length() * 4 / 3);
    final EncodingOutputStream output = EncodingOutputStream.base64(bufOut, 64);
    try {
      Streams.pipeAll(StreamUtil.makeStream(file), output);
    } finally {
      StreamUtil.closeStream(output);
    }
    assertEquals(ByteUtil.toString(bufOut.toByteArray()), expected);
  }
}
