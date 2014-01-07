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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.KeyStore;

import org.cryptosis.generator.Nonce;
import org.cryptosis.generator.sp80038a.BigIntegerCounterNonce;
import org.cryptosis.generator.sp80038a.LongCounterNonce;
import org.cryptosis.generator.sp80038a.RBGNonce;
import org.cryptosis.io.FileResource;
import org.cryptosis.spec.BufferedBlockCipherSpec;
import org.cryptosis.util.ByteUtil;
import org.cryptosis.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link BufferedBlockCipherBean}.
 *
 * @author Marvin S. Addison
 */
public class BufferedBlockCipherBeanTest
{
  @DataProvider(name = "test-arrays")
  public Object[][] getTestArrays()
  {
    return new Object[][] {
      new Object[] {
        // Plaintext is NOT multiple of block size
        "Able was I ere I saw elba.",
        "AES/CBC/PKCS5",
        new RBGNonce(16),
      },
      // Plaintext is multiple of block size
      new Object[] {
        "Four score and seven years ago, our forefathers ",
        "Blowfish/CBC/None",
        new RBGNonce(8),
      },
      // OFB
      new Object[] {
        "Have you passed through this night?",
        "Blowfish/OFB/PKCS5Padding",
        new LongCounterNonce(),
      },
      // CFB
      new Object[] {
        "I went to the woods because I wished to live deliberately, to front only the essential facts of life",
        "AES/CFB/PKCS5Padding",
        new RBGNonce(16),
      },
    };
  }

  @DataProvider(name = "test-streams")
  public Object[][] getTestStreams()
  {
    return new Object[][] {
      new Object[] {
        "src/test/resources/plaintexts/lorem-5000.txt",
        "AES/CBC/PKCS7",
        new RBGNonce(16),
      },
      new Object[] {
        "src/test/resources/plaintexts/lorem-1200.txt",
        "Twofish/OFB/NULL",
        new BigIntegerCounterNonce(BigInteger.ONE, 16),
      },
      new Object[] {
        "src/test/resources/plaintexts/lorem-1200.txt",
        "AES/CFB/PKCS5",
        new RBGNonce(16),
      },
      new Object[] {
        "src/test/resources/plaintexts/lorem-1200.txt",
        "AES/ECB/PKCS5",
        new RBGNonce(16),
      },
    };
  }


  @Test(dataProvider = "test-arrays")
  public void testEncryptDecryptArray(
    final String input, final String cipherSpecString, final Nonce nonce) throws Exception
  {
    final BufferedBlockCipherBean cipherBean = new BufferedBlockCipherBean();
    final BufferedBlockCipherSpec cipherSpec = BufferedBlockCipherSpec.parse(cipherSpecString);
    cipherBean.setNonce(nonce);
    cipherBean.setKeyAlias("vtcrypt");
    cipherBean.setKeyPassword("vtcrypt");
    cipherBean.setKeyStore(getTestKeyStore());
    cipherBean.setBlockCipherSpec(cipherSpec);
    final byte[] ciphertext = cipherBean.encrypt(ByteUtil.toBytes(input));
    assertEquals(ByteUtil.toString(cipherBean.decrypt(ciphertext)), input);
  }


  @Test(dataProvider = "test-streams")
  public void testEncryptDecryptStream(
    final String path, final String cipherSpecString, final Nonce nonce) throws Exception
  {
    final BufferedBlockCipherBean cipherBean = new BufferedBlockCipherBean();
    final BufferedBlockCipherSpec cipherSpec = BufferedBlockCipherSpec.parse(cipherSpecString);
    cipherBean.setNonce(nonce);
    cipherBean.setKeyAlias("vtcrypt");
    cipherBean.setKeyPassword("vtcrypt");
    cipherBean.setKeyStore(getTestKeyStore());
    cipherBean.setBlockCipherSpec(cipherSpec);
    final ByteArrayOutputStream tempOut = new ByteArrayOutputStream(8192);
    cipherBean.encrypt(StreamUtil.makeStream(new File(path)), tempOut);
    final ByteArrayInputStream tempIn = new ByteArrayInputStream(tempOut.toByteArray());
    final ByteArrayOutputStream finalOut = new ByteArrayOutputStream(8192);
    cipherBean.decrypt(tempIn, finalOut);
    assertEquals(ByteUtil.toString(finalOut.toByteArray()), ByteUtil.toString(StreamUtil.readAll(path)));
  }

  private static KeyStore getTestKeyStore()
  {
    final KeyStoreFactoryBean bean = new KeyStoreFactoryBean();
    bean.setPassword("vtcrypt");
    bean.setResource(new FileResource(new File("src/test/resources/keystores/cipher-bean.jceks")));
    bean.setType("JCEKS");
    return bean.newInstance();
  }
}
