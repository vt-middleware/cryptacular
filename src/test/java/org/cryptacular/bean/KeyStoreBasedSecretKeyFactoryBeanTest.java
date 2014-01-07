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

import java.io.File;
import javax.crypto.SecretKey;

import org.cryptacular.io.FileResource;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link KeyStoreBasedSecretKeyFactoryBean}.
 *
 * @author Marvin S. Addison
 */
public class KeyStoreBasedSecretKeyFactoryBeanTest
{
  private static final String KS_PATH = "src/test/resources/keystores/";

  @DataProvider(name = "keys")
  public Object[][] getKeys()
  {
    return new Object[][] {
      new Object[] { KS_PATH + "factory-bean.jceks", "JCEKS", "aes256", "AES", 32 },
    };
  }


  @Test(dataProvider = "keys")
  public void testNewInstance(
      final String keyStorePath,
      final String keyStoreType,
      final String alias,
      final String expectedAlg,
      final int expectedSize) throws Exception
  {
    final KeyStoreFactoryBean keyStoreFactory = new KeyStoreFactoryBean();
    keyStoreFactory.setResource(new FileResource(new File(keyStorePath)));
    keyStoreFactory.setPassword("vtcrypt");
    keyStoreFactory.setType(keyStoreType);
    final KeyStoreBasedSecretKeyFactoryBean secretKeyFactory = new KeyStoreBasedSecretKeyFactoryBean();
    secretKeyFactory.setKeyStore(keyStoreFactory.newInstance());
    secretKeyFactory.setAlias(alias);
    secretKeyFactory.setPassword("vtcrypt");
    final SecretKey key = secretKeyFactory.newInstance();
    assertEquals(key.getAlgorithm(), expectedAlg);
    assertEquals(key.getEncoded().length, expectedSize);
  }
}
