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

import java.io.File;

import org.cryptosis.io.FileResource;
import org.cryptosis.io.Resource;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link ResourceBasedSecretKeyFactoryBean}.
 *
 * @author Marvin S. Addison
 */
public class ResourceBasedSecretKeyFactoryBeanTest
{
  private static final String KEY_PATH = "src/test/resources/keys/";

  @DataProvider(name = "keys")
  public Object[][] getKeys()
  {
    return new Object[][] {
      new Object[] { "AES", new FileResource(new File(KEY_PATH + "aes-128.key")), 16 },
    };
  }


  @Test(dataProvider = "keys")
  public void testNewInstance(
      final String algorithm, final Resource resource, final int expectedSize) throws Exception
  {
    final ResourceBasedSecretKeyFactoryBean factory = new ResourceBasedSecretKeyFactoryBean();
    factory.setAlgorithm(algorithm);
    factory.setResource(resource);
    assertEquals(factory.newInstance().getEncoded().length, expectedSize);
  }
}
