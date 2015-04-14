/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.File;
import org.cryptacular.io.FileResource;
import org.cryptacular.io.Resource;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link ResourceBasedSecretKeyFactoryBean}.
 *
 * @author  Middleware Services
 */
public class ResourceBasedSecretKeyFactoryBeanTest
{
  private static final String KEY_PATH = "src/test/resources/keys/";

  @DataProvider(name = "keys")
  public Object[][] getKeys()
  {
    return new Object[][] {
      new Object[] {
        "AES",
        new FileResource(new File(KEY_PATH + "aes-128.key")),
        16,
      },
    };
  }


  @Test(dataProvider = "keys")
  public void testNewInstance(final String algorithm, final Resource resource, final int expectedSize)
    throws Exception
  {
    final ResourceBasedSecretKeyFactoryBean factory = new ResourceBasedSecretKeyFactoryBean();
    factory.setAlgorithm(algorithm);
    factory.setResource(resource);
    assertEquals(factory.newInstance().getEncoded().length, expectedSize);
  }
}
