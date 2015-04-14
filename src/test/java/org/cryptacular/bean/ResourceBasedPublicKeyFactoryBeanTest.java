/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.security.PublicKey;
import org.cryptacular.io.ClassPathResource;
import org.cryptacular.io.Resource;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;

/**
 * Unit test for {@link ResourceBasedPublicKeyFactoryBean}.
 *
 * @author  Middleware Services
 */
public class ResourceBasedPublicKeyFactoryBeanTest
{
  private static final String KEY_PATH = "/keys/";

  @DataProvider(name = "keys")
  public Object[][] getKeys()
  {
    return
      new Object[][] {
        new Object[] {KEY_PATH + "dsa-pub.pem"},
        new Object[] {KEY_PATH + "rsa-pub.pem"},
        new Object[] {KEY_PATH + "ec-secp224k1-explicit-pub.pem"},
      };
  }

  @Test(dataProvider = "keys")
  public void testNewInstance(final String path)
    throws Exception
  {
    final Resource resource = new ClassPathResource(path);
    final ResourceBasedPublicKeyFactoryBean factory = new ResourceBasedPublicKeyFactoryBean(resource);
    assertTrue(factory.newInstance() instanceof PublicKey);
  }
}
