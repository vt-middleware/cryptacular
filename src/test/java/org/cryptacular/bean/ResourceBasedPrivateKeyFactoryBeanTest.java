/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.File;
import java.security.PrivateKey;
import org.cryptacular.FailListener;
import org.cryptacular.io.FileResource;
import org.cryptacular.io.Resource;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link ResourceBasedPrivateKeyFactoryBean}.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class ResourceBasedPrivateKeyFactoryBeanTest
{
  private static final String KEY_PATH = "src/test/resources/keys/";

  @DataProvider(name = "keys")
  public Object[][] getKeys()
  {
    return
      new Object[][] {
        new Object[] {KEY_PATH + "dsa-pkcs8-nopass.pem", null},
        new Object[] {KEY_PATH + "dsa-openssl-nopass.pem", null},
        new Object[] {KEY_PATH + "rsa-pkcs8-nopass.pem", null},
        new Object[] {KEY_PATH + "rsa-openssl-nopass.pem", null},
        new Object[] {
          KEY_PATH + "ec-openssl-sect571r1-explicit-nopass.pem",
          null,
        },
        new Object[] {KEY_PATH + "dsa-openssl-des3.pem", "vtcrypt"},
        new Object[] {KEY_PATH + "dsa-pkcs8-v2-des3.der", "vtcrypt"},
        new Object[] {
          KEY_PATH + "ec-pkcs8-sect571r1-explicit-v2-aes128.pem",
          "vtcrypt",
        },
        new Object[] {
          KEY_PATH + "ec-pkcs8-sect571r1-named-v1-sha1-rc2-64.der",
          "vtcrypt",
        },
        new Object[] {KEY_PATH + "rsa-openssl-des.pem", "vtcrypt"},
        new Object[] {KEY_PATH + "rsa-pkcs8-v2-aes256.der", "vtcrypt"},
      };
  }

  @Test(dataProvider = "keys")
  public void testNewInstance(final String path, final String password)
    throws Exception
  {
    final Resource resource = new FileResource(new File(path));
    final ResourceBasedPrivateKeyFactoryBean factory = new ResourceBasedPrivateKeyFactoryBean(resource, password);
    assertThat(factory.newInstance()).isInstanceOf(PrivateKey.class);
  }
}
