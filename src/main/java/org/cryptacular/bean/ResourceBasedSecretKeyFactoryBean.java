/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.IOException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.cryptacular.CryptUtil;
import org.cryptacular.StreamException;
import org.cryptacular.io.Resource;
import org.cryptacular.util.StreamUtil;

/**
 * Factory that produces a {@link SecretKey} from a {@link Resource}.
 *
 * @author  Middleware Services
 */
public class ResourceBasedSecretKeyFactoryBean implements FactoryBean<SecretKey>
{

  /** Key algorithm. */
  private final String algorithm;

  /** Resource containing key data. */
  private final Resource resource;


  /**
   * Creates a new resource based secret key factory bean.
   *
   * @param  resource  Resource containing encoded key data.
   * @param  algorithm  Algorithm name of cipher with which key will be used.
   */
  public ResourceBasedSecretKeyFactoryBean(final Resource resource, final String algorithm)
  {
    this.resource = CryptUtil.assertNotNullArg(resource, "Resource cannot be null");
    this.algorithm = CryptUtil.assertNotNullArg(algorithm, "Algorithm cannot be null");
  }


  /** @return  Key algorithm name, e.g. AES. */
  public String getAlgorithm()
  {
    return algorithm;
  }


  /** @return  Resource containing key data. */
  public Resource getResource()
  {
    return resource;
  }


  @Override
  public SecretKey newInstance() throws StreamException
  {
    try {
      return new SecretKeySpec(StreamUtil.readAll(resource.getInputStream()), algorithm);
    } catch (IOException e) {
      throw new StreamException(e);
    }
  }
}
