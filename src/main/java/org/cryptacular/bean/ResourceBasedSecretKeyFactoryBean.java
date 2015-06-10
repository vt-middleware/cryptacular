/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.IOException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
  private String algorithm;

  /** Resource containing key data. */
  private Resource resource;


  /** Creates a new instance. */
  public ResourceBasedSecretKeyFactoryBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  resource  Resource containing encoded key data.
   * @param  algorithm  Algorithm name of cipher with which key will be used.
   */
  public ResourceBasedSecretKeyFactoryBean(final Resource resource, final String algorithm)
  {
    setResource(resource);
    setAlgorithm(algorithm);
  }


  /** @return  Key algorithm name, e.g. AES. */
  public String getAlgorithm()
  {
    return algorithm;
  }


  /**
   * Sets the key algorithm.
   *
   * @param  algorithm  Secret key algorithm, e.g. AES.
   */
  public void setAlgorithm(final String algorithm)
  {
    this.algorithm = algorithm;
  }


  /** @return  Resource containing key data. */
  public Resource getResource()
  {
    return resource;
  }


  /**
   * Sets the resource containing key data.
   *
   * @param  resource  Resource containing key bytes.
   */
  public void setResource(final Resource resource)
  {
    this.resource = resource;
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
