package org.cryptosis.bean;

import org.cryptosis.io.Resource;
import org.cryptosis.util.StreamUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;

/**
 * Factory that produces a {@link SecretKey} from a {@link Resource}.
 *
 * @author Marvin S. Addison
 */
public class ResourceBasedSecretKeyFactoryBean implements FactoryBean<SecretKey>
{
  /** Key algorithm. */
  private String algorithm;

  /** Resource containing key data. */
  private Resource resource;


  /**
   * Sets the key algorithm.
   *
   * @param  algorithm  Secret key algorithm.
   */
  public void setAlgorithm(final String algorithm)
  {
    this.algorithm = algorithm;
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


  /** {@inheritDoc} */
  @Override
  public SecretKey newInstance()
  {
    try {
      return new SecretKeySpec(StreamUtil.readAll(resource.getInputStream()), algorithm);
    } catch (IOException e) {
      throw new RuntimeException("Error getting input stream from " + resource);
    }
  }
}
