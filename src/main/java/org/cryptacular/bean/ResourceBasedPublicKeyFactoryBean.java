/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.IOException;
import java.security.PublicKey;

import org.cryptacular.io.Resource;
import org.cryptacular.util.KeyPairUtil;

/**
 * Factory for creating a public key from a {@link Resource} containing data
 * in any of the formats supported by {@link
 * KeyPairUtil#readPublicKey(java.io.InputStream)}.
 *
 * @author  Middleware Services
 * @see  KeyPairUtil#readPublicKey(java.io.InputStream)
 */
public class ResourceBasedPublicKeyFactoryBean implements FactoryBean<PublicKey>
{

  /** Resource containing key data. */
  private Resource resource;


  /** Creates a new instance. */
  public ResourceBasedPublicKeyFactoryBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  resource  Resource containing encoded key data.
   */
  public ResourceBasedPublicKeyFactoryBean(final Resource resource)
  {
    setResource(resource);
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


  /** {@inheritDoc} */
  @Override
  public PublicKey newInstance()
  {
    try {
      return KeyPairUtil.readPublicKey(resource.getInputStream());
    } catch (IOException e) {
      throw new RuntimeException("Error getting input stream from " + resource);
    }
  }
}
