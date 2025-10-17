/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.IOException;
import java.security.PublicKey;
import org.cryptacular.CryptUtil;
import org.cryptacular.EncodingException;
import org.cryptacular.StreamException;
import org.cryptacular.io.Resource;
import org.cryptacular.util.KeyPairUtil;

/**
 * Factory for creating a public key from a {@link Resource} containing data in any of the formats supported by {@link
 * KeyPairUtil#readPublicKey(java.io.InputStream)}.
 *
 * @author  Middleware Services
 * @see  KeyPairUtil#readPublicKey(java.io.InputStream)
 */
public class ResourceBasedPublicKeyFactoryBean implements FactoryBean<PublicKey>
{

  /** Resource containing key data. */
  private final Resource resource;


  /**
   * Creates a new resource based public key factory bean.
   *
   * @param  resource  Resource containing encoded key data.
   */
  public ResourceBasedPublicKeyFactoryBean(final Resource resource)
  {
    this.resource = CryptUtil.assertNotNullArg(resource, "Resource cannot be null");
  }


  /** @return  Resource containing key data. */
  public Resource getResource()
  {
    return resource;
  }


  @Override
  public PublicKey newInstance() throws EncodingException, StreamException
  {
    try {
      return KeyPairUtil.readPublicKey(resource.getInputStream());
    } catch (IOException e) {
      throw new StreamException(e);
    }
  }
}
