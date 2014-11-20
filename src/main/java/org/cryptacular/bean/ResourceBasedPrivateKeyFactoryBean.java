/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.IOException;
import java.security.PrivateKey;
import org.cryptacular.io.Resource;
import org.cryptacular.util.KeyPairUtil;

/**
 * Factory for reading a private from a {@link Resource} containing data in any
 * of the formats supported by {@link
 * KeyPairUtil#readPrivateKey(java.io.InputStream, char[])}.
 *
 * @author  Middleware Services
 * @see  KeyPairUtil#readPrivateKey(java.io.InputStream, char[])
 * @see  KeyPairUtil#readPrivateKey(java.io.InputStream)
 */
public class ResourceBasedPrivateKeyFactoryBean
  implements FactoryBean<PrivateKey>
{

  /** Resource containing key data. */
  private Resource resource;

  /** Password required to decrypt an encrypted private key. */
  private String password;


  /** Creates a new instance. */
  public ResourceBasedPrivateKeyFactoryBean() {}


  /**
   * Creates a new instance capable of reading an unencrypted private key.
   *
   * @param  resource  Resource containing encoded key data.
   */
  public ResourceBasedPrivateKeyFactoryBean(final Resource resource)
  {
    setResource(resource);
  }


  /**
   * Creates a new instance of reading an encrypted private key.
   *
   * @param  resource  Resource containing encoded key data.
   * @param  decryptionPassword  Password-based encryption key.
   */
  public ResourceBasedPrivateKeyFactoryBean(
    final Resource resource,
    final String decryptionPassword)
  {
    setResource(resource);
    setPassword(decryptionPassword);
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


  /**
   * Sets the password-based key used to decrypt an encrypted private key.
   *
   * @param  decryptionPassword  Password-based encryption key.
   */
  public void setPassword(final String decryptionPassword)
  {
    this.password = decryptionPassword;
  }


  /** {@inheritDoc} */
  @Override
  public PrivateKey newInstance()
  {
    try {
      if (password != null) {
        return
          KeyPairUtil.readPrivateKey(
            resource.getInputStream(),
            password.toCharArray());
      }
      return KeyPairUtil.readPrivateKey(resource.getInputStream());
    } catch (IOException e) {
      throw new RuntimeException("Error getting input stream from " + resource);
    }
  }
}
