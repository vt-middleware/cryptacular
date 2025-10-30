/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.IOException;
import java.security.PrivateKey;
import org.cryptacular.CryptUtil;
import org.cryptacular.EncodingException;
import org.cryptacular.StreamException;
import org.cryptacular.io.Resource;
import org.cryptacular.util.KeyPairUtil;

/**
 * Factory for reading a private from a {@link Resource} containing data in any of the formats supported by {@link
 * KeyPairUtil#readPrivateKey(java.io.InputStream, char[])}.
 *
 * @author  Middleware Services
 * @see  KeyPairUtil#readPrivateKey(java.io.InputStream, char[])
 * @see  KeyPairUtil#readPrivateKey(java.io.InputStream)
 */
public class ResourceBasedPrivateKeyFactoryBean implements FactoryBean<PrivateKey>
{

  /** Resource containing key data. */
  private final Resource resource;

  /** Password required to decrypt an encrypted private key. */
  private final String password;


  /**
   * Creates a new instance capable of reading an unencrypted private key.
   *
   * @param  resource  Resource containing encoded key data.
   */
  public ResourceBasedPrivateKeyFactoryBean(final Resource resource)
  {
    this(resource, null);
  }


  /**
   * Creates a new instance of reading an encrypted private key.
   *
   * @param  resource  Resource containing encoded key data.
   * @param  decryptionPassword  Password-based encryption key.
   */
  public ResourceBasedPrivateKeyFactoryBean(final Resource resource, final String decryptionPassword)
  {
    this.resource = CryptUtil.assertNotNullArg(resource, "Resource cannot be null");
    this.password = decryptionPassword;
  }


  /** @return  Resource containing key data. */
  public Resource getResource()
  {
    return resource;
  }


  @Override
  public PrivateKey newInstance() throws EncodingException, StreamException
  {
    try {
      if (password != null) {
        return KeyPairUtil.readPrivateKey(resource.getInputStream(), password.toCharArray());
      }
      return KeyPairUtil.readPrivateKey(resource.getInputStream());
    } catch (IOException e) {
      throw new StreamException(e);
    }
  }
}
