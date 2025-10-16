/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import org.cryptacular.CryptUtil;
import org.cryptacular.CryptoException;
import org.cryptacular.StreamException;
import org.cryptacular.io.Resource;

/**
 * Factory bean that produces a {@link KeyStore} from a file or URI.
 *
 * @author  Middleware Services
 */
public class KeyStoreFactoryBean implements FactoryBean<KeyStore>
{

  /** Default keystore type, {@value}. */
  public static final String DEFAULT_TYPE = "JCEKS";

  /** Keystore type, e.g. JKS, JCEKS, BKS. */
  private final String type;

  /** Resource that provides encoded keystore data. */
  private final Resource resource;

  /** Keystore password. */
  private final String password;


  /**
   * Creates a new keystore factory bean.
   *
   * @param  resource  Resource containing encoded keystore data.
   * @param  password  Password used to decrypt key entry in keystore.
   */
  public KeyStoreFactoryBean(final Resource resource, final String password)
  {
    this(resource, DEFAULT_TYPE, password);
  }


  /**
   * Creates a new keystore factory bean.
   *
   * @param  resource  Resource containing encoded keystore data.
   * @param  type  Keystore type, e.g. JCEKS.
   * @param  password  Password used to decrypt key entry in keystore.
   */
  public KeyStoreFactoryBean(final Resource resource, final String type, final String password)
  {
    this.resource = CryptUtil.assertNotNullArg(resource, "Resource cannot be null");
    this.type = CryptUtil.assertNotNullArg(type, "Type cannot be null");
    this.password = password;
  }


  /** @return  Keystore type. */
  public String getType()
  {
    return type;
  }


  /** @return  Resource that provides encoded keystore data. */
  public Resource getResource()
  {
    return resource;
  }


  @Override
  public KeyStore newInstance()
  {
    if (resource == null) {
      throw new IllegalStateException("Must provide resource.");
    }

    final KeyStore store;
    try {
      store = KeyStore.getInstance(type);
    } catch (KeyStoreException e) {
      String message = "Unsupported keystore type " + type;
      if ("BKS".equalsIgnoreCase(type)) {
        message += ". Is BC provider installed?";
      }
      throw new CryptoException(message, e);
    }
    try {
      store.load(resource.getInputStream(), password.toCharArray());
    } catch (CertificateException | NoSuchAlgorithmException e) {
      throw new CryptoException("Error loading keystore", e);
    } catch (IOException e) {
      throw new StreamException(e);
    }
    return store;
  }
}
