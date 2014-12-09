/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.security.KeyStore;
import java.security.KeyStoreException;
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
  private String type = DEFAULT_TYPE;

  /** Resource that provides encoded keystore data. */
  private Resource resource;

  /** Keystore password. */
  private String password;


  /** Creates a new instance. */
  public KeyStoreFactoryBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  resource  Resource containing encoded keystore data.
   * @param  type  Keystore type, e.g. JCEKS.
   * @param  password  Password used to decrypt key entry in keystore.
   */
  public KeyStoreFactoryBean(
    final Resource resource,
    final String type,
    final String password)
  {
    setResource(resource);
    setType(type);
    setPassword(password);
  }


  /** @return  Keystore type. */
  public String getType()
  {
    return type;
  }


  /**
   * Sets the keystore type.
   *
   * @param  type  JCEKS (default), JKS, PKCS12, or BKS. <strong>NOTE:</strong>
   *               BKS type is supported only when BC provider is installed.
   */
  public void setType(final String type)
  {
    this.type = type;
  }


  /** @return  Resource that provides encoded keystore data. */
  public Resource getResource()
  {
    return resource;
  }


  /**
   * Sets the resource that provides encoded keystore data.
   *
   * @param  resource  Keystore resource.
   */
  public void setResource(final Resource resource)
  {
    this.resource = resource;
  }


  /**
   * Sets the keystore password required to decrypt an encrypted keystore.
   *
   * @param  password  Keystore password.
   */
  public void setPassword(final String password)
  {
    this.password = password;
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
      throw new IllegalArgumentException(message, e);
    }
    try {
      store.load(resource.getInputStream(), password.toCharArray());
    } catch (Exception e) {
      throw new RuntimeException("Error loading keystore", e);
    }
    return store;
  }
}
