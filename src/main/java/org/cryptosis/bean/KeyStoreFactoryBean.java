package org.cryptosis.bean;

import org.cryptosis.io.Resource;

import java.security.KeyStore;
import java.security.KeyStoreException;

/**
 * Factory bean that produces a {@link KeyStore} from a file or URI.
 *
 * @author Marvin S. Addison
 */
public class KeyStoreFactoryBean implements FactoryBean<KeyStore>
{
  /** Default keystore type, {@value #DEFAULT_TYPE} */
  public static final String DEFAULT_TYPE = "JCEKS";

  /** Keystore type, e.g. JKS, JCEKS, BKS. */
  private String type = DEFAULT_TYPE;

  /** Resource that provides encoded keystore data. */
  private Resource resource;

  /** Keystore password. */
  private String password;


  /**
   * Sets the keystore type.
   *
   * @param  type  JCEKS (default), JKS, PKCS12, or BKS. <strong>NOTE:</strong> BKS type is supported only when BC
   *               provider is installed.
   */
  public void setType(final String type)
  {
    this.type = type;
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


  /** {@inheritDoc} */
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
