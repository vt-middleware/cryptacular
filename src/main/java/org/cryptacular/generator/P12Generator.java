/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.bouncycastle.pkcs.PKCS12PfxPdu;

/**
 * Provides a simple interface for generating PKCS12 containers.
 *
 * @author Marvin S. Addison
 */
public interface P12Generator
{
  /**
   * Generates a PKCS12 container object that contains the given private key and certificates.
   *
   * @param password PKCS12 encryption password. This secret is also used to encrypt the inner private key.
   * @param key Private key.
   * @param certificates One or more certificates. If more than one certificate is provided, the first is taken as the
   *                     end-entity certificate.
   *
   * @return Bouncy Castle PKCS12 container object.
   */
  PKCS12PfxPdu generate(char[] password, PrivateKey key, X509Certificate... certificates);
}
