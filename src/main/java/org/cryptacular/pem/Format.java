/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.pem;

/**
 * Enum to define the RFC governing the PEM format
 *
 * @author Middleware Services
 */
public enum Format
{
  /**
   * a PEM encoded file as defined by RFC-2440 (OpenPGP).
   */
  RFC2440,

  /**
   * a PEM encoded file as defined by RFC-7468 (Textual Encodings of PKIX, PKCS, and CMS Structures).
   */
  RFC7468,

  /**
   * a PEM encoded file as defined by RFC-1421 (Privacy Enhanced Message).
   */
  RFC1421,

  /**
   * a PEM encoded file as defined by RFC-4716 (SSH).
   */
  RFC4716,
}
