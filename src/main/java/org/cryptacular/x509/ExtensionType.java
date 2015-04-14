/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509;

/**
 * Enumeration of X.509v3 extension fields defined in section 4.2 of RFC 2459.
 *
 * @author  Middleware Services
 * @version  $Revision: 2745 $
 */
public enum ExtensionType {

  /** AuthorityInfoAccess extension field. */
  AuthorityInformationAccess("1.3.6.1.5.5.7.1.1", false),

  /** AuthorityKeyIdentifier extension field. */
  AuthorityKeyIdentifier("2.5.29.35", false),

  /** BasicConstraints extension field. */
  BasicConstraints("2.5.29.19", true),

  /** CertificatePolicies extension field. */
  CertificatePolicies("2.5.29.32", false),

  /** CRLDistributionPoints extension field. */
  CRLDistributionPoints("2.5.29.31", false),

  /** ExtendedKeyUsage extension field. */
  ExtendedKeyUsage("2.5.29.37", false),

  /** IssuerAlternativeName extension field. */
  IssuerAlternativeName("2.5.29.18", false),

  /** KeyUsage extension field. */
  KeyUsage("2.5.29.15", true),

  /** NameConstraints extension field. */
  NameConstraints("2.5.29.30", true),

  /** PolicyConstraints extension field. */
  PolicyConstraints("2.5.29.36", false),

  /** PolicyMappings extension field. */
  PolicyMappings("2.5.29.33", false),

  /** PrivateKeyUsage extension field. */
  PrivateKeyUsagePeriod("2.5.29.16", false),

  /** SubjectAlternativeName extension field. */
  SubjectAlternativeName("2.5.29.17", false),

  /** SubjectKeyIdentifier extension field. */
  SubjectKeyIdentifier("2.5.29.14", false),

  /** SubjectDirectoryAttributes extension field. */
  SubjectDirectoryAttributes("2.5.29.9", false);


  /** Oid value. */
  private final String oid;

  /** Whether this extension is critical according to RFC 2459. */
  private final boolean critical;


  /**
   * Creates a new type with the given OID value.
   *
   * @param  oidString  Extension OID value.
   * @param  criticality  True if extension MUST or SHOULD be marked critical under general circumstances, false
   *                      otherwise.
   */
  ExtensionType(final String oidString, final boolean criticality)
  {
    oid = oidString;
    critical = criticality;
  }


  /**
   * Gets the extension by OID.
   *
   * @param  oid  Extension OID value.
   *
   * @return  Extension with given OID value.
   *
   * @throws  IllegalArgumentException  If no extension with given OID exists.
   */
  public static ExtensionType fromOid(final String oid)
  {
    for (ExtensionType ext : values()) {
      if (ext.getOid().equals(oid)) {
        return ext;
      }
    }
    throw new IllegalArgumentException("Invalid X.509v3 extension OID " + oid);
  }


  /**
   * Gets the extension by name.
   *
   * @param  name  Case-sensitive X.509v3 extension name. The acceptable case of extension names is governed by
   *               conventions in RFC 2459.
   *
   * @return  Extension with given name.
   *
   * @throws  IllegalArgumentException  If no extension with given name exists.
   */
  public static ExtensionType fromName(final String name)
  {
    try {
      return ExtensionType.valueOf(ExtensionType.class, name);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid X.509v3 extension name " + name);
    }
  }


  /**
   * @return  True if extension MUST or SHOULD be marked critical under general circumstances according to RFC 2459,
   *          false otherwise.
   */
  public boolean isCritical()
  {
    return critical;
  }


  /** @return  OID value of extension field. */
  public String getOid()
  {
    return oid;
  }
}
