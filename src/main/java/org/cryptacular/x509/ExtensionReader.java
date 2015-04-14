/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

/**
 * Reads X.509v3 extended properties from an {@link java.security.cert.X509Certificate} object. The available properties
 * are described in section 4.2 of RFC 2459, http://www.faqs.org/rfcs/rfc2459.html.
 *
 * @author  Middleware Services
 */
public final class ExtensionReader
{

  /** The X509Certificate whose extension fields will be read. */
  private final X509Certificate certificate;


  /**
   * Creates a new instance that can read extension fields from the given X.509 certificate.
   *
   * @param  cert  Certificate to read.
   */
  public ExtensionReader(final X509Certificate cert)
  {
    certificate = cert;
  }


  /**
   * Reads the value of the extension given by OID or name as defined in section 4.2 of RFC 2459.
   *
   * @param  extensionOidOrName  OID or extension name, e.g. 2.5.29.14 orSubjectK eyIdentifier. In the case of extension
   *                             name, the name is case-sensitive and follows the conventions in RFC 2459.
   *
   * @return  Extension type containing data from requested extension field.
   */
  public ASN1Encodable read(final String extensionOidOrName)
  {
    if (extensionOidOrName == null) {
      throw new IllegalArgumentException("extensionOidOrName cannot be null.");
    }
    if (extensionOidOrName.contains(".")) {
      return read(ExtensionType.fromOid(extensionOidOrName));
    } else {
      return read(ExtensionType.fromName(extensionOidOrName));
    }
  }


  /**
   * Reads the value of the given certificate extension field.
   *
   * @param  extension  Extension to read from certificate.
   *
   * @return  Extension type containing data from requested extension field.
   */
  public ASN1Encodable read(final ExtensionType extension)
  {
    byte[] data = certificate.getExtensionValue(extension.getOid());
    if (data == null) {
      return null;
    }
    try {
      ASN1Encodable der = ASN1Primitive.fromByteArray(data);
      if (der instanceof ASN1OctetString) {
        // Strip off octet string "wrapper"
        data = ((ASN1OctetString) der).getOctets();
        der = ASN1Primitive.fromByteArray(data);
      }
      return der;
    } catch (IOException e) {
      throw new IllegalArgumentException("IO exception parsing ASN.1 data", e);
    }
  }


  /**
   * Reads the value of the SubjectAlternativeName extension field of the certificate.
   *
   * @return  Collection of subject alternative names or null if the certificate does not define this extension field.
   *          Note that an empty collection of names is different from a null return value; in the former case the field
   *          is defined but empty, whereas in the latter the field is not defined on the certificate.
   */
  public GeneralNames readSubjectAlternativeName()
  {
    return GeneralNames.getInstance(read(ExtensionType.SubjectAlternativeName));
  }


  /**
   * Reads the value of the <code>IssuerAlternativeName</code> extension field of the certificate.
   *
   * @return  Collection of issuer alternative names or null if the certificate does not define this extension field.
   *          Note that an empty collection of names is different from a null return value; in the former case the field
   *          is defined but empty, whereas in the latter the field is not defined on the certificate.
   */
  public GeneralNames readIssuerAlternativeName()
  {
    return GeneralNames.getInstance(read(ExtensionType.IssuerAlternativeName));
  }


  /**
   * Reads the value of the <code>BasicConstraints</code> extension field of the certificate.
   *
   * @return  Basic constraints defined on certificate or null if the certificate does not define the field.
   */
  public BasicConstraints readBasicConstraints()
  {
    return BasicConstraints.getInstance(read(ExtensionType.BasicConstraints));
  }


  /**
   * Reads the value of the <code>CertificatePolicies</code> extension field of the certificate.
   *
   * @return  List of certificate policies defined on certificate or null if the certificate does not define the field.
   */
  public List<PolicyInformation> readCertificatePolicies()
  {
    final ASN1Encodable data = read(ExtensionType.CertificatePolicies);
    if (data == null) {
      return null;
    }

    final ASN1Sequence sequence = ASN1Sequence.getInstance(data);
    final List<PolicyInformation> list = new ArrayList<>(sequence.size());
    for (int i = 0; i < sequence.size(); i++) {
      list.add(PolicyInformation.getInstance(sequence.getObjectAt(i)));
    }
    return list;
  }


  /**
   * Reads the value of the <code>SubjectKeyIdentifier</code> extension field of the certificate.
   *
   * @return  Subject key identifier.
   */
  public SubjectKeyIdentifier readSubjectKeyIdentifier()
  {
    return SubjectKeyIdentifier.getInstance(read(ExtensionType.SubjectKeyIdentifier));
  }


  /**
   * Reads the value of the <code>AuthorityKeyIdentifier</code> extension field of the certificate.
   *
   * @return  Authority key identifier.
   */
  public AuthorityKeyIdentifier readAuthorityKeyIdentifier()
  {
    return AuthorityKeyIdentifier.getInstance(read(ExtensionType.AuthorityKeyIdentifier));
  }


  /**
   * Reads the value of the <code>KeyUsage</code> extension field of the certificate.
   *
   * @return  Key usage data or null if extension field is not defined.
   */
  public KeyUsage readKeyUsage()
  {
    return KeyUsage.getInstance(read(ExtensionType.KeyUsage));
  }


  /**
   * Reads the value of the <code>ExtendedKeyUsage</code> extension field of the certificate.
   *
   * @return  List of supported extended key usages or null if extension is not defined.
   */
  public List<KeyPurposeId> readExtendedKeyUsage()
  {
    final ASN1Encodable data = read(ExtensionType.ExtendedKeyUsage);
    if (data == null) {
      return null;
    }

    final ASN1Sequence sequence = ASN1Sequence.getInstance(data);
    final List<KeyPurposeId> list = new ArrayList<>(sequence.size());
    for (int i = 0; i < sequence.size(); i++) {
      list.add(KeyPurposeId.getInstance(sequence.getObjectAt(i)));
    }
    return list;
  }


  /**
   * Reads the value of the <code>CRLDistributionPoints</code> extension field of the certificate.
   *
   * @return  List of CRL distribution points or null if extension is not defined.
   */
  public List<DistributionPoint> readCRLDistributionPoints()
  {
    final ASN1Encodable data = read(ExtensionType.CRLDistributionPoints);
    if (data == null) {
      return null;
    }

    final ASN1Sequence sequence = ASN1Sequence.getInstance(data);
    final List<DistributionPoint> list = new ArrayList<>(sequence.size());
    for (int i = 0; i < sequence.size(); i++) {
      list.add(DistributionPoint.getInstance(sequence.getObjectAt(i)));
    }
    return list;
  }


  /**
   * Reads the value of the <code>AuthorityInformationAccess</code> extension field of the certificate.
   *
   * @return  List of access descriptions or null if extension is not defined.
   */
  public List<AccessDescription> readAuthorityInformationAccess()
  {
    final ASN1Encodable data = read(ExtensionType.AuthorityInformationAccess);
    if (data == null) {
      return null;
    }

    final ASN1Sequence sequence = ASN1Sequence.getInstance(data);
    final List<AccessDescription> list = new ArrayList<>(sequence.size());
    for (int i = 0; i < sequence.size(); i++) {
      list.add(AccessDescription.getInstance(sequence.getObjectAt(i)));
    }
    return list;
  }

}
