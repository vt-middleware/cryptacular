/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509;

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
import org.cryptacular.CryptUtil;
import org.cryptacular.EncodingException;

/**
 * Reads X.509v3 extended properties from an {@link java.security.cert.X509Certificate} object. The available properties
 * are described in section 4.2 of <a href="http://www.faqs.org/rfcs/rfc2459.html">RFC 2459</a>.
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
    certificate = CryptUtil.assertNotNullArg(cert, "Certificate cannot be null");
  }


  /**
   * Reads the value of the extension given by OID or name as defined in section 4.2 of RFC 2459.
   *
   * @param  extensionOidOrName  OID or extension name, e.g. 2.5.29.14 orSubjectK eyIdentifier. In the case of extension
   *                             name, the name is case-sensitive and follows the conventions in RFC 2459.
   *
   * @return  Extension type containing data from requested extension field.
   *
   * @throws  EncodingException  On certificate field parse errors.
   */
  public ASN1Encodable read(final String extensionOidOrName) throws EncodingException
  {
    CryptUtil.assertNotNullArg(extensionOidOrName, "Extension OID cannot be null");
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
   *
   * @throws  EncodingException  On certificate field parse errors.
   */
  public ASN1Encodable read(final ExtensionType extension)
  {
    CryptUtil.assertNotNullArg(extension, "Extension cannot be null");
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
    } catch (Exception e) {
      throw new EncodingException("ASN.1 parse error", e);
    }
  }


  /**
   * Reads the value of the SubjectAlternativeName extension field of the certificate.
   *
   * @return  Collection of subject alternative names or null if the certificate does not define this extension field.
   *          Note that an empty collection of names is different from a null return value; in the former case the field
   *          is defined but empty, whereas in the latter the field is not defined on the certificate.
   *
   * @throws  EncodingException  On certificate field parse errors.
   */
  public GeneralNames readSubjectAlternativeName() throws EncodingException
  {
    try {
      return GeneralNames.getInstance(read(ExtensionType.SubjectAlternativeName));
    } catch (RuntimeException e) {
      throw new EncodingException("GeneralNames parse error", e);
    }
  }


  /**
   * Reads the value of the <code>IssuerAlternativeName</code> extension field of the certificate.
   *
   * @return  Collection of issuer alternative names or null if the certificate does not define this extension field.
   *          Note that an empty collection of names is different from a null return value; in the former case the field
   *          is defined but empty, whereas in the latter the field is not defined on the certificate.
   *
   * @throws  EncodingException  On certificate field parse errors.
   */
  public GeneralNames readIssuerAlternativeName() throws EncodingException
  {
    try {
      return GeneralNames.getInstance(read(ExtensionType.IssuerAlternativeName));
    } catch (RuntimeException e) {
      throw new EncodingException("GeneralNames parse error", e);
    }
  }


  /**
   * Reads the value of the <code>BasicConstraints</code> extension field of the certificate.
   *
   * @return  Basic constraints defined on certificate or null if the certificate does not define the field.
   *
   * @throws  EncodingException  On certificate field parse errors.
   */
  public BasicConstraints readBasicConstraints() throws EncodingException
  {
    try {
      return BasicConstraints.getInstance(read(ExtensionType.BasicConstraints));
    } catch (RuntimeException e) {
      throw new EncodingException("BasicConstraints parse error", e);
    }
  }


  /**
   * Reads the value of the <code>CertificatePolicies</code> extension field of the certificate.
   *
   * @return  List of certificate policies defined on certificate or null if the certificate does not define the field.
   *
   * @throws  EncodingException  On certificate field parse errors.
   */
  public List<PolicyInformation> readCertificatePolicies() throws EncodingException
  {
    final ASN1Encodable data = read(ExtensionType.CertificatePolicies);
    if (data == null) {
      return null;
    }

    try {
      final ASN1Sequence sequence = ASN1Sequence.getInstance(data);
      final List<PolicyInformation> list = new ArrayList<>(sequence.size());
      for (int i = 0; i < sequence.size(); i++) {
        list.add(PolicyInformation.getInstance(sequence.getObjectAt(i)));
      }
      return list;
    } catch (RuntimeException e) {
      throw new EncodingException("PolicyInformation parse error", e);
    }
  }


  /**
   * Reads the value of the <code>SubjectKeyIdentifier</code> extension field of the certificate.
   *
   * @return  Subject key identifier.
   *
   * @throws  EncodingException  On certificate field parse errors.
   */
  public SubjectKeyIdentifier readSubjectKeyIdentifier() throws EncodingException
  {
    try {
      return SubjectKeyIdentifier.getInstance(read(ExtensionType.SubjectKeyIdentifier));
    } catch (RuntimeException e) {
      throw new EncodingException("SubjectKeyIdentifier parse error", e);
    }
  }


  /**
   * Reads the value of the <code>AuthorityKeyIdentifier</code> extension field of the certificate.
   *
   * @return  Authority key identifier.
   *
   * @throws  EncodingException  On certificate field parse errors.
   */
  public AuthorityKeyIdentifier readAuthorityKeyIdentifier() throws EncodingException
  {
    try {
      return AuthorityKeyIdentifier.getInstance(read(ExtensionType.AuthorityKeyIdentifier));
    } catch (RuntimeException e) {
      throw new EncodingException("AuthorityKeyIdentifier parse error", e);
    }
  }


  /**
   * Reads the value of the <code>KeyUsage</code> extension field of the certificate.
   *
   * @return  Key usage data or null if extension field is not defined.
   *
   * @throws  EncodingException  On certificate field parse errors.
   */
  public KeyUsage readKeyUsage() throws EncodingException
  {
    try {
      return KeyUsage.getInstance(read(ExtensionType.KeyUsage));
    } catch (RuntimeException e) {
      throw new EncodingException("KeyUsage parse error", e);
    }
  }


  /**
   * Reads the value of the <code>ExtendedKeyUsage</code> extension field of the certificate.
   *
   * @return  List of supported extended key usages or null if extension is not defined.
   *
   * @throws  EncodingException  On certificate field parse errors.
   */
  public List<KeyPurposeId> readExtendedKeyUsage() throws EncodingException
  {
    final ASN1Encodable data = read(ExtensionType.ExtendedKeyUsage);
    if (data == null) {
      return null;
    }

    try {
      final ASN1Sequence sequence = ASN1Sequence.getInstance(data);
      final List<KeyPurposeId> list = new ArrayList<>(sequence.size());
      for (int i = 0; i < sequence.size(); i++) {
        list.add(KeyPurposeId.getInstance(sequence.getObjectAt(i)));
      }
      return list;
    } catch (RuntimeException e) {
      throw new EncodingException("KeyPurposeId parse error", e);
    }
  }


  /**
   * Reads the value of the <code>CRLDistributionPoints</code> extension field of the certificate.
   *
   * @return  List of CRL distribution points or null if extension is not defined.
   *
   * @throws  EncodingException  On certificate field parse errors.
   */
  public List<DistributionPoint> readCRLDistributionPoints() throws EncodingException
  {
    final ASN1Encodable data = read(ExtensionType.CRLDistributionPoints);
    if (data == null) {
      return null;
    }

    try {
      final ASN1Sequence sequence = ASN1Sequence.getInstance(data);
      final List<DistributionPoint> list = new ArrayList<>(sequence.size());
      for (int i = 0; i < sequence.size(); i++) {
        list.add(DistributionPoint.getInstance(sequence.getObjectAt(i)));
      }
      return list;
    } catch (RuntimeException e) {
      throw new EncodingException("DistributionPoint parse error", e);
    }
  }


  /**
   * Reads the value of the <code>AuthorityInformationAccess</code> extension field of the certificate.
   *
   * @return  List of access descriptions or null if extension is not defined.
   *
   * @throws  EncodingException  On certificate field parse errors.
   */
  public List<AccessDescription> readAuthorityInformationAccess() throws EncodingException
  {
    final ASN1Encodable data = read(ExtensionType.AuthorityInformationAccess);
    if (data == null) {
      return null;
    }

    try {
      final ASN1Sequence sequence = ASN1Sequence.getInstance(data);
      final List<AccessDescription> list = new ArrayList<>(sequence.size());
      for (int i = 0; i < sequence.size(); i++) {
        list.add(AccessDescription.getInstance(sequence.getObjectAt(i)));
      }
      return list;
    } catch (RuntimeException e) {
      throw new EncodingException("AccessDescription parse error", e);
    }
  }
}
