/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * Reads X.509 subject and issuer DNs as a raw sequence of attributes to facilitate precise handling of name parsing.
 *
 * @author  Middleware Services
 */
public class NameReader
{

  /** Certificate to read. */
  private final X509Certificate certificate;


  /**
   * Creates a new instance to support reading subject and issuer information on the given certificate.
   *
   * @param  cert  Certificate to read.
   */
  public NameReader(final X509Certificate cert)
  {
    if (cert == null) {
      throw new IllegalArgumentException("Certificate cannot be null.");
    }
    this.certificate = cert;
  }


  /**
   * Reads the subject field from the certificate.
   *
   * @return  Subject DN as an RDN sequence.
   */
  public RDNSequence readSubject()
  {
    return readX500Principal(certificate.getSubjectX500Principal());
  }


  /**
   * Reads the issuer field from the certificate.
   *
   * @return  Issuer DN as an RDN sequence.
   */
  public RDNSequence readIssuer()
  {
    return readX500Principal(certificate.getIssuerX500Principal());
  }


  /**
   * Converts the given X.500 principal to a list of relative distinguished names that contains the attributes
   * comprising the DN.
   *
   * @param  principal  Principal to convert.
   *
   * @return  X500 principal as an RDN sequence.
   */
  public static RDNSequence readX500Principal(final X500Principal principal)
  {
    final X500Name name = X500Name.getInstance(principal.getEncoded());
    final RDNSequence sequence = new RDNSequence();
    for (org.bouncycastle.asn1.x500.RDN rdn : name.getRDNs()) {
      final Attributes attributes = new Attributes();
      for (AttributeTypeAndValue tv : rdn.getTypesAndValues()) {
        attributes.add(tv.getType().getId(), tv.getValue().toString());
      }
      sequence.add(new RDN(attributes));
    }
    return sequence;
  }
}
