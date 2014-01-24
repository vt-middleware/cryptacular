/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * Reads X.509 subject and issuer DNs as a raw sequence of attributes to
 * facilitate precise handling of name parsing.
 *
 * @author  Middleware Services
 */
public class NameReader
{

  /** Certificate to read. */
  private final X509Certificate certificate;


  /**
   * Creates a new instance to support reading subject and issuer information on
   * the given certificate.
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
   * @return  List of type/value attributes.
   */
  public Attributes readSubject()
  {
    return readX500Principal(certificate.getSubjectX500Principal());
  }


  /**
   * Reads the issuer field from the certificate.
   *
   * @return  List of type/value attributes.
   */
  public Attributes readIssuer()
  {
    return readX500Principal(certificate.getIssuerX500Principal());
  }


  /**
   * Converts the given X.500 principal to a list of type/value attributes.
   *
   * @param  principal  Principal to convert.
   *
   * @return  List of type/value attributes.
   */
  public static Attributes readX500Principal(final X500Principal principal)
  {
    final X500Name name = X500Name.getInstance(principal.getEncoded());
    final Attributes attributes = new Attributes();
    for (RDN rdn : name.getRDNs()) {
      for (AttributeTypeAndValue tv : rdn.getTypesAndValues()) {
        attributes.add(tv.getType().getId(), tv.getValue().toString());
      }
    }
    return attributes;
  }
}
