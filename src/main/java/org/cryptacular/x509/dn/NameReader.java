/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.X500Name;
import org.cryptacular.CryptUtil;

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
    this.certificate = CryptUtil.assertNotNullArg(cert, "Certificate cannot be null.");
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
    CryptUtil.assertNotNullArg(principal, "Principal cannot be null.");
    return readX500Name(X500Name.getInstance(principal.getEncoded()));
  }


  /**
   * Converts the given X.500 name to a list of relative distinguished names that contains the attributes
   * comprising the DN.
   *
   * @param  name  X.500 name.
   *
   * @return  X.500 name as an RDN sequence.
   */
  public static RDNSequence readX500Name(final X500Name name)
  {
    CryptUtil.assertNotNullArg(name, "Name cannot be null.");
    final List<RDN> rdns = new ArrayList<>();
    for (org.bouncycastle.asn1.x500.RDN rdn : name.getRDNs()) {
      final List<Attribute> attrs = new ArrayList<>();
      for (AttributeTypeAndValue tv : rdn.getTypesAndValues()) {
        attrs.add(new Attribute(tv.getType().getId(), tv.getValue().toString()));
      }
      rdns.add(new RDN(new Attributes(attrs)));
    }
    return new RDNSequence(rdns);
  }
}
