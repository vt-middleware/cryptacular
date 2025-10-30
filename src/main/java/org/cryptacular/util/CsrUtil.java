/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.cryptacular.CryptUtil;
import org.cryptacular.CryptoException;
import org.cryptacular.EncodingException;
import org.cryptacular.x509.dn.NameReader;
import org.cryptacular.x509.dn.RDNSequence;
import org.cryptacular.x509.dn.StandardAttributeType;

/**
 * PKCS#10 certificate signing request (CSR) utilities.
 *
 * @author Marvin S. Addison
 */
public final class CsrUtil
{
  /** Maps algorithm OIDs onto typical algorithm names like "SHA256withRSA". */
  private static final AlgorithmNameFinder ALG_NAME_FINDER = new DefaultAlgorithmNameFinder();


  /**
   * Private constructor of utility class.
   */
  private CsrUtil() {}

  /**
   * Encodes a PKCS#10 certificate signing request to PEM-encoded string format.
   *
   * @param csr Certificate signing request.
   *
   * @return PEM-encoded CSR.
   *
   * @throws EncodingException on errors writing PEM-encoded data.
   */
  public static String encodeCsr(final PKCS10CertificationRequest csr)
  {
    CryptUtil.assertNotNullArg(csr, "CSR cannot be null");
    final StringWriter writer = new StringWriter();
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
      pemWriter.writeObject(csr);
      pemWriter.close();
      return writer.toString();
    } catch (IOException e) {
      throw new EncodingException("CSR encoding error", e);
    }
  }

  /**
   * Decodes PEM-encoded PKCS#10 certificate signing request into a structured object.
   *
   * @param csr PEM-encoded CSR.
   *
   * @return Decoded CSR.
   *
   * @throws IllegalArgumentException if input does not appear to be PEM-encoded data.
   */
  public static CertificationRequest decodeCsr(final String csr)
  {
    CryptUtil.assertNotNullArg(csr, "CSR cannot be null");
    byte[] csrBytes = csr.getBytes(StandardCharsets.US_ASCII);
    if (!PemUtil.isPem(csrBytes)) {
      throw new IllegalArgumentException("Input is not PEM-encoded as required");
    }
    csrBytes = PemUtil.decode(csrBytes);
    return CertificationRequest.getInstance(csrBytes);
  }

  /**
   * Decodes DER-encoded PKCS#10 certificate signing request into a structured object.
   *
   * @param csr Bytes of a DER-encoded CSR.
   *
   * @return Decoded CSR.
   */
  public static CertificationRequest decodeCsr(final byte[] csr)
  {
    return CertificationRequest.getInstance(CryptUtil.assertNotNullArg(csr, "CSR cannot be null"));
  }

  /**
   * Decodes either a PEM or DER-encoded PKCS#10 certificate signing request from a file into a structured object.
   *
   * @param file File containing PEM or DER-encoded data.
   *
   * @return Decoded CSR.
   */
  public static CertificationRequest readCsr(final File file)
  {
    return readCsr(StreamUtil.makeStream(CryptUtil.assertNotNullArg(file, "File cannot be null")));
  }

  /**
   * Decodes either a PEM or DER-encoded PKCS#10 certificate signing request from a stream into a structured object.
   *
   * @param in Input stream containing PEM or DER-encoded data.
   *
   * @return Decoded CSR.
   */
  public static CertificationRequest readCsr(final InputStream in)
  {
    final byte[] data = StreamUtil.readAll(CryptUtil.assertNotNullArg(in, "Input stream cannot be null"));
    if (PemUtil.isPem(data)) {
      return decodeCsr(PemUtil.decode(data));
    }
    return decodeCsr(data);
  }

  /**
   * Gets all the common names from the subject of the certificate request.
   *
   * @param csr Certificate request.
   *
   * @return List of zero or more common names.
   */
  public static List<String> commonNames(final CertificationRequest csr)
  {
    CryptUtil.assertNotNullArg(csr, "CSR cannot be null");
    final RDNSequence sequence = NameReader.readX500Name(csr.getCertificationRequestInfo().getSubject());
    return sequence.getValues(StandardAttributeType.CommonName);
  }

  /**
   * Gets all subject alternative names mentioned on the certificate request.
   *
   * @param csr Certificate request.
   *
   * @return List of subject alternative names.
   */
  public static List<String> subjectAltNames(final CertificationRequest csr)
  {
    CryptUtil.assertNotNullArg(csr, "CSR cannot be null");
    final List<String> names = new ArrayList<>();
    final ASN1Set attributeSet = csr.getCertificationRequestInfo().getAttributes();
    if (attributeSet == null) {
      return names;
    }
    for (ASN1Encodable item : attributeSet)
    {
      final Attribute attr = Attribute.getInstance(item);
      if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
        final Extensions extensions = Extensions.getInstance(attr.getAttributeValues()[0]);
        final GeneralNames subjAltNames = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        if (subjAltNames != null) {
          for (GeneralName gn : subjAltNames.getNames()) {
            names.add(gn.getName().toString().toLowerCase(Locale.ROOT));
          }
        }
      }
    }
    return names;
  }

  /**
   * Gets the name of the signature algorithm mentioned in the CSR.
   *
   * @param csr Certificate request.
   *
   * @return Signature algorithm name, e.g. "SHA256withRSA"
   */
  public static String sigAlgName(final CertificationRequest csr)
  {
    CryptUtil.assertNotNullArg(csr, "CSR cannot be null");
    return ALG_NAME_FINDER.getAlgorithmName(csr.getSignatureAlgorithm()).replace("WITH", "with");
  }

  /**
   * Gets the size in bits of the public key in the CSR.
   *
   * @param csr Certificate request.
   *
   * @return Public key size in bits.
   *
   * @throws IllegalArgumentException if CSR specifies a key algorithm other than RSA or EC.
   * @throws CryptoException on errors creating a public key from data in the CSR.
   */
  public static int keyLength(final CertificationRequest csr)
  {
    CryptUtil.assertNotNullArg(csr, "CSR cannot be null");
    final AsymmetricKeyParameter pubKeyParam;
    try {
      pubKeyParam = PublicKeyFactory.createKey(
          csr.getCertificationRequestInfo().getSubjectPublicKeyInfo());
    } catch (IOException e) {
      throw new CryptoException("Error creating public key parameters", e);
    }
    final int length;
    if (pubKeyParam instanceof RSAKeyParameters) {
      length = ((RSAKeyParameters) pubKeyParam).getModulus().bitLength();
    } else if (pubKeyParam instanceof ECKeyParameters) {
      length = ((ECPublicKeyParameters) pubKeyParam).getQ().getXCoord().getFieldSize();
    } else {
      throw new IllegalArgumentException("Unsupported key algorithm");
    }
    return length;
  }

  /**
   * Generates a CSR given a key pair, subject DN, and optional subject alternative names.
   *
   * @param keyPair Key pair.
   * @param subjectDN Subject distinguished name, e.g. "CN=host.example.org, DC=example, DC=org".
   * @param subjectAltNames Zero or more DNS subject alternative names.
   *
   * @return PKCS#10 certification request. Use {@link PKCS10CertificationRequest#toASN1Structure()} to get the
   * underlying {@link CertificationRequest} that may be used with other helper methods.
   *
   * @throws IllegalArgumentException if CSR specifies a key algorithm other than RSA or EC.
   * @throws CryptoException on errors generating the CSR from data provided.
   */
  public static PKCS10CertificationRequest generateCsr(
    final KeyPair keyPair, final String subjectDN, final String ... subjectAltNames)
  {
    CryptUtil.assertNotNullArg(keyPair, "Key pair cannot be null");
    CryptUtil.assertNotNullArg(subjectDN, "Subject DN cannot be null");
    final String keyAlg = keyPair.getPublic().getAlgorithm();
    final String sigAlg;
    if ("RSA".equals(keyAlg)) {
      sigAlg = "SHA256withRSA";
    } else if ("EC".equals(keyAlg)) {
      sigAlg = "SHA256withECDSA";
    } else {
      throw new IllegalArgumentException("Unsupported key algorithm");
    }
    final PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
        new X500Principal(subjectDN), keyPair.getPublic());
    if (subjectAltNames != null && subjectAltNames.length > 0) {
      final GeneralNamesBuilder namesBuilder = new GeneralNamesBuilder();
      for (String subjectAltName : subjectAltNames) {
        namesBuilder.addName(new GeneralName(GeneralName.dNSName, subjectAltName));
      }
      final GeneralNames names = namesBuilder.build();
      try {
        final Extension sanExtension = Extension.create(Extension.subjectAlternativeName, false, names);
        p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new Extensions(sanExtension));
      } catch (IOException e) {
        throw new CryptoException("Error adding subject alt names to CSR", e);
      }
    }
    final JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(sigAlg);
    try {
      final ContentSigner signer = csBuilder.build(keyPair.getPrivate());
      return p10Builder.build(signer);
    } catch (OperatorCreationException e) {
      throw new CryptoException("Failed generating CSR", e);
    }
  }
}
