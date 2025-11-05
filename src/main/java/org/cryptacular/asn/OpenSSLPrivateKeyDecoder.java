/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.asn;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.cryptacular.EncodingException;
import org.cryptacular.pbe.OpenSSLAlgorithm;
import org.cryptacular.pbe.OpenSSLEncryptionScheme;
import org.cryptacular.pem.Constants;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.CodecUtil;
import org.cryptacular.util.PemUtil;

/**
 * Decrypts PEM-encoded OpenSSL "traditional" format private keys.
 *
 * @author  Middleware Services
 */
public class OpenSSLPrivateKeyDecoder extends AbstractPrivateKeyDecoder<AsymmetricKeyParameter>
{

  @Override
  protected byte[] decryptKey(final byte[] encrypted, final char[] password)
  {
    final String pem = new String(encrypted, ByteUtil.ASCII_CHARSET);
    final int start = pem.indexOf(Constants.RFC1421_HEADER_FIELD_DEK_INFO);
    final int eol = pem.indexOf('\n', start);
    final String[] dekInfo = pem.substring(start + 10, eol).split(",");
    final String alg = dekInfo[0];
    final byte[] iv = CodecUtil.hex(dekInfo[1]);
    final byte[] bytes = PemUtil.decode(encrypted);
    return new OpenSSLEncryptionScheme(OpenSSLAlgorithm.fromAlgorithmId(alg), iv, password).decrypt(bytes);
  }


  @Override
  protected AsymmetricKeyParameter decodeASN1(final byte[] encoded)
  {
    final AsymmetricKeyParameter key;
    try (ASN1InputStream stream = new ASN1InputStream(encoded)) {
      final ASN1Object o;
      try {
        o = stream.readObject();
      } catch (Exception e) {
        throw new EncodingException("Invalid encoded key", e);
      }

      if (o instanceof ASN1ObjectIdentifier) {
        // EC private key with named curve in the default OpenSSL format emitted
        // by openssl ecparam -name xxxx -genkey
        try {
          key = parseECPrivateKey(ASN1Sequence.getInstance(stream.readObject()));
        } catch (Exception e) {
          throw new EncodingException("Invalid encoded key", e);
        }
      } else {
        // OpenSSL "traditional" format is an ASN.1 sequence of key parameters

        // Detect key type based on number and types of parameters:
        // RSA -> {version, mod, pubExp, privExp, prime1, prime2, exp1, exp2, c}
        // DSA -> {version, p, q, g, pubExp, privExp}
        // EC ->  {version, privateKey, parameters, publicKey}
        final ASN1Sequence sequence = ASN1Sequence.getInstance(o);
        if (sequence.size() == 9) {
          // RSA private certificate key
          key = new RSAPrivateCrtKeyParameters(
            ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue(),
            ASN1Integer.getInstance(sequence.getObjectAt(2)).getValue(),
            ASN1Integer.getInstance(sequence.getObjectAt(3)).getValue(),
            ASN1Integer.getInstance(sequence.getObjectAt(4)).getValue(),
            ASN1Integer.getInstance(sequence.getObjectAt(5)).getValue(),
            ASN1Integer.getInstance(sequence.getObjectAt(6)).getValue(),
            ASN1Integer.getInstance(sequence.getObjectAt(7)).getValue(),
            ASN1Integer.getInstance(sequence.getObjectAt(8)).getValue());
        } else if (sequence.size() == 6) {
          // DSA private key
          key = new DSAPrivateKeyParameters(
            ASN1Integer.getInstance(sequence.getObjectAt(5)).getValue(),
            new DSAParameters(
              ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue(),
              ASN1Integer.getInstance(sequence.getObjectAt(2)).getValue(),
              ASN1Integer.getInstance(sequence.getObjectAt(3)).getValue()));
        } else if (sequence.size() == 4) {
          // EC private key with explicit curve
          key = parseECPrivateKey(sequence);
        } else {
          throw new EncodingException("Invalid OpenSSL traditional private key format.");
        }
      }
    } catch (IOException e) {
      throw new EncodingException("Unexpected IO error", e);
    }
    return key;
  }


  /**
   * Parses an EC private key as defined in RFC 5915.
   * <pre>
   *      ECPrivateKey ::= SEQUENCE {
   *        version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
   *        privateKey     OCTET STRING,
   *        parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
   *        publicKey  [1] BIT STRING OPTIONAL
   *      }
   * </pre>
   *
   * @param  seq  ASN1 sequence to parse
   *
   * @return  EC private key
   */
  private ECPrivateKeyParameters parseECPrivateKey(final ASN1Sequence seq)
  {
    final ASN1TaggedObject asn1Params = ASN1TaggedObject.getInstance(seq.getObjectAt(2));
    final X9ECParameters params;
    if (asn1Params.getBaseObject() instanceof ASN1ObjectIdentifier) {
      params = ECUtil.getNamedCurveByOid(ASN1ObjectIdentifier.getInstance(asn1Params.getBaseObject()));
    } else {
      params = X9ECParameters.getInstance(asn1Params.getBaseObject());
    }
    return new ECPrivateKeyParameters(
      new BigInteger(1, ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets()),
      new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed()));
  }
}
