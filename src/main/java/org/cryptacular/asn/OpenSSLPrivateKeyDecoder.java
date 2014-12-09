/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.asn;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
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
import org.cryptacular.pbe.OpenSSLAlgorithm;
import org.cryptacular.pbe.OpenSSLEncryptionScheme;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.CodecUtil;
import org.cryptacular.util.PemUtil;

/**
 * Decrypts PEM-encoded OpenSSL "traditional" format private keys.
 *
 * @author  Middleware Services
 */
public class OpenSSLPrivateKeyDecoder
  extends AbstractPrivateKeyDecoder<AsymmetricKeyParameter>
{

  @Override
  protected byte[] decryptKey(final byte[] encrypted, final char[] password)
  {
    final String pem = new String(encrypted, ByteUtil.ASCII_CHARSET);
    final int start = pem.indexOf(PemUtil.DEK_INFO);
    final int eol = pem.indexOf('\n', start);
    final String[] dekInfo = pem.substring(start + 10, eol).split(",");
    final String alg = dekInfo[0];
    final byte[] iv = CodecUtil.hex(dekInfo[1]);
    final byte[] bytes = PemUtil.decode(encrypted);
    return
      new OpenSSLEncryptionScheme(
        OpenSSLAlgorithm.fromAlgorithmId(alg),
        iv,
        password).decrypt(bytes);
  }


  @Override
  protected AsymmetricKeyParameter decodeASN1(final byte[] encoded)
  {
    final ASN1Object o;
    try {
      o = ASN1Primitive.fromByteArray(encoded);
    } catch (Exception e) {
      throw new IllegalArgumentException("Invalid encoded key");
    }

    final AsymmetricKeyParameter key;
    if (o instanceof ASN1ObjectIdentifier) {
      // EC private key with named curve in the default OpenSSL format emitted
      // by
      //
      // openssl ecparam -name xxxx -genkey
      //
      // which is the concatenation of the named curve OID and a sequence of 1
      // containing the private point
      final ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(o);
      final int len = encoded[1];
      final byte[] privatePart = new byte[encoded.length - len - 2];
      System.arraycopy(encoded, len + 2, privatePart, 0, privatePart.length);

      final ASN1Sequence seq = ASN1Sequence.getInstance(privatePart);
      final X9ECParameters params = ECUtil.getNamedCurveByOid(oid);
      key = new ECPrivateKeyParameters(
        ASN1Integer.getInstance(seq.getObjectAt(0)).getValue(),
        new ECDomainParameters(
          params.getCurve(),
          params.getG(),
          params.getN(),
          params.getH(),
          params.getSeed()));
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
        final X9ECParameters params = X9ECParameters.getInstance(
          ASN1TaggedObject.getInstance(sequence.getObjectAt(2)).getObject());
        key = new ECPrivateKeyParameters(
          new BigInteger(
            ASN1OctetString.getInstance(sequence.getObjectAt(1)).getOctets()),
          new ECDomainParameters(
            params.getCurve(),
            params.getG(),
            params.getN(),
            params.getH(),
            params.getSeed()));
      } else {
        throw new IllegalArgumentException(
          "Invalid OpenSSL traditional private key format.");
      }
    }
    return key;
  }
}
