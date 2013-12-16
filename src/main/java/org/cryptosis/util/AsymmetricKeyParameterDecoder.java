package org.cryptosis.util;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.cryptosis.pbe.EncryptionScheme;
import org.cryptosis.pbe.OpenSSLAlgorithm;
import org.cryptosis.pbe.OpenSSLEncryptionScheme;
import org.cryptosis.pbe.PBES1Algorithm;
import org.cryptosis.pbe.PBES1EncryptionScheme;
import org.cryptosis.pbe.PBES2EncryptionScheme;

/**
 * Produces Bouncy Castle {@AsymmetricKeyParameter} objects containing private key data from ASN.1 encoded bytes in
 * DER or PEM format. This class handles encrypted private keys in PKCS#8 format or OpenSSL "traditional" format.
 *
 * @author Marvin S. Addison
 */
public class AsymmetricKeyParameterDecoder implements PrivateKeyDecoder<AsymmetricKeyParameter>
{
  /** {@inheritDoc} */
  @Override
  public AsymmetricKeyParameter decode(final byte[] encoded)
  {
    final byte[] asn1Bytes;
    if (PemUtil.isPem(encoded)) {
      asn1Bytes = PemUtil.decode(encoded);
    } else {
      asn1Bytes = encoded;
    }

    // Assume PKCS#8 and try OpenSSL "traditional" format as backup
    try {
      return PrivateKeyFactory.createKey(asn1Bytes);
    } catch (Exception e) {
      // Ignore error and try OpenSSL format
    }

    final ASN1Object o;
    try {
      o = ASN1Primitive.fromByteArray(asn1Bytes);
    } catch (Exception e) {
      throw new IllegalArgumentException("Invalid encoded key");
    }

    final AsymmetricKeyParameter key;
    if (o instanceof ASN1ObjectIdentifier) {
      // EC private key with named curve in the default OpenSSL format emitted by
      //
      // openssl ecparam -name xxxx -genkey
      //
      // which is the concatenation of the named curve OID and a sequence of 1
      // containing the private point
      final ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(o);
      final int len = asn1Bytes[1];
      final byte[] privatePart = new byte[asn1Bytes.length - len - 2];
      System.arraycopy(asn1Bytes, len + 2, privatePart, 0, privatePart.length);
      final ASN1Sequence seq = ASN1Sequence.getInstance(privatePart);
      final X9ECParameters params = ECUtil.getNamedCurveByOid(oid);
      key = new ECPrivateKeyParameters(
        ASN1Integer.getInstance(seq.getObjectAt(0)).getValue(),
        new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed()));
    } else {
      // OpenSSL "traditional" format is an ASN.1 sequence of key parameters

      // Detect key type based on number and types of parameters:
      // RSA -> {version, mod, pubExp, privExp, prime1, prime2, exp1, exp2, c}
      // DSA -> {version, p, q, g, pubExp, privExp}
      // EC ->  {version, privateKey, parameters, publicKey}
      final ASN1Sequence sequence = ASN1Sequence.getInstance(o);
      if (sequence.size() == 9) {
        // RSA private key
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
          new BigInteger(ASN1OctetString.getInstance(sequence.getObjectAt(1)).getOctets()),
          new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed()));
      } else {
        throw new IllegalArgumentException("Invalid OpenSSL traditional private key format.");
      }
    }
    return key;
  }


  /** {@inheritDoc} */
  @Override
  public AsymmetricKeyParameter decode(final byte[] encrypted, final char[] password)
  {
    if (password == null || password.length == 0) {
      throw new IllegalArgumentException("Password is required for decrypting an encrypted private key.");
    }
    return decode(decryptKey(encrypted, password));
  }


  /**
   * Decrypts an encrypted key in either PKCS#8 or OpenSSL "traditional" format.
   * Both PEM and DER encodings are supported.
   *
   * @param  encrypted  Encoded encrypted key data.
   * @param  password  Password to decrypt key.
   *
   * @return  Decrypted key.
   */
  private byte[] decryptKey(final byte[] encrypted, final char[] password)
  {
    byte[] bytes = encrypted;
    if (PemUtil.isPem(encrypted)) {
      final String pem = new String(encrypted, ByteUtil.ASCII_CHARSET);
      if (pem.contains(PemUtil.PROC_TYPE)) {
        bytes = decryptOpenSSLKey(pem, password);
      } else {
        bytes = decryptPKCS8Key(PemUtil.decode(bytes), password);
      }
    } else {
      bytes = decryptPKCS8Key(bytes, password);
    }
    return bytes;
  }


  /**
   * Decrypts a DER-encoded private key in PKCS#8 format.
   *
   * @param  encrypted  Bytes of DER-encoded encrypted private key.
   * @param  password  Password to decrypt private key.
   *
   * @return  ASN.1 encoded bytes of decrypted key.
   */
  private byte[] decryptOpenSSLKey(final String encrypted, final char[] password)
  {
    final int start = encrypted.indexOf(PemUtil.DEK_INFO);
    final int eol = encrypted.indexOf('\n', start);
    final String[] dekInfo = encrypted.substring(start + 10, eol).split(",");
    final String alg = dekInfo[0];
    final byte[] iv = CodecUtil.hex(dekInfo[1]);
    final byte[] bytes = PemUtil.decode(encrypted);
    return new OpenSSLEncryptionScheme(OpenSSLAlgorithm.fromAlgorithmId(alg), iv, password).decrypt(bytes);
  }


  /**
   * Decrypts a DER-encoded private key in PKCS#8 format.
   *
   * @param  encrypted  Bytes of DER-encoded encrypted private key.
   * @param  password  Password to decrypt private key.
   *
   * @return  ASN.1 encoded bytes of decrypted key.
   */
  private byte[] decryptPKCS8Key(final byte[] encrypted, final char[] password)
  {
    final EncryptionScheme scheme;
    final EncryptedPrivateKeyInfo ki = EncryptedPrivateKeyInfo.getInstance(encrypted);
    final AlgorithmIdentifier alg = ki.getEncryptionAlgorithm();
    if (PKCSObjectIdentifiers.id_PBES2.equals(alg.getAlgorithm())) {
      scheme = new PBES2EncryptionScheme(PBES2Parameters.getInstance(alg.getParameters()), password);
    } else {
      scheme = new PBES1EncryptionScheme(
        PBES1Algorithm.fromOid(alg.getAlgorithm().getId()),
        PBEParameter.getInstance(alg.getParameters()),
        password);
    }
    return scheme.decrypt(ki.getEncryptedData());
  }
}
