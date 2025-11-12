/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.ssh;

import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.cryptacular.CryptUtil;
import org.cryptacular.EncodingException;
import org.cryptacular.pem.Format;
import org.cryptacular.pem.PemObject;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.CodecUtil;
import org.cryptacular.util.PemUtil;

/**
 * Decodes public keys formatted as described in RFC 4253, Section 6.6, Public Key Algorithms.
 * RSA and DSS key formats are supported.
 *
 * @author Middleware Services
 */
public class SSHPublicKeyDecoder
{

  /**
   * Attempts to infer whether the encoded bytes contain an SSH public key.
   *
   * @param key encoded key as a string
   *
   * @return true if encoding format is probable, false otherwise
   */
  public static boolean isRFC4253EncodedPublicKey(final String key)
  {
    return key != null && key.startsWith("ssh-");
  }

  /**
   * Attempts to infer whether the encoded bytes contain an SSH public key.
   *
   * @param key encoded key as a byte array
   *
   * @return true if encoding format is probable, false otherwise
   */
  public static boolean isRFC4253EncodedPublicKey(final byte[] key)
  {
    if (key == null || key.length - 10 < 1) {
      return false;
    }
    return isRFC4253EncodedPublicKey(new String(key, 0, 10, ByteUtil.ASCII_CHARSET).trim());
  }

  /**
   * Produces an asymmetric key parameter from an encoded representation.
   *
   * @param encoded encoded data
   *
   * @return  Decoded object.
   */
  public AsymmetricKeyParameter decode(final byte[] encoded)
  {
    CryptUtil.assertNotNullArgOr(encoded, v -> v.length == 0, "Bytes cannot be null or empty");
    if (PemUtil.isPem(encoded)) {
      final PemObject pem = PemObject.decode(encoded);
      if (Format.RFC4716.equals(pem.getDescriptor().getFormat())) {
        return decodeInternal(pem.getContent());
      }
      throw new EncodingException("Unsupported SSH public key format: " + pem.getDescriptor().getFormat());
    }
    if (isRFC4253EncodedPublicKey(encoded)) {
      return decode(new String(encoded, ByteUtil.ASCII_CHARSET));
    }
    throw new EncodingException("Unsupported SSH public key format");
  }

  /**
   * Produces an asymmetric key parameter from an encoded representation.
   *
   * @param pubData encoded data
   *
   * @return  Decoded object.
   *
   * @throws  EncodingException  on encoding errors.
   */
  public AsymmetricKeyParameter decode(final String pubData)
  {
    final String[] tokenized =
      CryptUtil.assertNotNullArgOr(
        pubData,
        String::isEmpty,
        "Public data cannot be null or empty").trim().split("\\s+", 2);
    if (tokenized.length < 2) {
      throw new EncodingException("Unsupported SSH public key format");
    }
    return decodeInternal(CodecUtil.b64(tokenized[1]));
  }

  /**
   * Decode the supplied bytes for ssh-rsa and ssh-dss formats.
   *
   * @param encoded to decode
   *
   * @return decoded key
   */
  private AsymmetricKeyParameter decodeInternal(final byte[] encoded)
  {
    CryptUtil.assertNotNullArgOr(encoded, v -> v.length == 0, "Bytes cannot be null or empty");
    final ByteBuffer buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
    final String type = decodeString(buffer);
    switch (type) {
      case "ssh-rsa":
        final BigInteger e = decodeMPInt(buffer);
        final BigInteger m = decodeMPInt(buffer);
        return new RSAKeyParameters(false, m, e);
      case "ssh-dss":
        final BigInteger p = decodeMPInt(buffer);
        final BigInteger q = decodeMPInt(buffer);
        final BigInteger g = decodeMPInt(buffer);
        final BigInteger y = decodeMPInt(buffer);
        return new DSAPublicKeyParameters(y, new DSAParameters(p, q, g));
      default:
        throw new EncodingException("Unsupported SSH2 public key type: " + type);
    }
  }

  /**
   * Decodes a string value per RFC 4251, section 5 using the current position of the byte buffer.
   *
   * @param buffer buffered byte array to read from
   *
   * @return {@link String} representing string
   */
  private String decodeString(final ByteBuffer buffer)
  {
    try {
      int length = buffer.getInt();
      if (length < 0 || length > 256 * 1024) {
        length = 256 * 1024;
      }
      final byte[] string = new byte[length];
      buffer.get(string);
      return new String(string, ByteUtil.ASCII_CHARSET);
    } catch (BufferUnderflowException e) {
      throw new EncodingException("Error decoding ssh key", e);
    }
  }

  /**
   * Decodes a mpint per RFC 4251, section 5 using the current position of the byte buffer.
   *
   * @param buffer buffered byte array to read from
   *
   * @return {@link BigInteger} representing mpint
   */
  private BigInteger decodeMPInt(final ByteBuffer buffer)
  {
    try {
      int length = buffer.getInt();
      if (length < 0 || length > 8 * 1024) {
        length = 8 * 1024;
      }
      final byte[] value = new byte[length];
      buffer.get(value);
      return new BigInteger(value);
    } catch (BufferUnderflowException e) {
      throw new EncodingException("Error decoding ssh key", e);
    }
  }
}
