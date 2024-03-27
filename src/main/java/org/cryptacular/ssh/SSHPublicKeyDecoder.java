/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.ssh;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.cryptacular.EncodingException;
import org.cryptacular.KeyDecoder;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.CodecUtil;

/**
 * Decodes public keys formatted as described in RFC 4253, Section 6.6, Public Key Algorithms.
 * RSA and DSS key formats are supported.
 *
 * @author Middleware Services
 */
public class SSHPublicKeyDecoder implements KeyDecoder<AsymmetricKeyParameter>
{
  /**
   * Attempts to infer whether the encoded bytes contain an SSH public key.
   *
   * @param key encoded key as a string
   * @return true if encoding format is probable, false otherwise
   */
  public static boolean isRFC4253EncodedPublicKey(final String key)
  {
    return key.startsWith("ssh-");
  }


  /**
   * Attempts to infer whether the encoded bytes contain an SSH public key.
   *
   * @param key encoded key as a byte array
   * @return true if encoding format is probable, false otherwise
   */
  public static boolean isRFC4253EncodedPublicKey(final byte[] key)
  {
    return isRFC4253EncodedPublicKey(new String(key, 0, 10, ByteUtil.ASCII_CHARSET).trim());
  }

  @Override
  public AsymmetricKeyParameter decode(final byte[] bytes, final Object... args) throws EncodingException
  {
    final ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
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

  public AsymmetricKeyParameter decode(final String pubData)
  {
    final String[] tokenized = pubData.trim().split("\\s+");
    if (tokenized.length < 2) {
      throw new EncodingException("Unsupported SSH public key type");
    }
    return decode(CodecUtil.b64(tokenized[1]));
  }


  /**
   * Decodes a string value per RFC 4251, section 5 using the current position of the byte buffer.
   *
   * @param buffer buffered byte array to read from
   * @return {@link String} representing string
   */
  private String decodeString(final ByteBuffer buffer)
  {
    int length = buffer.getInt();
    if (length < 0 || length > 256 * 1024) {
      length = 256 * 1024;
    }
    final byte[] string = new byte[length];
    buffer.get(string);
    return new String(string);
  }


  /**
   * Decodes a mpint per RFC 4251, section 5 using the current position of the byte buffer.
   *
   * @param buffer buffered byte array to read from
   * @return {@link BigInteger} representing mpint
   */
  private BigInteger decodeMPInt(final ByteBuffer buffer)
  {
    int length = buffer.getInt();
    if (length < 0 || length > 8 * 1024) {
      length = 8 * 1024;
    }
    final byte[] value = new byte[length];
    buffer.get(value);
    return new BigInteger(value);
  }
}
