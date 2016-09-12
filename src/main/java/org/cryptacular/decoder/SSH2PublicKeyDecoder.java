/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.decoder;

import java.math.BigInteger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.cryptacular.EncodingException;

/**
 * Decodes public keys formatted in SSH2 Public Key format RFC 4253 Section 6.6. Public Key Algorithms.
 * Currently RSA and DSS key formats are supported.
 *
 * @author Middleware Services
 */
public class SSH2PublicKeyDecoder implements KeyDecoder<AsymmetricKeyParameter>
{
  /**
   * Represents the current position of the buffer.  This value is set to 0 every time decode is called.
   */
  private int position;

  @Override
  public AsymmetricKeyParameter decode(final byte[] bytes, final Object... args) throws EncodingException
  {
    position = 0;
    final String type = decodeString(bytes);
    switch (type) {
    case "ssh-rsa":
      final BigInteger e = decodeMPInt(bytes);
      final BigInteger m = decodeMPInt(bytes);
      return new RSAKeyParameters(false, m, e);
    case "ssh-dss":
      final BigInteger p = decodeMPInt(bytes);
      final BigInteger q = decodeMPInt(bytes);
      final BigInteger g = decodeMPInt(bytes);
      final BigInteger y = decodeMPInt(bytes);
      return new DSAPublicKeyParameters(y, new DSAParameters(p, q, g));
    default:
      throw new EncodingException("Unsupported SSH2 public key type: " + type);
    }
  }

  /**
   * Decodes a Java String from a string as per RFC 4251 Section 5 using the current
   * position of the bytes buffer
   * @param bytes buffered bytes array to read from
   * @return {@link String} representing string
   */
  private String decodeString(final byte[] bytes)
  {
    int length = decodeUInt32(bytes);
    if (length < 0 || length > 256 * 1024) {
      length = 256 * 1024;
    }
    final String type = new String(bytes, position, length);
    position += length;
    return type;
  }

  /**
   * Decodes a Java int from a uint32 as per RFC 4251 Section 5 using the current
   * position of the bytes buffer
   * @param bytes buffered bytes array to read from
   * @return {@link BigInteger} representing mpint
   */
  private int decodeUInt32(final byte[] bytes)
  {
    return ((bytes[position++] & 0xFF) << 24) | ((bytes[position++] & 0xFF) << 16) |
            ((bytes[position++] & 0xFF) << 8) | (bytes[position++] & 0xFF);
  }

  /**
   * Decodes a Java {@link BigInteger} from mpint as per RFC 4253 Section 6.6 using the current
   * position of the bytes buffer
   * @param bytes buffered bytes array to read from
   * @return {@link BigInteger} representing mpint
   */
  private BigInteger decodeMPInt(final byte[] bytes)
  {
    int length = decodeUInt32(bytes);
    if (length < 0 || length > 8 * 1024) {
      length = 8 * 1024;
    }
    final byte[] bigIntBytes = new byte[length];
    System.arraycopy(bytes, position, bigIntBytes, 0, length);
    position += length;
    return new BigInteger(bigIntBytes);
  }
}
