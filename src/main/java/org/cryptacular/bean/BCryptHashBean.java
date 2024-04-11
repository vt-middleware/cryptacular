/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.generators.BCrypt;
import org.cryptacular.CryptoException;
import org.cryptacular.StreamException;
import org.cryptacular.codec.Base64Decoder;
import org.cryptacular.codec.Base64Encoder;
import org.cryptacular.codec.Decoder;
import org.cryptacular.codec.Encoder;
import org.cryptacular.util.ByteUtil;

/**
 * {@link HashBean} implementation that uses the <em>bcrypt</em> algorithm for hashing. Hash strings of the following
 * format are supported:
 * <br>
 * <code>
 *   $2n$cost$xxxxxxxxxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
 *
 *   where:
 *     n is an optional bcrypt algorithm version (typically "a" or "b")
 *     4 &le; cost &le; 31
 *     x is 22 characters of encoded salt
 *     y is 31 characters of encoded hash bytes
 * </code>
 * <p>
 * The encoding for salt and hash bytes is a variant of base-64 encoding without padding in the following alphabet:
 * </p>
 * <br>
 * <code>./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789</code>
 *
 * @author  Middleware Services
 */
public class BCryptHashBean implements HashBean<String>
{
  /** Custom base-64 alphabet. */
  private static final String ALPHABET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  /** BCrypt cost factor in the range [4, 31]. Default value is {@value}. */
  private int cost = 12;

  /** BCrypt version used when computing hashes. Default value is {@value}. */
  private String version = "2b";


  /** Creates a new instance. */
  public BCryptHashBean() {}


  /**
   * Creates a new instance that uses the given cost factor when hashing.
   *
   * @param costFactor BCrypt cost in the range [4, 31].
   */
  public BCryptHashBean(final int costFactor)
  {
    setCost(costFactor);
  }


  /**
   * Sets the bcrypt cost factor.
   *
   * @param costFactor BCrypt cost in the range [4, 31].
   */
  public void setCost(final int costFactor)
  {
    if (costFactor < 4 || costFactor > 31) {
      throw new IllegalArgumentException("Cost must be in the range [4, 31].");
    }
    cost = costFactor;
  }


  /**
   * Sets the bcrypt version.
   *
   * @param  ver  Bcrypt version, e.g. "2b"
   */
  public void setVersion(final String ver)
  {
    if (!ver.startsWith("2") && ver.length() <= 2) {
      throw new IllegalArgumentException("Invalid version: " + ver);
    }
    version = ver;
  }

  /**
   * Compute a bcrypt hash of the form <code>$2n$cost$xxxxxxxxxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy</code>
   * given a salt and a password.
   * @param  data  A 2-element array containing salt and password. The salt may be encoded per the bcrypt standard
   *               or raw bytes.
   *
   * @return An encoded bcrypt hash, <code>yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy</code> in the specification above.
   *
   * @throws CryptoException on bcrypt algorithm errors.
   */
  @Override
  public String hash(final Object... data) throws CryptoException
  {
    if (data.length != 2) {
      throw new IllegalArgumentException("Expected exactly two elements in data array but got " + data.length);
    }
    return encode(BCrypt.generate(password(version, data[1]), salt(data[0]), cost), 23);
  }


  /**
   * Compares a bcrypt hash of the form <code>$2n$cost$xxxxxxxxxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy</code>
   * with the computed hash from the given password. The bcrypt algorithm parameters are derived from the reference
   * bcrypt hash string.
   *
   * @param  data  A 1-element array containing password.
   *
   * @return True if the computed hash is exactly equal to the reference hash, false otherwise.
   *
   * @throws CryptoException on bcrypt algorithm errors.
   */
  @Override
  public boolean compare(final String hash, final Object... data) throws CryptoException, StreamException
  {
    if (data.length != 1) {
      throw new IllegalArgumentException("Expected exactly one element in data array but got " + data.length);
    }
    final BCryptParameters params = new BCryptParameters(hash);
    final byte[] computed = BCrypt.generate(password(params.getVersion(), data[0]), params.getSalt(), params.getCost());
    for (int i = 0; i < 23; i++) {
      if (params.getHash()[i] != computed[i]) {
        return false;
      }
    }
    return true;
  }


  /**
   * Encodes an input byte array into a string using the configured encoder.
   *
   * @param  bytes  Input bytes to encode.
   * @param  length  Number of bytes of input to encode.
   *
   * @return  Input encoded as a string.
   */
  private static String encode(final byte[] bytes, final int length)
  {
    final Encoder encoder = new Base64Encoder.Builder().setAlphabet(ALPHABET).setPadding(false).build();
    // Only want 184 bits (23 bytes) of the output
    final ByteBuffer input = ByteBuffer.wrap(bytes, 0, length);
    final CharBuffer output = CharBuffer.allocate(encoder.outputSize(length));
    encoder.encode(input, output);
    encoder.finalize(output);
    return output.flip().toString();
  }


  /**
   * Decodes an input string into a byte array using the configured decoder.
   *
   * @param  input  Input string to decode.
   * @param  length  Desired output size in bytes.
   *
   * @return  Input decoded as a byte array.
   */
  private static byte[] decode(final String input, final int length)
  {
    final Decoder decoder = new Base64Decoder.Builder().setAlphabet(ALPHABET).setPadding(false).build();
    final ByteBuffer output = ByteBuffer.allocate(decoder.outputSize(input.length()));
    decoder.decode(CharBuffer.wrap(input), output);
    decoder.finalize(output);
    output.flip();
    if (output.limit() != length) {
      throw new IllegalArgumentException("Input is not of the expected size: " + output.limit() + "!=" + length);
    }
    return ByteUtil.toArray(output);
  }


  /**
   * Converts an input object into a salt as an array of bytes.
   *
   * @param  data  Input salt as a byte array or encoded string.
   *
   * @return  Salt as byte array.
   */
  private static byte[] salt(final Object data)
  {
    if (data instanceof byte[]) {
      return (byte[]) data;
    } else if (data instanceof String) {
      return decode((String) data, 16);
    }
    throw new IllegalArgumentException("Expected byte array or base-64 string.");
  }


  /**
   * Converts an input object into a password as an array of UTF-8 bytes. A null terminator is added if the supplied
   * data does not end with one.
   *
   * @param  version  Bcrypt version, e.g. "2a".
   * @param  data  Input password.
   *
   * @return  Null terminated password as UTF-8 byte array.
   */
  private static byte[] password(final String version, final Object data)
  {
    if (data instanceof byte[]) {
      final byte[] origData = (byte[]) data;
      final byte[] newData;
      if (origData[origData.length - 1] != 0x00) {
        newData = new byte[origData.length + 1];
        System.arraycopy(origData, 0, newData, 0, origData.length);
        newData[newData.length - 1] = 0x00;
      } else {
        newData = origData;
      }
      return newData;
    }
    final StringBuilder sb = new StringBuilder();
    if (data instanceof char[]) {
      sb.append((char[]) data);
    } else if (data instanceof String) {
      sb.append((String) data);
    } else {
      throw new IllegalArgumentException("Expected byte array or string.");
    }
    if (sb.charAt(sb.length() - 1) != '\0') {
      // Version 2a and later requires null terminator on password
      sb.append('\0');
    }
    return sb.toString().getBytes(StandardCharsets.UTF_8);
  }


  /**
   * Handles encoding and decoding a bcrypt hash of the form
   * <code>$2n$cost$xxxxxxxxxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy</code>.
   */
  public static class BCryptParameters
  {
    /** bcrypt version. */
    private final String version;

    /** bcrypt cost. */
    private final int cost;

    /** bcrypt salt. */
    private final byte[] salt;

    /** bcrypt hash. */
    private final byte[] hash;


    /**
     * Decodes bcrypt parameters from a string.
     *
     * @param  bCryptString  bcrypt hash of the form
     *                       <code>$2n$cost$xxxxxxxxxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy</code>
     */
    protected BCryptParameters(final String bCryptString)
    {
      if (!bCryptString.startsWith("$2")) {
        throw new IllegalArgumentException("Expected bcrypt hash of the form $2n$cost$salthash");
      }
      final String[] parts = bCryptString.split("\\$");
      if (parts.length != 4) {
        throw new IllegalArgumentException("Invalid bcrypt hash");
      }
      version = parts[1];
      cost = Integer.parseInt(parts[2]);
      salt = decode(parts[3].substring(0, 22), 16);
      hash = decode(parts[3].substring(22), 23);
    }


    /** @return  bcrypt version. */
    public String getVersion()
    {
      return version;
    }


    /** @return  bcrypt cost in the range [4, 31]. */
    public int getCost()
    {
      return cost;
    }


    /** @return  bcrypt salt. */
    public byte[] getSalt()
    {
      return salt;
    }


    /** @return  bcrypt hash. */
    public byte[] getHash()
    {
      return hash;
    }


    /**
     * Produces an encoded bcrypt hash string from bcrypt parameter data.
     *
     * @return  Bcrypt hash of the form <code>$2n$cost$xxxxxxxxxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy</code>.
     */
    public String encode()
    {
      return '$' + version + '$' + cost + '$' + BCryptHashBean.encode(salt, 16) + BCryptHashBean.encode(hash, 23);
    }


    /**
     * Produces an encoded bcrypt hash string from bcrypt parameters and a provided hash string.
     *
     * @param  hash  Encoded bcrypt hash bytes; e.g. the value produced from {@link #hash(Object...)}.
     *
     * @return  Bcrypt hash of the form <code>$2n$cost$xxxxxxxxxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy</code>.
     */
    public String encode(final String hash)
    {
      return '$' + version + '$' + cost + '$' + BCryptHashBean.encode(salt, 16) + hash;
    }
  }
}
