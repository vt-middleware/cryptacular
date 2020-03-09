/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.function.Function;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.cryptacular.util.ByteUtil;

/**
 * Cleartext header prepended to ciphertext providing data required for decryption.
 *
 * <p>Data format:</p>
 *
 * <pre>
     +---------+---------+---+----------+-------+------+
     | Version | KeyName | 0 | NonceLen | Nonce | HMAC |
     +---------+---------+---+----------+-------+------+
     |                                                 |
     +--- 4 ---+--- x ---+ 1 +--- 1 ----+-- y --+- 32 -+
 * </pre>
 *
 * <p>Where fields are defined as follows:</p>
 *
 * <ul>
 *   <li>Version - Header version format as a negative number (4-byte integer). Current version is -2.</li>
 *   <li>KeyName - Symbolic key name encoded as UTF-8 bytes (variable length)</li>
 *   <li>0 - Null byte signifying the end of the symbolic key name</li>
 *   <li>NonceLen - Nonce length in bytes (1-byte unsigned integer)</li>
 *   <li>Nonce - Nonce bytes (variable length)</li>
 *   <li>HMAC - HMAC-256 over preceding fields (32 bytes)</li>
 * </ul>
 *
 * <p>The last two fields provide support for multiple keys at the encryption provider. A common case for multiple
 * keys is key rotation; by tagging encrypted data with a key name, an old key may be retrieved by name to decrypt
 * outstanding data which will be subsequently re-encrypted with a new key.</p>
 *
 * @author  Middleware Services
 */
public class V2CiphertextHeader extends V1CiphertextHeader
{
  /** Header version format. */
  protected static final int VERSION = -2;

  /** Size of HMAC algorithm output in bytes. */
  protected static final int HMAC_SIZE = 32;

  /** Function to resolve a key from a symbolic key name. */
  private Function<String, SecretKey> keyLookup;


  /**
   * Creates a new instance with a nonce and named key.
   *
   * @param  nonce  Nonce bytes.
   * @param  keyName  Key name.
   */
  public V2CiphertextHeader(final byte[] nonce, final String keyName)
  {
    super(nonce, keyName);
    if (keyName == null || keyName.isEmpty()) {
      throw new IllegalArgumentException("Key name is required");
    }
  }

  /**
   * Sets the function to resolve keys from {@link #keyName}.
   *
   * @param  keyLookup  Key lookup function.
   */
  public void setKeyLookup(final Function<String, SecretKey> keyLookup)
  {
    this.keyLookup = keyLookup;
  }


  @Override
  public byte[] encode()
  {
    final SecretKey key = keyLookup != null ? keyLookup.apply(keyName) : null;
    if (key == null) {
      throw new IllegalStateException("Could not resolve secret key to generate header HMAC");
    }
    return encode(key);
  }


  /**
   * Encodes the header into bytes.
   *
   * @param  hmacKey  Key used to generate header HMAC.
   *
   * @return  Byte representation of header.
   */
  public byte[] encode(final SecretKey hmacKey)
  {
    if (hmacKey == null) {
      throw new IllegalArgumentException("Secret key cannot be null");
    }
    final ByteBuffer bb = ByteBuffer.allocate(length);
    bb.order(ByteOrder.BIG_ENDIAN);
    bb.putInt(VERSION);
    bb.put(ByteUtil.toBytes(keyName));
    bb.put((byte) 0);
    bb.put(ByteUtil.toUnsignedByte(nonce.length));
    bb.put(nonce);
    bb.put(hmac(bb.array(), 0, bb.limit() - HMAC_SIZE));
    return bb.array();
  }


  /**
   * @return  Length of this header encoded as bytes.
   */
  protected int computeLength()
  {
    return 4 + ByteUtil.toBytes(keyName).length + 2 + nonce.length + HMAC_SIZE;
  }


  /**
   * Generates an HMAC-256 over the given input byte array.
   *
   * @param  input  Input bytes.
   * @param  offset  Starting position in input byte array.
   * @param  length  Number of bytes in input to consume.
   *
   * @return  HMAC as byte array.
   */
  private static byte[] hmac(final byte[] input, final int offset, final int length)
  {
    final HMac hmac = new HMac(new SHA256Digest());
    final byte[] output = new byte[HMAC_SIZE];
    hmac.update(input, offset, length);
    hmac.doFinal(output, 0);
    return output;
  }
}
