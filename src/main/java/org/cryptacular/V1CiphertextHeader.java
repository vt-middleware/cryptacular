/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.cryptacular.util.ByteUtil;

/**
 * Cleartext header prepended to ciphertext providing data required for decryption.
 *
 * <p>Data format:</p>
 *
 * <pre>
     +-----+----------+-------+------------+---------+
     | Len | NonceLen | Nonce | KeyNameLen | KeyName |
     +-----+----------+-------+------------+---------+
 * </pre>
 *
 * <p>Where fields are defined as follows:</p>
 *
 * <ul>
 *   <li>Len - Total header length in bytes (4-byte integer)</li>
 *   <li>NonceLen - Nonce length in bytes (4-byte integer)</li>
 *   <li>Nonce - Nonce bytes (variable length)</li>
 *   <li>KeyNameLen (OPTIONAL) - Key name length in bytes (4-byte integer)</li>
 *   <li>KeyName (OPTIONAL) - Key name encoded as bytes in platform-specific encoding (variable length)</li>
 * </ul>
 *
 * <p>The last two fields are optional and provide support for multiple keys at the encryption provider. A common case
 * for multiple keys is key rotation; by tagging encrypted data with a key name, an old key may be retrieved by name to
 * decrypt outstanding data which will be subsequently re-encrypted with a new key.</p>
 *
 * @author  Middleware Services
 */
public class V1CiphertextHeader implements CiphertextHeader
{
  /** Maximum nonce length in bytes. */
  protected static final int MAX_NONCE_LEN = 255;

  /** Maximum key name length in bytes. */
  protected static final int MAX_KEYNAME_LEN = 500;

  /** Header nonce field value. */
  protected final byte[] nonce;

  /** Header key name field value. */
  protected String keyName;

  /** Header length in bytes. */
  protected int length;


  /**
   * Creates a new instance with only a nonce.
   *
   * @param  nonce  Nonce bytes.
   */
  public V1CiphertextHeader(final byte[] nonce)
  {
    this(nonce, null);
  }


  /**
   * Creates a new instance with a nonce and named key.
   *
   * @param  nonce  Nonce bytes.
   * @param  keyName  Key name.
   */
  public V1CiphertextHeader(final byte[] nonce, final String keyName)
  {
    if (nonce.length > MAX_NONCE_LEN) {
      throw new IllegalArgumentException("Nonce exceeds size limit in bytes (" + MAX_NONCE_LEN + ")");
    }
    if (keyName != null) {
      if (ByteUtil.toBytes(keyName).length > MAX_KEYNAME_LEN) {
        throw new IllegalArgumentException("Key name exceeds size limit in bytes (" + MAX_KEYNAME_LEN + ")");
      }
    }
    this.nonce = nonce;
    this.keyName = keyName;
    length = computeLength();
  }

  /**
   * Gets the header length in bytes.
   *
   * @return  Header length in bytes.
   */
  @Override
  public int getLength()
  {
    return this.length;
  }

  /**
   * Gets the bytes of the nonce/IV.
   *
   * @return  Nonce bytes.
   */
  @Override
  public byte[] getNonce()
  {
    return this.nonce;
  }

  /**
   * Gets the encryption key name stored in the header.
   *
   * @return  Encryption key name.
   */
  @Override
  public String getKeyName()
  {
    return this.keyName;
  }


  /**
   * Encodes the header into bytes.
   *
   * @return  Byte representation of header.
   */
  @Override
  public byte[] encode()
  {
    final ByteBuffer bb = ByteBuffer.allocate(length);
    bb.order(ByteOrder.BIG_ENDIAN);
    bb.putInt(length);
    bb.putInt(nonce.length);
    bb.put(nonce);
    if (keyName != null) {
      final byte[] b = keyName.getBytes();
      bb.putInt(b.length);
      bb.put(b);
    }
    return bb.array();
  }


  /**
   * @return  Length of this header encoded as bytes.
   */
  protected int computeLength()
  {
    int len = 8 + nonce.length;
    if (keyName != null) {
      len += 4 + keyName.getBytes().length;
    }
    return len;
  }
}
