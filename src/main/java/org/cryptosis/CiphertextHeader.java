package org.cryptosis;

import java.nio.ByteBuffer;

/**
 * Cleartext header prepended to ciphertext providing data required for decryption.
 *
 * @author Marvin S. Addison
 */
public class CiphertextHeader
{
  /** Header nonce field value. */
  private final byte[] nonce;

  /** Header key name field value. */
  private String keyName;

  /** Header length in bytes. */
  private int length;

  public CiphertextHeader(final byte[] nonce)
  {
    this(nonce, null);
  }

  public CiphertextHeader(final byte[] nonce, final String keyName)
  {
    this.nonce = nonce;
    this.length = 8 + nonce.length;
    if (keyName != null) {
      this.length += 4 + keyName.getBytes().length;
      this.keyName = keyName;
    }
  }

  public int getLength()
  {
    return this.length;
  }

  public byte[] getNonce()
  {
    return this.nonce;
  }

  public String getKeyName()
  {
    return this.keyName;
  }

  public byte[] encode()
  {
    ByteBuffer bb = ByteBuffer.allocate(this.length);
    bb.putInt(this.length);
    bb.putInt(nonce.length);
    bb.put(nonce);
    if (keyName != null) {
      final byte[] b = keyName.getBytes();
      bb.putInt(b.length);
      bb.put(b);
    }
    return bb.array();
  }

  public static CiphertextHeader decode(final byte[] data)
  {
    final ByteBuffer bb = ByteBuffer.wrap(data);
    final int length = bb.getInt();
    final byte[] nonce = new byte[bb.getInt()];
    bb.get(nonce);
    String keyName = null;
    if (length > nonce.length + 4) {
      final byte[] b = new byte[bb.getInt()];
      bb.get(b);
      keyName = new String(b);
    }
    return new CiphertextHeader(nonce, keyName);
  }
}
