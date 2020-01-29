/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.function.BiConsumer;
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
public class CiphertextHeaderV2 extends CiphertextHeader
{
  /** Header version format. */
  private static final int VERSION = -2;

  /** Size of HMAC algorithm output in bytes. */
  private static final int HMAC_SIZE = 32;

  /** Function to resolve a key from a symbolic key name. */
  private Function<String, SecretKey> keyLookup;


  /**
   * Creates a new instance with a nonce and named key.
   *
   * @param  nonce  Nonce bytes.
   * @param  keyName  Key name.
   */
  public CiphertextHeaderV2(final byte[] nonce, final String keyName)
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
   * Creates a header from encrypted data containing a cleartext header prepended to the start.
   *
   * @param  data  Encrypted data with prepended header data.
   * @param  keyLookup  Function used to look up the secret key from the symbolic key name in the header.
   *
   * @return  Decoded header.
   *
   * @throws  EncodingException  when ciphertext header cannot be decoded.
   */
  public static CiphertextHeaderV2 decode(final byte[] data, final Function<String, SecretKey> keyLookup)
      throws EncodingException
  {
    final ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
    return decodeInternal(
      ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN),
      keyLookup,
      ByteBuffer -> bb.getInt(),
      ByteBuffer -> bb.get(),
      (ByteBuffer, output) -> bb.get(output));
  }


  /**
   * Creates a header from encrypted data containing a cleartext header prepended to the start.
   *
   * @param  input  Input stream that is positioned at the start of ciphertext header data.
   * @param  keyLookup  Function used to look up the secret key from the symbolic key name in the header.
   *
   * @return  Decoded header.
   *
   * @throws  EncodingException  when ciphertext header cannot be decoded.
   * @throws  StreamException  on stream IO errors.
   */
  public static CiphertextHeaderV2 decode(final InputStream input, final Function<String, SecretKey> keyLookup)
      throws EncodingException, StreamException
  {
    return decodeInternal(
      input, keyLookup, ByteUtil::readInt, CiphertextHeaderV2::readByte, CiphertextHeaderV2::readInto);
  }


  /**
   * Internal header decoding routine.
   *
   * @param  <T>  Type of input source.
   * @param  source  Source of header data (input stream or byte buffer).
   * @param  keyLookup  Function to look up key from symbolic key name in header.
   * @param  readIntFn  Function that produces a 4-byte integer from the input source.
   * @param  readByteFn  Function that produces a byte from the input source.
   * @param  readBytesConsumer  Function that fills a byte array from the input source.
   *
   * @return  Decoded header.
   */
  private static <T> CiphertextHeaderV2 decodeInternal(
      final T source,
      final Function<String, SecretKey> keyLookup,
      final Function<T, Integer> readIntFn,
      final Function<T, Byte> readByteFn,
      final BiConsumer<T, byte[]> readBytesConsumer)
  {
    final SecretKey key;
    final String keyName;
    final byte[] nonce;
    final byte[] hmac;
    try {
      final int version = readIntFn.apply(source);
      if (version != VERSION) {
        throw new EncodingException("Unsupported ciphertext header version");
      }
      final ByteArrayOutputStream out = new ByteArrayOutputStream(100);
      byte b = 0;
      int count = 0;
      while ((b = readByteFn.apply(source)) != 0) {
        out.write(b);
        if (out.size() > MAX_KEYNAME_LEN) {
          throw new EncodingException("Bad ciphertext header: maximum nonce length exceeded");
        }
        count++;
      }
      keyName = ByteUtil.toString(out.toByteArray(), 0, count);
      key = keyLookup.apply(keyName);
      if (key == null) {
        throw new IllegalStateException("Symbolic key name mentioned in header was not found");
      }
      final int nonceLen = ByteUtil.toInt(readByteFn.apply(source));
      nonce = new byte[nonceLen];
      readBytesConsumer.accept(source, nonce);
      hmac = new byte[HMAC_SIZE];
      readBytesConsumer.accept(source, hmac);
    } catch (IndexOutOfBoundsException | BufferUnderflowException e) {
      throw new EncodingException("Bad ciphertext header");
    }
    final CiphertextHeaderV2 header = new CiphertextHeaderV2(nonce, keyName);
    final byte[] encoded = header.encode(key);
    if (!arraysEqual(hmac, 0, encoded, encoded.length - HMAC_SIZE, HMAC_SIZE)) {
      throw new EncodingException("Ciphertext header HMAC verification failed");
    }
    header.setKeyLookup(keyLookup);
    return header;
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


  /**
   * Read <code>output.length</code> bytes from the input stream into the output buffer.
   *
   * @param  input  Input stream.
   * @param  output  Output buffer.
   *
   * @throws  StreamException  on stream IO errors.
   */
  private static void readInto(final InputStream input, final byte[] output)
  {
    try {
      input.read(output);
    } catch (IOException e) {
      throw new StreamException(e);
    }
  }


  /**
   * Read a single byte from the input stream.
   *
   * @param  input  Input stream.
   *
   * @return  Byte read from input stream.
   */
  private static byte readByte(final InputStream input)
  {
    try {
      return (byte) input.read();
    } catch (IOException e) {
      throw new StreamException(e);
    }
  }


  /**
   * Determines if two byte array ranges are equal bytewise.
   *
   * @param  a  First array to compare.
   * @param  aOff  Offset into first array.
   * @param  b  Second array to compare.
   * @param  bOff  Offset into second array.
   * @param  length  Number of bytes to compare.
   *
   * @return  True if every byte in the given range is equal, false otherwise.
   */
  private static boolean arraysEqual(final byte[] a, final int aOff, final byte[] b, final int bOff, final int length)
  {
    if (length + aOff > a.length || length + bOff > b.length) {
      return false;
    }
    for (int i = 0; i < length; i++) {
      if (a[i + aOff] != b[i + bOff]) {
        return false;
      }
    }
    return true;
  }
}
