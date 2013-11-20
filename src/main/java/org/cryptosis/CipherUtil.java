package org.cryptosis;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.crypto.SecretKey;

/**
 * Utility class that performs encryption and decryption operations using a block cipher.
 *
 * @author Marvin S. Addison
 */
public final class CipherUtil
{
  /** Default nonce size in bytes. */
  private static final int DEFAULT_NONCE_SIZE = 12;

  /** Mac size in bits. */
  private static final int MAC_SIZE_BITS = 128;

  /** Private constructor of utility class. */
  private CipherUtil() {}

  public static byte[] encrypt(final AEADBlockCipher cipher, final SecretKey key, final byte[] data)
  {
    final byte[] nonce = NonceUtil.nist80038d(DEFAULT_NONCE_SIZE);
    final byte[] header = new CiphertextHeader(nonce).encode();
    cipher.init(true, new AEADParameters(new KeyParameter(key.getEncoded()), MAC_SIZE_BITS, nonce, header));
    return encrypt(new AEADCipherAdapter(cipher), header, data);
  }

  public static byte[] decrypt(final AEADBlockCipher cipher, final SecretKey key, final byte[] data)
  {
    final CiphertextHeader header = CiphertextHeader.decode(data);
    final byte[] nonce = header.getNonce();
    final byte[] hbytes = header.encode();
    cipher.init(false, new AEADParameters(new KeyParameter(key.getEncoded()), MAC_SIZE_BITS, nonce, hbytes));
    return decrypt(new AEADCipherAdapter(cipher), data, header.getLength());
  }

  public static byte[] encrypt(final BlockCipher cipher, final SecretKey key, final byte[] data)
  {
    final byte[] iv = NonceUtil.nist80063a(cipher, key);
    final byte[] header = new CiphertextHeader(iv).encode();
    final PaddedBufferedBlockCipher padded  = new PaddedBufferedBlockCipher(cipher, new PKCS7Padding());
    padded.init(true, new ParametersWithIV(new KeyParameter(key.getEncoded()), iv));
    return encrypt(new PaddedCipherAdapter(padded), header, data);
  }

  public static byte[] decrypt(final BlockCipher cipher, final SecretKey key, final byte[] data)
  {
    final CiphertextHeader header = CiphertextHeader.decode(data);
    final PaddedBufferedBlockCipher padded  = new PaddedBufferedBlockCipher(cipher, new PKCS7Padding());
    padded.init(false, new ParametersWithIV(new KeyParameter(key.getEncoded()), header.getNonce()));
    return decrypt(new PaddedCipherAdapter(padded), data, header.getLength());
  }

  private static byte[] encrypt(final CipherAdapter cipher, final byte[] header, final byte[] data)
  {
    final int outSize = header.length + cipher.getOutputSize(data.length);
    byte[] output = new byte[outSize];
    System.arraycopy(header, 0, output, 0, header.length);
    int outOff = header.length;
    outOff += cipher.processBytes(data, 0, data.length, output, outOff);
    cipher.doFinal(output, outOff);
    cipher.reset();
    return output;
  }

  private static byte[] decrypt(final CipherAdapter cipher, final byte[] data, final int inOff)
  {
    final int len = data.length - inOff;
    final int outSize = cipher.getOutputSize(len);
    final byte[] output = new byte[outSize];
    int outOff = cipher.processBytes(data, inOff, len, output, 0);
    outOff += cipher.doFinal(output, outOff);
    cipher.reset();
    if (outOff < output.length) {
      final byte[] temp = new byte[outOff];
      System.arraycopy(output, 0, temp, 0, outOff);
      return temp;
    }
    return output;
  }

  /** Adapts BC classes with similar methods but no inheritance hierarchy. */
  private static interface CipherAdapter
  {
    int getOutputSize(int len);

    int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff);

    int doFinal(byte[] out, int outOff);

    void reset();
  }

  private static class PaddedCipherAdapter implements CipherAdapter
  {
    private final PaddedBufferedBlockCipher cipher;

    public PaddedCipherAdapter(final PaddedBufferedBlockCipher c)
    {
      this.cipher = c;
    }

    @Override
    public int getOutputSize(final int len)
    {
      return cipher.getOutputSize(len);
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
    {
      return cipher.processBytes(in, inOff, len, out, outOff);
    }

    @Override
    public int doFinal(byte[] out, int outOff)
    {
      try {
        return cipher.doFinal(out, outOff);
      } catch (InvalidCipherTextException e) {
        throw new RuntimeException("Cipher doFinal failed", e);
      }
    }

    @Override
    public void reset()
    {
      this.cipher.reset();
    }
  }

  private static class AEADCipherAdapter implements CipherAdapter
  {
    private final AEADBlockCipher cipher;

    public AEADCipherAdapter(final AEADBlockCipher c)
    {
      this.cipher = c;
    }

    @Override
    public int getOutputSize(final int len)
    {
      return cipher.getOutputSize(len);
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
    {
      return cipher.processBytes(in, inOff, len, out, outOff);
    }

    @Override
    public int doFinal(byte[] out, int outOff)
    {
      try {
        return cipher.doFinal(out, outOff);
      } catch (InvalidCipherTextException e) {
        throw new RuntimeException("Cipher doFinal failed", e);
      }
    }

    @Override
    public void reset()
    {
      this.cipher.reset();
    }
  }
}
