/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.asn;

import org.cryptacular.util.PemUtil;

/**
 * Base class for all private key decoders.
 *
 * @param  <T>  Type produced by decode operation.
 *
 * @author  Middleware Services
 */
public abstract class AbstractPrivateKeyDecoder<T> implements ASN1Decoder<T>
{

  @Override
  public T decode(final byte[] encoded, final Object... args)
  {
    final byte[] asn1Bytes;
    if (args != null && args.length > 0 && args[0] instanceof char[]) {
      asn1Bytes = decryptKey(encoded, (char[]) args[0]);
    } else {
      asn1Bytes = tryConvertPem(encoded);
    }
    return decodeASN1(asn1Bytes);
  }


  /**
   * Tests the given encoded input and converts it to PEM if it is detected,
   * stripping out any header/footer data in the process.
   *
   * @param  input  Encoded data that may be PEM encoded.
   *
   * @return  Decoded data if PEM encoding detected, otherwise original data.
   */
  protected byte[] tryConvertPem(final byte[] input)
  {
    if (PemUtil.isPem(input)) {
      return PemUtil.decode(input);
    }
    return input;
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
  protected abstract byte[] decryptKey(byte[] encrypted, char[] password);


  /**
   * Decodes the given raw ASN.1 encoded data into a private key of the type
   * supported by this class.
   *
   * @param  encoded  Encoded ASN.1 data.
   *
   * @return  Private key object.
   */
  protected abstract T decodeASN1(byte[] encoded);
}
