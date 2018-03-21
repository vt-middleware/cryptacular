/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.key;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.cryptacular.EncodingException;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.CodecUtil;
import org.cryptacular.util.PemUtil;

/**
 * Decodes public keys formatted in an X.509 SubjectPublicKeyInfo structure in either PEM or DER encoding.
 * SSH2 public keys are also supported in PEM encoded format as well as the standard SSH2 public key
 * format using RSA and DSA public keys.
 *
 * @author Middleware Services
 */
public class PublicKeyDecoder implements KeyDecoder<AsymmetricKeyParameter>
{

  @Override
  public AsymmetricKeyParameter decode(final byte[] encoded, final Object... args)
  {
    final AsymmetricKeyParameter returnValue;
    try {
      final String encodedString = new String(encoded, 0, 10, ByteUtil.ASCII_CHARSET).trim();
      if (PemUtil.isRFC4716Pem(encoded)) {
        returnValue = new SSH2PublicKeyDecoder().decode(PemUtil.decodeToPem(encoded).getContent());
      } else if (encodedString.startsWith("ssh-")) {
        final String[] tokenized = new String(encoded, 0, encoded.length, ByteUtil.ASCII_CHARSET).trim().split("\\s+");
        if (tokenized.length < 2) {
          throw new EncodingException("Unsupported SSH2 public key type");
        }
        for (int i = 1; i < tokenized.length; i++) {
          if (CodecUtil.isB64(tokenized[i])) {
            return new SSH2PublicKeyDecoder().decode(CodecUtil.b64(tokenized[i]));
          }
        }
        throw new EncodingException("Could not find Base64 encoded public key data in encoded buffer");
      } else if (PemUtil.isValidPem(encoded)) {
        returnValue = PublicKeyFactory.createKey(PemUtil.decodeToPem(encoded).getContent());
      } else {
        returnValue = PublicKeyFactory.createKey(new ASN1InputStream(encoded).readObject().getEncoded());
      }
    } catch (IOException e) {
      throw new EncodingException("Decoding error", e);
    }
    return returnValue;
  }
}
