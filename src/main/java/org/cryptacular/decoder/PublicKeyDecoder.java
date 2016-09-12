/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.decoder;

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
 * SSH2 public keys are also supported in PEM encoded format.
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
      String encodedString = new String(encoded, 0, 10, ByteUtil.ASCII_CHARSET).trim();
      if (PemUtil.isRFC4716Pem(encoded)) {
        returnValue =  new SSH2PublicKeyDecoder().decode(PemUtil.decodeToPem(encoded).getContent());
      } else if (encodedString.startsWith("ssh-")) {
        encodedString = new String(encoded, 0, encoded.length, ByteUtil.ASCII_CHARSET).trim();
        returnValue =  new SSH2PublicKeyDecoder().decode(
                CodecUtil.b64(encodedString.substring(
                        encodedString.indexOf(" ") + 1, encodedString.lastIndexOf(" ") + 1)
                )
        );
      } else if (PemUtil.isValidPem(encoded)) {
        returnValue = PublicKeyFactory.createKey(PemUtil.decodeToPem(encoded).getContent());
      } else {
        returnValue = PublicKeyFactory.createKey(new ASN1InputStream(encoded).readObject().getEncoded());
      }
    } catch (IOException e) {
      throw new EncodingException("ASN.1 decoding error", e);
    }
    return returnValue;
  }
}
