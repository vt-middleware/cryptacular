/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.asn;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.cryptacular.EncodingException;
import org.cryptacular.util.PemUtil;

/**
 * Decodes public keys formatted in an X.509 SubjectPublicKeyInfo structure in either PEM or DER encoding.
 *
 * @deprecated Use {@link org.cryptacular.key.PublicKeyDecoder}
 * @author  Middleware Services
 */
@Deprecated
public class PublicKeyDecoder implements ASN1Decoder<AsymmetricKeyParameter>
{

  @Override
  public AsymmetricKeyParameter decode(final byte[] encoded, final Object... args)
  {
    try {
      if (PemUtil.isPem(encoded)) {
        return PublicKeyFactory.createKey(PemUtil.decode(encoded));
      }
      return PublicKeyFactory.createKey(new ASN1InputStream(encoded).readObject().getEncoded());
    } catch (IOException e) {
      throw new EncodingException("ASN.1 decoding error", e);
    }
  }
}
