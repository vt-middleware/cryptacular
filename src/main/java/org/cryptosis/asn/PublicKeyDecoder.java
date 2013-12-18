package org.cryptosis.asn;

import java.io.IOException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.cryptosis.util.PemUtil;

/**
 * Decodes public keys formatted in an X.509 SubjectPublicKeyInfo structure in either PEM or DER encoding.
 *
 * @author Marvin S. Addison
 */
public class PublicKeyDecoder implements ASN1Decoder<AsymmetricKeyParameter>
{
  /** {@inheritDoc} */
  @Override
  public AsymmetricKeyParameter decode(final byte[] encoded, final Object... args)
  {
    try {
      if (PemUtil.isPem(encoded)) {
        return PublicKeyFactory.createKey(PemUtil.decode(encoded));
      }
      return PublicKeyFactory.createKey(encoded);
    } catch (IOException e) {
      throw new RuntimeException("ASN.1 decoding error", e);
    }
  }
}
