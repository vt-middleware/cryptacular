/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.asn;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.cryptacular.EncodingException;
import org.cryptacular.io.pem.PemObject;
import org.cryptacular.ssh.SSHPublicKeyDecoder;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.PemUtil;

/**
 * Decodes public keys formatted in an X.509 SubjectPublicKeyInfo structure in either PEM or DER encoding.
 *
 * @author  Middleware Services
 */
public class PublicKeyDecoder implements ASN1Decoder<AsymmetricKeyParameter>
{

  @Override
  public AsymmetricKeyParameter decode(final byte[] encoded, final Object... args)
  {
    try {
      if (PemUtil.isPem(encoded)) {
        return decodePem(encoded, args);
      } else if (SSHPublicKeyDecoder.isRFC4253EncodedPublicKey(encoded)) {
        return new SSHPublicKeyDecoder().decode(new String(encoded, ByteUtil.ASCII_CHARSET));
      }
      try (ASN1InputStream is = new ASN1InputStream(encoded)) {
        return PublicKeyFactory.createKey(is.readObject().getEncoded());
      }
    } catch (IOException e) {
      throw new EncodingException("ASN.1 decoding error", e);
    }
  }


  /**
   * Decodes PEM formats.
   *
   * @param encoded data.
   * @param args Additional data required to perform decoding.
   *
   * @return Decoded object.
   *
   * @throws EncodingException on encoding errors.
   */
  private AsymmetricKeyParameter decodePem(final byte[] encoded, final Object... args)
          throws EncodingException
  {
    final PemObject pem;
    try {
      pem = PemUtil.read(new BufferedReader(
              new InputStreamReader(new ByteArrayInputStream(encoded))));
    } catch (IllegalArgumentException | IOException ex) {
      throw new EncodingException("Could not parse PEM data", ex);
    }
    if (PemObject.Format.RFC4716.equals(pem.getDescriptor().getFormat())) {
      return new SSHPublicKeyDecoder().decode(pem.getContent(), args);
    }
    try {
      return PublicKeyFactory.createKey(pem.getContent());
    } catch (IOException ex) {
      throw new EncodingException("Could not decode key", ex);
    }
  }
}
