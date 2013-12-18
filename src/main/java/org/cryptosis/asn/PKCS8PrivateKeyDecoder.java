package org.cryptosis.asn;

import java.io.IOException;

import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.cryptosis.pbe.EncryptionScheme;
import org.cryptosis.pbe.PBES1Algorithm;
import org.cryptosis.pbe.PBES1EncryptionScheme;
import org.cryptosis.pbe.PBES2EncryptionScheme;

/**
 * Decodes PEM or DER-encoded PKCS#8 private keys.
 *
 * @author Marvin S. Addison
 */
public class PKCS8PrivateKeyDecoder extends AbstractPrivateKeyDecoder<AsymmetricKeyParameter>
{
  /** {@inheritDoc} */
  @Override
  protected byte[] decryptKey(final byte[] encrypted, final char[] password)
  {
    final EncryptionScheme scheme;
    final EncryptedPrivateKeyInfo ki = EncryptedPrivateKeyInfo.getInstance(tryConvertPem(encrypted));
    final AlgorithmIdentifier alg = ki.getEncryptionAlgorithm();
    if (PKCSObjectIdentifiers.id_PBES2.equals(alg.getAlgorithm())) {
      scheme = new PBES2EncryptionScheme(PBES2Parameters.getInstance(alg.getParameters()), password);
    } else {
      scheme = new PBES1EncryptionScheme(
        PBES1Algorithm.fromOid(alg.getAlgorithm().getId()),
        PBEParameter.getInstance(alg.getParameters()),
        password);
    }
    return scheme.decrypt(ki.getEncryptedData());
  }


  /** {@inheritDoc} */
  @Override
  protected AsymmetricKeyParameter decodeASN1(final byte[] encoded)
  {
    try {
      return PrivateKeyFactory.createKey(encoded);
    } catch (IOException e) {
      throw new RuntimeException("ASN.1 decoding error", e);
    }
  }
}
