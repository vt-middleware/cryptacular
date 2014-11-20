/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.security.PublicKey;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.KeyPairUtil;
import org.cryptacular.util.PemUtil;

/**
 * Factory for creating a public key from a PEM-encoded string:
 *
 * <pre>-----BEGIN PUBLIC KEY-----
 MIIBtzCCASsGByqGSM44BAEwggEeAoGBAOulifG+AGGBVGWEjunG4661rydB7eFy
 RfHzbwVAVaPU0H3zFcOY35z1l6Pk4ZANVHq7hCbViJBR7XyrkYKaUcaB0nSPLgg3
 vWWOmvGqhuR6tWRGbz4fyHl1urCRk9mrJum4mAJd3OlLugCyuIqozsYUtvJ5mlGe
 vir1zmxinKd7AhUA7fBEySYP53g7FLOlcEyuhIjvQAECgYBJ9baoGzn0zKpeteC4
 jfbGVuKrFksr2eeY0AFJOeTtyFkCnVqrNnF674eN1RAOwA2tzzhWZ96G0AGux8ah
 mGsNRbj/qaUTDNRWr7BPBIvDd+8LpMin4Cb5j4c/A7uOY+5WxhUm3TNifueBRohw
 h1NnexYQqpclcuTRA/ougLX48gOBhQACgYEA6Tw2khtb1g0vcHu6JRgggWPZVTuj
 /HOH3FyjufsfHogWKrlKebZ6hnQ73qAcEgLLYKctPdCX6wnpXN+BsQGYdTkc0FsU
 NZD4VW5L5kaWRiLVfE8x55wXdMZtXKWqg1vL6aXYZw7RFe9U9Ck+/AG90knThDC+
 xrX2FTDm6uC25rk=
 -----END PUBLIC KEY-----</pre>
 *
 * @author  Middleware Services
 * @see  KeyPairUtil#decodePublicKey(byte[])
 */
public class PemBasedPublicKeyFactoryBean implements FactoryBean<PublicKey>
{

  /** PEM-encoded public key data. */
  private String encodedKey;


  /** Creates a new instance. */
  public PemBasedPublicKeyFactoryBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  pemEncodedKey  PEM-encoded public key data.
   */
  public PemBasedPublicKeyFactoryBean(final String pemEncodedKey)
  {
    setEncodedKey(pemEncodedKey);
  }


  /** @return  PEM-encoded public key data. */
  public String getEncodedKey()
  {
    return encodedKey;
  }


  /**
   * Sets the PEM-encoded public key data.
   *
   * @param  pemEncodedKey  PEM-encoded public key data.
   */
  public void setEncodedKey(final String pemEncodedKey)
  {
    if (!PemUtil.isPem(ByteUtil.toBytes(pemEncodedKey))) {
      throw new IllegalArgumentException("Data is not PEM encoded.");
    }
    this.encodedKey = pemEncodedKey;
  }


  /** {@inheritDoc} */
  @Override
  public PublicKey newInstance()
  {
    return KeyPairUtil.decodePublicKey(PemUtil.decode(encodedKey));
  }
}
