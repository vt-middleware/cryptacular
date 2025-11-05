/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.pem;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.bouncycastle.util.io.pem.PemHeader;
import org.cryptacular.CryptUtil;
import org.cryptacular.EncodingException;

/**
 * Container for PEM encoded data.
 *
 * @author Middleware Services
 */
public final class PemObject extends org.bouncycastle.util.io.pem.PemObject
{

  /**
   * {@link Descriptor} for this PEM object which includes the RFC governing its format and other relevant data
   * about the data.
   */
  private final Descriptor descriptor;

  /**
   * Generic constructor for object without headers.
   *
   * @param descriptorParam Descriptor on the content (i.e. RFC governing PEM format, type etc.)
   * @param content The binary content of the object.
   */
  public PemObject(final Descriptor descriptorParam, final byte[] content)
  {
    super(
      CryptUtil.assertNotNullArg(descriptorParam, "Descriptor cannot be null").getType(),
      CryptUtil.assertNotNullArg(content, "Content cannot be null"));
    descriptor = descriptorParam;
  }


  /**
   * Generic constructor for object with headers.
   *
   * @param descriptorParam Descriptor on the content (i.e. RFC governing PEM format, type etc.)
   * @param headers A list of PemHeader objects.
   * @param content The binary content of the object.
   */
  public PemObject(final Descriptor descriptorParam, final List<PemHeader> headers, final byte[] content)
  {
    super(
      CryptUtil.assertNotNullArg(descriptorParam, "Descriptor cannot be null").getType(),
      CryptUtil.assertNotNullArg(headers, "Headers cannot be null"),
      CryptUtil.assertNotNullArg(content, "Content cannot be null"));
    descriptor = descriptorParam;
    assertHeadersValid(headers);
  }


  /**
   * Decodes the supplied bytes into a {@link PemObject}.
   *
   * @param encoded to decode
   *
   * @return PEM object
   *
   * @throws EncodingException if the bytes cannot be decoded
   */
  public static PemObject decode(final byte[] encoded)
    throws EncodingException
  {
    final PemParser parser = new PemParser();
    return parser.parse(encoded);
  }


  /**
   * Returns descriptor on PEM object
   *
   * @return {@link Descriptor}
   */
  public Descriptor getDescriptor()
  {
    return descriptor;
  }


  /**
   * Throws an exception if the headers are not according to their governing RFC format.
   *
   * @param headers headers
   */
  private void assertHeadersValid(final List<PemHeader> headers)
  {
    switch (descriptor.getFormat()) {
    case RFC1421:
      assertPemHeaderValid(headers, Constants.RFC1421_SPECIFIERS, Format.RFC1421, false, true);
      break;
    case RFC2440:
      assertPemHeaderValid(headers, Constants.RFC2440_SPECIFIERS, Format.RFC2440, false, false);
      break;
    case RFC4716:
      assertPemHeaderValid(headers, Constants.RFC4716_SPECIFIERS, Format.RFC4716, true, false);
      break;
    case RFC7468:
      throw new IllegalArgumentException("Headers are not allowed in this PEM format specified (RFC 7468)");
    default:
      break;
    }
  }


  /**
   * Checks to make sure a given list of {@link PemHeader} instances the names specified are valid.
   *
   * @param headers headers
   * @param specifiers Set of allowed specifiers/headers
   * @param format RFC format
   * @param allowX Allow specifiers/headers starting with X-
   * @param disregardX Treat specifiers/headers starting with X- as if they do not
   * @throws IllegalArgumentException If header element in the headers list is not valid
   */
  private void assertPemHeaderValid(
    final List<PemHeader> headers,
    final Set<String> specifiers,
    final Format format,
    final boolean allowX,
    final boolean disregardX)
    throws IllegalArgumentException
  {
    for (final PemHeader header : headers) {
      if (header.getName() == null) {
        throw new IllegalArgumentException("Neither a supplied PemHeader nor its name may be null");
      }
      final boolean isXHeader =
        header.getName().toLowerCase(Locale.ROOT).startsWith(Constants.RFC4716_SPECIFIER_PRIVATE_BEGIN_MARKER);
      final String headerName = disregardX && isXHeader ? header.getName().substring(2) : header.getName();
      if (!specifiers.contains(headerName) && !allowX && isXHeader) {
        throw new IllegalArgumentException(
          String.format("Invalid header \"%s\" specified in PEM format (%s)", header.getName(), format.name()));
      }
    }
  }
}
