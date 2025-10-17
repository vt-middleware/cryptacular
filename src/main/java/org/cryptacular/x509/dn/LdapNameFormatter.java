/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import javax.security.auth.x500.X500Principal;
import org.cryptacular.codec.HexEncoder;

/**
 * Produces a string representation of an X.500 distinguished name using the process described in section 2 of RFC 2253,
 * LADPv3 Distinguished Names.
 *
 * @author  Middleware Services
 */
public class LdapNameFormatter implements NameFormatter
{

  /** Separator character between RDN components. */
  public static final char RDN_SEPARATOR = ',';

  /** Separator character between ATV components in the same RDN element. */
  public static final char ATV_SEPARATOR = '+';

  /** Escape character. */
  public static final char ESCAPE_CHAR = '\\';

  /** String of characters that need to be escaped. */
  public static final String RESERVED_CHARS = ",+\"\\<>;";

  /** Handles hex encoding. */
  private static final HexEncoder ENCODER = new HexEncoder();


  @Override
  public String format(final X500Principal dn)
  {
    final StringBuilder builder = new StringBuilder();
    final RDNSequence sequence = NameReader.readX500Principal(dn);
    int i = 0;
    for (RDN rdn : sequence.backward()) {
      if (i++ > 0) {
        builder.append(RDN_SEPARATOR);
      }

      int j = 0;
      for (Attribute attr : rdn.getAttributes()) {
        if (j++ > 0) {
          builder.append(ATV_SEPARATOR);
        }
        builder.append(attr.getType()).append('=');

        final AttributeType type = attr.getType();
        if (type instanceof StandardAttributeType) {
          escape(attr.getValue(), builder);
        } else {
          encode(attr.getValue(), builder);
        }
      }
    }
    return builder.toString();
  }


  /**
   * Appends the given value to the output with proper character escaping.
   *
   * @param  value  Value to escape.
   * @param  output  String builder where escaped value is written.
   */
  private static void escape(final String value, final StringBuilder output)
  {
    char c = value.charAt(0);
    if (c == ' ' || c == '#') {
      output.append(ESCAPE_CHAR);
    }
    output.append(c);

    final int nmax = value.length() - 1;
    for (int n = 1; n < nmax; n++) {
      c = value.charAt(n);
      if (RESERVED_CHARS.indexOf(c) > -1) {
        output.append(ESCAPE_CHAR);
      }
      output.append(c);
    }
    c = value.charAt(nmax);
    if (c == ' ') {
      output.append(ESCAPE_CHAR);
    }
    output.append(c);
  }


  /**
   * Appends the given value to the output using the HEX encoding method described in section 2.4.
   *
   * @param  value  Value to encode.
   * @param  output  String builder where encoded value is written.
   */
  private static void encode(final String value, final StringBuilder output)
  {
    output.append('#');
    final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    final CharBuffer out = CharBuffer.allocate(bytes.length * 2);
    ENCODER.encode(ByteBuffer.wrap(bytes), out);
    output.append(out.flip());
  }
}
