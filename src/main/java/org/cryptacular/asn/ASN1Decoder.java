/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.asn;

import org.cryptacular.KeyDecoder;

/**
 * Strategy interface for converting encoded ASN.1 bytes to an object.
 *
 * @param  <T>  Type of object to produce on decode.
 *
 * @author  Middleware Services
 */
public interface ASN1Decoder<T> extends KeyDecoder<T>
{
}
