/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

/**
 * Simple implementation of the X.501 RDNSequence type described in section 4.1.2.4 of RFC 2459.
 *
 * @author  Middleware Services
 */
public class RDNSequence implements Iterable<RDN>
{

  /** Maintains the list/sequence of RDNs. */
  private final List<RDN> rdns = new ArrayList<>(10);


  /**
   * Adds an RDN to the sequence.
   *
   * @param  rdn  RDN to add.
   */
  public void add(final RDN rdn)
  {
    rdns.add(rdn);
  }


  @Override
  public Iterator<RDN> iterator()
  {
    return rdns.iterator();
  }


  /** @return  Iterable that moves backward over the RDN sequence. */
  public Iterable<RDN> backward()
  {
    return
      new Iterable<RDN>() {
      @Override
      public Iterator<RDN> iterator()
      {
        return
          new Iterator<RDN>() {

          /** List iterator. */
          private final ListIterator<RDN> it = rdns.listIterator(rdns.size());

          @Override
          public boolean hasNext()
          {
            return it.hasPrevious();
          }

          @Override
          public RDN next()
          {
            return it.previous();
          }

          @Override
          public void remove()
          {
            throw new UnsupportedOperationException("Remove not supported");
          }
        };
      }
    };
  }


  /**
   * Gets an immutable list of all attributes of the given type. The order of the returned list reflects the ordering of
   * the RDNs and their attributes.
   *
   * @param  type  Attribute type.
   *
   * @return  Non-null list of attributes of given type. An empty list is returned if there are no attributes of the
   *          given type.
   */
  public List<String> getValues(final AttributeType type)
  {
    final List<String> values = new ArrayList<>(rdns.size());
    for (RDN rdn : rdns) {
      values.addAll(rdn.getAttributes().getValues(type));
    }
    return Collections.unmodifiableList(values);
  }


  /**
   * Gets the first value of the given type that appears in the attribute list of any RDN in the sequence.
   *
   * @param  type  Attribute type.
   *
   * @return  Value of first attribute of given type or null if no attributes of given type exist.
   */
  public String getValue(final AttributeType type)
  {
    final List<String> values = getValues(type);
    if (values.size() > 0) {
      return values.get(0);
    }
    return null;
  }

  /**
   * Creates a comma-separated list of TYPE=VALUE tokens from the attributes in the list in order.
   *
   * @return  String representation that resembles an X.509 distinguished name, e.g. <code>CN=foo, OU=Bar, dc=example,
   *          dc=com</code>.
   */
  @Override
  public String toString()
  {
    final StringBuilder builder = new StringBuilder();
    int i = 0;
    for (RDN rdn : this) {
      for (Attribute attr : rdn.getAttributes()) {
        if (i++ > 0) {
          builder.append(", ");
        }
        builder.append(attr.getType()).append('=').append(attr.getValue());
      }
    }
    return builder.toString();
  }
}
