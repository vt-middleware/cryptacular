/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Ordered list of {@link Attribute}s.
 *
 * @author  Middleware Services
 */
public class Attributes implements Iterable<Attribute>
{

  /** Underlying attributes. */
  private final List<Attribute> attributes = new ArrayList<>(5);


  /**
   * Adds an attribute by type and value to the end of the attribute list.
   *
   * @param  typeOid  OID of attribute type.
   * @param  value  Attribute value.
   */
  public void add(final String typeOid, final String value)
  {
    add(new Attribute(AttributeType.fromOid(typeOid), value));
  }


  /**
   * Adds the given attribute to the end of the attribute list.
   *
   * @param  attr  Non-null attribute.
   */
  public void add(final Attribute attr)
  {
    if (attr == null) {
      throw new IllegalArgumentException("Attribute cannot be null");
    }
    attributes.add(attr);
  }


  /**
   * Gets the number of attributes contained in this instance.
   *
   * @return  Number of attributes.
   */
  public int size()
  {
    return attributes.size();
  }


  /**
   * Gets an immutable list of attributes.
   *
   * @return  Non-null immutable attribute list.
   */
  public List<Attribute> getAll()
  {
    return Collections.unmodifiableList(attributes);
  }


  /**
   * Gets an immutable list of all attributes of the given type. The order of
   * the returned list reflects the ordering of the underlying attributes.
   *
   * @param  type  Attribute type.
   *
   * @return  Non-null list of attributes of given type. An empty list is
   * returned if there are no attributes of the given type.
   */
  public List<String> getValues(final AttributeType type)
  {
    final List<String> values = new ArrayList<>(attributes.size());
    for (Attribute attr : attributes) {
      if (attr.getType().equals(type)) {
        values.add(attr.getValue());
      }
    }
    return Collections.unmodifiableList(values);
  }


  /**
   * Gets the first value of the given type that appears in the attribute list.
   *
   * @param  type  Attribute type.
   *
   * @return  Value of first attribute of given type or null if no attributes of
   * given type exist.
   */
  public String getValue(final AttributeType type)
  {
    for (Attribute attr : attributes) {
      if (attr.getType().equals(type)) {
        return attr.getValue();
      }
    }
    return null;
  }


  /** {@inheritDoc} */
  @Override
  public Iterator<Attribute> iterator()
  {
    return attributes.iterator();
  }
}
