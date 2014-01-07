/*
 * Licensed to Virginia Tech under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Virginia Tech licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.cryptacular.x509.dn;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Ordered list of {@link Attribute}s.
 *
 * @author Marvin S. Addison
 */
public class Attributes implements Iterable<Attribute>
{
  /** Underlying attributes. */
  private final List<Attribute> attributes = new ArrayList<Attribute>(20);


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
   * Gets an immutable list of all attributes of the given type. The order of the returned list reflects the ordering
   * of the underlying attributes.
   *
   * @param  type  Attribute type.
   *
   * @return  Non-null list of attributes of given type. An empty list is returned if there are no attributes of the
   * given type.
   */
  public List<String> getValues(final AttributeType type)
  {
    final List<String> values = new ArrayList<String>(attributes.size());
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
   * @return  Value of first attribute of given type or null if no attributes of given type exist.
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


  /**
   * Gets an iterator that moves over the attribute list from last to first.
   *
   * @return  Iterator that moves backward over the attribute list.
   */
  public Iterator<Attribute> backward()
  {
    return new Iterator<Attribute>()
    {
      /** Iterator position. */
      private int position = attributes.size();

      @Override
      public boolean hasNext()
      {
        return position > 0;
      }

      @Override
      public Attribute next()
      {
        return attributes.get(--position);
      }

      @Override
      public void remove()
      {
        throw new UnsupportedOperationException("Remove not supported");
      }
    };
  }


  /**
   * Creates a comma-separated list of TYPE=VALUE tokens from the attributes in the list in order.
   *
   * @return  String representation that resembles an X.509 distinguished name, e.g.
   * <code>CN=foo, OU=Bar, dc=example, dc=com</code>.
   */
  @Override
  public String toString()
  {
    final StringBuilder builder = new StringBuilder();
    int count = 0;
    for (Attribute attr : attributes) {
      if (count++ > 0) {
        builder.append(", ");
      }
      builder.append(attr.getType().getName()).append('=').append(attr.getValue());
    }
    return builder.toString();
  }


}
