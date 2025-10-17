/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.x509.dn;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.cryptacular.CryptUtil;

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
   * Creates a new attributes.
   *
   * @param attributes to include
   */
  public Attributes(final Attribute... attributes)
  {
    this(Arrays.asList(attributes));
  }


  /**
   * Creates a new attributes.
   *
   * @param attributes to include
   */
  public Attributes(final List<Attribute> attributes)
  {
    this.attributes.addAll(
      CryptUtil.assertNotNullArgOr(attributes, v -> v.stream().anyMatch(Objects::isNull), "Attributes cannot be null"));
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
   * Gets an immutable list of all attributes of the given type. The order of the returned list reflects the ordering of
   * the underlying attributes.
   *
   * @param  type  Attribute type.
   *
   * @return  Non-null list of attributes of given type. An empty list is returned if there are no attributes of the
   *          given type.
   */
  public List<String> getValues(final AttributeType type)
  {
    final List<String> values = new ArrayList<>(attributes.size());
    values.addAll(
      attributes.stream().filter(
        attr -> attr.getType().equals(type)).map(Attribute::getValue).collect(Collectors.toList()));
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


  @Override
  public Iterator<Attribute> iterator()
  {
    return attributes.iterator();
  }
}
