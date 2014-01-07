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

/**
 * Describes the registered values of AttributeType that may appear in a
 * RelativeDistinguishedName (RDN) as defined in section 2 of RFC 2253.
 *
 * <p>Enumeration values include attributes likely to appear in an X.509 RDN,
 * which were obtained from the following sources:</p>
 *
 * <ul>
 *   <li>RFC 4519 Lightweight Directory Access Protocol (LDAP): Schema for User
 *     Applications</li>
 *   <li>RFC 4524 COSINE LDAP/X.500 Schema</li>
 *   <li>PKCS #9 v2.0: Selected Object Classes and Attribute Types</li>
 * </ul>
 *
 * @author  Middleware Services
 * @version  $Revision: 2745 $
 */
public enum AttributeType
{

  /** CN - RFC 4519 section 2.3. */
  CommonName("2.5.4.3", "CN"),

  /** C - RFC 4519 section 2.2. */
  CountryName("2.5.4.6", "C"),

  /** DNQUALIFIER - RFC 4519 section 2.8. */
  DnQualifier("2.5.4.46", "DNQUALIFIER"),

  /** DC - RFC 4519 section 2.4. */
  DomainComponent("0.9.2342.19200300.100.1.25", "DC"),

  /** Email address - PKCS#9 v2.0 section B.3.5. */
  EmailAddress("1.2.840.113549.1.9.1", "EMAILADDRESS"),

  /** GenerationQualifier - RFC 4519 section 2.11. */
  GenerationQualifier("2.5.4.44", "GENERATIONQUALIFIER"),

  /** GIVENNAME - RFC 4519 section 2.12. */
  GivenName("2.5.4.42", "GIVENNAME"),

  /** INITIALS - RFC 4519 section 2.14. */
  Initials("2.5.4.43", "INITIALS"),

  /** L - RFC 4519 section 2.16. */
  LocalityName("2.5.4.7", "L"),

  /** MAIL - RFC 4524 section 2.16. */
  Mail("0.9.2342.19200300.100.1.3", "MAIL"),

  /** NAME - RFC 4519 section 2.18. */
  Name("2.5.4.41", "NAME"),

  /** O - RFC 4519 section 2.19. */
  OrganizationName("2.5.4.10", "O"),

  /** OU - RFC 4519 section 2.20. */
  OrganizationalUnitName("2.5.4.11", "OU"),

  /** POSTALADDRESS - RFC 4519 section 2.23. */
  PostalAddress("2.5.4.16", "POSTALADDRESS"),

  /** POSTALCODE - RFC 4519 section 2.24. */
  PostalCode("2.5.4.17", "POSTALCODE"),

  /** POSTOFFICEBOX - RFC 4519 section 2.25. */
  PostOfficeBox("2.5.4.18", "POSTOFFICEBOX"),

  /** SERIALNUMBER - RFC 4519 section 2.31. */
  SerialNumber("2.5.4.5", "SERIALNUMBER"),

  /** ST - RFC 4519 section 2.33. */
  StateOrProvinceName("2.5.4.8", "ST"),

  /** STREET - RFC 4519 section 2.34. */
  StreetAddress("2.5.4.9", "STREET"),

  /** SN - RFC 4519 section 2.32. */
  Surname("2.5.4.4", "SN"),

  /** TITLE - RFC 4519 section 2.38. */
  Title("2.5.4.12", "TITLE"),

  /** UNIQUEIDENTIFIER - RFC 4524 section 2.24. */
  UniqueIdentifier("0.9.2342.19200300.100.1.44", "UNIQUEIDENTIFIER"),

  /** UID - RFC 4519 section 2.39. */
  UserId("0.9.2342.19200300.100.1.1", "UID");


  /** OID of RDN attribute type. */
  private final String oid;

  /** Display string of the type in an RDN. */
  private final String name;


  /**
   * Creates a new type for the given OID.
   *
   * @param  attributeTypeOid  OID of attribute type.
   * @param  shortName  Registered short name for the attribute type.
   */
  AttributeType(final String attributeTypeOid, final String shortName)
  {
    oid = attributeTypeOid;
    name = shortName;
  }


  /** @return  OID of attribute type. */
  public String getOid()
  {
    return oid;
  }


  /** @return  Registered short name of attribute type. */
  public String getName()
  {
    return name;
  }


  /**
   * @return  Attribute name.
   */
  @Override
  public String toString()
  {
    return name;
  }


  /**
   * Gets the attribute type whose OID is the given string.
   *
   * @param  oid  OID of attribute type to get.
   *
   * @return  Attribute type whose OID matches given value.
   *
   * @throws  IllegalArgumentException  On unknown OID.
   */
  public static AttributeType fromOid(final String oid)
  {
    for (AttributeType t : AttributeType.values()) {
      if (t.getOid().equals(oid)) {
        return t;
      }
    }
    throw new IllegalArgumentException("Unknown AttributeType for OID " + oid);
  }


  /**
   * Gets the attribute type whose name is the given string.
   *
   * @param  name  Name of attribute to get, where the name is the all-caps
   * RFC/standard name that would be returned by {@link #getName()} for the
   * desired attribute.
   *
   * @return  Attribute type whose {@link #getName()} property matches the given value.
   *
   * @throws  IllegalArgumentException  On unknown name.
   */
  public static AttributeType fromName(final String name)
  {
    for (AttributeType t : AttributeType.values()) {
      if (t.getName().equals(name)) {
        return t;
      }
    }
    throw new IllegalArgumentException(
      "Unknown AttributeType for name " + name);
  }
}
