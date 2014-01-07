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

import java.util.Iterator;
import javax.security.auth.x500.X500Principal;

/**
 * Produces a string representation of an X.500 distinguished name using the
 * process described in section 2 of RFC 2253, LADPv3 Distinguished Names.
 *
 * @author  Middleware Services
 */
public class LdapNameFormatter implements NameFormatter
{
  /** Separator character between RDN components. */
  public static final char SEPARATOR = ',';


  /** {@inheritDoc} */
  public String format(final X500Principal dn)
  {
    final StringBuilder builder = new StringBuilder();
    final Iterator<Attribute> iterator = NameReader.readX500Principal(dn).backward();
    Attribute attr;
    while (iterator.hasNext()) {
      attr = iterator.next();
      builder.append(attr.getType()).append('=').append(attr.getValue());
      if (iterator.hasNext()) {
        builder.append(SEPARATOR);
      }
    }
    return builder.toString();
  }
}
