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

import java.security.cert.X509Certificate;

import org.cryptacular.util.CertUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link NameReader}.
 *
 * @author Marvin S. Addison
 */
public class NameReaderTest
{
  private static final String CRT_PATH = "src/test/resources/certs/";

  @DataProvider(name = "subjects")
  public Object[][] getSubjects()
  {
    return new Object[][] {
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
        "UID=1145718, CN=Marvin S Addison, O=Virginia Polytechnic Institute and State University, DC=edu, DC=vt, C=US",
      },
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "glider.cc.vt.edu.crt"),
        "CN=glider.cc.vt.edu, SERIALNUMBER=1248110657961, OU=SETI, OU=Middleware-Client, " +
          "O=Virginia Polytechnic Institute and State University, L=Blacksburg, ST=Virginia, DC=vt, DC=edu, C=US",
      },
    };
  }

  @DataProvider(name = "issuers")
  public Object[][] getIssuers()
  {
    return new Object[][] {
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt"),
        "DC=edu, DC=vt, C=US, O=Virginia Polytechnic Institute and State University, " +
          "CN=DEV Virginia Tech Class 1 Server CA, SERIALNUMBER=12",
      },
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "glider.cc.vt.edu.crt"),
        "DC=edu, DC=vt, C=US, O=Virginia Polytechnic Institute and State University, CN=Virginia Tech Middleware CA",
      },
    };
  }

  @Test(dataProvider = "subjects")
  public void testReadSubject(final X509Certificate cert, final String expected) throws Exception
  {
    final Attributes attributes = new NameReader(cert).readSubject();
    assertEquals(attributes.toString(), expected);
  }

  @Test(dataProvider = "issuers")
  public void testReadIssuer(final X509Certificate cert, final String expected) throws Exception
  {
    final Attributes attributes = new NameReader(cert).readIssuer();
    assertEquals(attributes.toString(), expected);
  }
}
