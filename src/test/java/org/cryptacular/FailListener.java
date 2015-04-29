/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

import org.testng.ITestResult;
import org.testng.TestListenerAdapter;

/**
 * TestNG listener that converts skipped results to failures when the cause of skip is an error.
 * A common use case for this listener is triggering failures on <code>@DataProvider</code> errors.
 *
 * @author  Middleware Services
 */
public class FailListener extends TestListenerAdapter
{
  @Override
  public void onTestSkipped(final ITestResult tr)
  {
    if (tr.getThrowable() != null) {
      tr.setStatus(ITestResult.FAILURE);
    }
  }
}
