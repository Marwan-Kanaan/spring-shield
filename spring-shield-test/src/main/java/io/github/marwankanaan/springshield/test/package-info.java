/**
 * Helpers for testing an application that uses SpringShield.
 *
 * <p>
 * Add the module at test scope:
 *
 * <pre>
 * &lt;dependency&gt;
 *   &lt;groupId&gt;io.github.marwan-kanaan&lt;/groupId&gt;
 *   &lt;artifactId&gt;spring-shield-test&lt;/artifactId&gt;
 *   &lt;scope&gt;test&lt;/scope&gt;
 * &lt;/dependency&gt;
 * </pre>
 *
 * <p>
 * The one rule these helpers follow is that they never weaken what they are helping you
 * test. They populate a security context the way an authenticated request would; none of
 * them disables a check, skips the filter chain, or grants an authority the application
 * would not have granted. A helper that made authorization pass would leave you with
 * tests that stay green while the application stops being safe.
 *
 * @author mkanaan
 */
package io.github.marwankanaan.springshield.test;
