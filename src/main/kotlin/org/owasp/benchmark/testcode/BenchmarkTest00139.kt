/**
 * OWASP Benchmark Project v1.2
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Benchmark Project. For details, please see
 * [https://owasp.org/www-project-benchmark/](https://owasp.org/www-project-benchmark/).
 *
 * The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * @author Nick Sanidas
 * @created 2015
 */
package org.owasp.benchmark.testcode

import org.apache.commons.codec.binary.Base64
import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServlet
import kotlin.Throws
import javax.servlet.ServletException
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.sql.PreparedStatement
import java.sql.SQLException
import org.owasp.benchmark.helpers.ThingInterface
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.dao.DataAccessException
import java.lang.StringBuilder
import java.io.FileInputStream
import javax.crypto.Cipher
import javax.crypto.SecretKey
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import java.io.File
import java.io.FileWriter
import java.security.NoSuchAlgorithmException
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.security.InvalidAlgorithmParameterException
import javax.crypto.spec.GCMParameterSpec
import java.io.FileOutputStream
import org.owasp.benchmark.helpers.LDAPManager
import org.owasp.benchmark.helpers.ThingFactory
import org.owasp.esapi.ESAPI
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import java.security.MessageDigest
import java.lang.ProcessBuilder
import java.lang.Runtime
import java.sql.CallableStatement
import java.util.Enumeration
import java.net.URISyntaxException
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.lang.Exception
import java.net.URLDecoder
import java.util.HashMap

@WebServlet(value = ["/ldapi-00/BenchmarkTest00139"])
class BenchmarkTest00139 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param = ""
        if (request.getHeader("BenchmarkTest00139") != null) {
            param = request.getHeader("BenchmarkTest00139")
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = URLDecoder.decode(param, "UTF-8")


        // Chain a bunch of propagators in sequence
        val a48394 = param //assign
        val b48394 = StringBuilder(a48394) // stick in stringbuilder
        b48394.append(" SafeStuff") // append some safe content
        b48394.replace(b48394.length - "Chars".length, b48394.length, "Chars") //replace some of the end content
        val map48394 = HashMap<String, Any>()
        map48394["key48394"] = b48394.toString() // put in a collection
        val c48394 = map48394["key48394"] as String? // get it back out
        val d48394 = c48394!!.substring(0, c48394.length - 1) // extract most of it
        val e48394 = String(
            Base64.decodeBase64(
                Base64.encodeBase64(d48394.toByteArray())
            )
        ) // B64 encode and decode it
        val f48394 = e48394.split(" ".toRegex()).toTypedArray()[0] // split it on a space
        val thing = ThingFactory.createThing()
        val g48394 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
        val bar = thing.doSomething(g48394) // reflection
        val ads = LDAPManager()
        try {
            response.contentType = "text/html;charset=UTF-8"
            val base = "ou=users,ou=system"
            val sc = SearchControls()
            sc.searchScope = SearchControls.SUBTREE_SCOPE
            val filter = ("(&(objectclass=person)(uid=" + bar
                    + "))")
            val ctx = ads.dirContext
            val idc = ctx as InitialDirContext
            var found = false
            val results = idc.search(base, filter, sc)
            while (results.hasMore()) {
                val sr = results.next() as SearchResult
                val attrs = sr.attributes
                val attr = attrs["uid"]
                val attr2 = attrs["street"]
                if (attr != null) {
                    response.writer.println(
                        "LDAP query results:<br>"
                                + "Record found with name " + attr.get() + "<br>"
                                + "Address: " + attr2.get() + "<br>"
                    )
                    // System.out.println("record found " + attr.get());
                    found = true
                }
            }
            if (!found) {
                response.writer.println(
                    "LDAP query results: nothing found for query: " + ESAPI.encoder().encodeForHTML(filter)
                )
            }
        } catch (e: NamingException) {
            throw ServletException(e)
        } finally {
            try {
                ads.closeDirContext()
            } catch (e: Exception) {
                throw ServletException(e)
            }
        }
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}