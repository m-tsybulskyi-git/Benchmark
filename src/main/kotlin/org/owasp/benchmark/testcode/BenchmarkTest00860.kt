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

import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServlet
import kotlin.Throws
import javax.servlet.ServletException
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.lang.StringBuilder
import java.lang.Runtime
import java.io.File
import org.owasp.benchmark.helpers.ThingInterface
import java.security.NoSuchAlgorithmException
import java.sql.PreparedStatement
import java.sql.SQLException
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.dao.DataAccessException
import java.io.FileInputStream
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.io.FileWriter
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.security.InvalidAlgorithmParameterException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import java.net.URISyntaxException
import java.io.FileOutputStream
import java.security.MessageDigest
import java.lang.ProcessBuilder
import java.sql.CallableStatement
import java.util.Enumeration
import org.owasp.benchmark.helpers.LDAPManager
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import org.owasp.benchmark.helpers.SeparateClassRequest
import org.owasp.esapi.ESAPI
import java.io.PrintWriter
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.lang.Exception
import java.util.ArrayList

@WebServlet(value = ["/ldapi-00/BenchmarkTest00860"])
class BenchmarkTest00860 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val scr = SeparateClassRequest(request)
        val param = scr.getTheValue("BenchmarkTest00860")
        var bar = "alsosafe"
        if (param != null) {
            val valuesList: MutableList<String> = ArrayList()
            valuesList.add("safe")
            valuesList.add(param)
            valuesList.add("moresafe")
            valuesList.removeAt(0) // remove the 1st safe value
            bar = valuesList[1] // get the last 'safe' value
        }
        val ads = LDAPManager()
        try {
            response.contentType = "text/html;charset=UTF-8"
            val ctx = ads.dirContext
            val base = "ou=users,ou=system"
            val sc = SearchControls()
            sc.searchScope = SearchControls.SUBTREE_SCOPE
            val filter = "(&(objectclass=person))(|(uid=$bar)(street={0}))"
            val filters = arrayOf<Any>("The streetz 4 Ms bar")
            // System.out.println("Filter " + filter);
            var found = false
            val results = ctx.search(base, filter, filters, sc)
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