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
import org.owasp.benchmark.helpers.DatabaseHelper
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
import java.net.URLDecoder
import java.util.HashMap

@WebServlet(value = ["/sqli-00/BenchmarkTest00201"])
class BenchmarkTest00201 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param = ""
        if (request.getHeader("BenchmarkTest00201") != null) {
            param = request.getHeader("BenchmarkTest00201")
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = URLDecoder.decode(param, "UTF-8")


        // Chain a bunch of propagators in sequence
        val a60073 = param //assign
        val b60073 = StringBuilder(a60073) // stick in stringbuilder
        b60073.append(" SafeStuff") // append some safe content
        b60073.replace(b60073.length - "Chars".length, b60073.length, "Chars") //replace some of the end content
        val map60073 = HashMap<String, Any>()
        map60073["key60073"] = b60073.toString() // put in a collection
        val c60073 = map60073["key60073"] as String? // get it back out
        val d60073 = c60073!!.substring(0, c60073.length - 1) // extract most of it
        val e60073 = String(
            Base64.decodeBase64(
                Base64.encodeBase64(d60073.toByteArray())
            )
        ) // B64 encode and decode it
        val f60073 = e60073.split(" ".toRegex()).toTypedArray()[0] // split it on a space
        val thing = ThingFactory.createThing()
        val g60073 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
        val bar = thing.doSomething(g60073) // reflection
        try {
            val sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='$bar'"
            DatabaseHelper.JDBCtemplate.batchUpdate(sql)
            response.writer.println(
                "No results can be displayed for query: " + ESAPI.encoder().encodeForHTML(sql) + "<br>"
                        + " because the Spring batchUpdate method doesn't return results."
            )
        } catch (e: DataAccessException) {
            if (DatabaseHelper.hideSQLErrors) {
                response.writer.println(
                    "Error processing request."
                )
            } else throw ServletException(e)
        }
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}