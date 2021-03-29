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
import org.owasp.benchmark.helpers.ThingFactory
import java.io.PrintWriter
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.util.HashMap

@WebServlet(value = ["/xss-01/BenchmarkTest00725"])
class BenchmarkTest00725 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val values = request.getParameterValues("BenchmarkTest00725")
        val param: String
        param = if (values != null && values.size > 0) values[0] else ""


        // Chain a bunch of propagators in sequence
        val b49441 = StringBuilder(
            param //assign
        ) // stick in stringbuilder
        b49441.append(" SafeStuff") // append some safe content
        b49441.replace(b49441.length - "Chars".length, b49441.length, "Chars") //replace some of the end content
        val map49441 = HashMap<String, Any>()
        map49441["key49441"] = b49441.toString() // put in a collection
        val c49441 = map49441["key49441"] as String? // get it back out
        val d49441 = c49441!!.substring(0, c49441.length - 1) // extract most of it
        val e49441 = String(
            Base64.decodeBase64(
                Base64.encodeBase64(d49441.toByteArray())
            )
        ) // B64 encode and decode it
        val f49441 = e49441.split(" ".toRegex()).toTypedArray()[0] // split it on a space
        val thing = ThingFactory.createThing()
        val bar = thing.doSomething(f49441) // reflection
        response.setHeader("X-XSS-Protection", "0")
        response.writer.println(bar)
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}