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
import java.util.*

@WebServlet(value = ["/xss-01/BenchmarkTest00717"])
class BenchmarkTest00717 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val values = request.getParameterValues("BenchmarkTest00717")
        val param: String
        param = if (values != null && values.size > 0) values[0] else ""


        // Chain a bunch of propagators in sequence
        val b59129 = StringBuilder(
            param //assign
        ) // stick in stringbuilder
        b59129.append(" SafeStuff") // append some safe content
        b59129.replace(b59129.length - "Chars".length, b59129.length, "Chars") //replace some of the end content
        val map59129 = HashMap<String, Any>()
        map59129["key59129"] = b59129.toString() // put in a collection
        val c59129 = map59129["key59129"] as String? // get it back out
        val d59129 = c59129!!.substring(0, c59129.length - 1) // extract most of it
        val e59129 = String(
            Base64.decodeBase64(
                Base64.encodeBase64(d59129.toByteArray())
            )
        ) // B64 encode and decode it
        val f59129 = e59129.split(" ".toRegex()).toTypedArray()[0] // split it on a space
        val thing = ThingFactory.createThing()
        val g59129 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
        val bar = thing.doSomething(g59129) // reflection
        response.setHeader("X-XSS-Protection", "0")
        val obj = arrayOf<Any>("a", bar)
        response.writer.printf(Locale.US, "Formatted like: %1\$s and %2\$s.", *obj)
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}