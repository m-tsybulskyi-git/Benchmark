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
 * @author Dave Wichers
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
import org.springframework.dao.DataAccessException
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.jdbc.support.rowset.SqlRowSet
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
import java.lang.StringBuilder
import org.owasp.benchmark.helpers.ThingInterface
import org.owasp.benchmark.helpers.LDAPManager
import javax.naming.directory.DirContext
import javax.naming.directory.SearchControls
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import java.net.URISyntaxException
import java.io.FileOutputStream
import java.security.MessageDigest
import java.io.PrintWriter
import java.lang.Runtime
import java.util.Enumeration
import javax.crypto.spec.GCMParameterSpec
import java.lang.ProcessBuilder
import java.sql.CallableStatement
import javax.naming.directory.InitialDirContext
import org.owasp.benchmark.helpers.SeparateClassRequest
import org.owasp.benchmark.helpers.ThingFactory
import java.util.HashMap

@WebServlet(value = ["/xss-02/BenchmarkTest01347"])
class BenchmarkTest01347 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val map = request.parameterMap
        var param = ""
        if (!map.isEmpty()) {
            val values = map["BenchmarkTest01347"]
            if (values != null) param = values[0]
        }
        val bar: String = Test().doSomething(request, param)
        response.setHeader("X-XSS-Protection", "0")
        response.writer.println(bar)
    } // end doPost

    private inner class Test {
        @Throws(ServletException::class, IOException::class)
        fun doSomething(request: HttpServletRequest?, param: String): String {

            // Chain a bunch of propagators in sequence
            val b81561 = StringBuilder(
                param //assign
            ) // stick in stringbuilder
            b81561.append(" SafeStuff") // append some safe content
            b81561.replace(b81561.length - "Chars".length, b81561.length, "Chars") //replace some of the end content
            val map81561 = HashMap<String, Any>()
            map81561["key81561"] = b81561.toString() // put in a collection
            val c81561 = map81561["key81561"] as String? // get it back out
            val d81561 = c81561!!.substring(0, c81561.length - 1) // extract most of it
            val e81561 = String(
                Base64.decodeBase64(
                    Base64.encodeBase64(d81561.toByteArray())
                )
            ) // B64 encode and decode it
            val f81561 = e81561.split(" ".toRegex()).toTypedArray()[0] // split it on a space
            val thing = ThingFactory.createThing()
            return thing.doSomething(f81561) // reflection
        }
    } // end innerclass Test

    companion object {
        private const val serialVersionUID = 1L
    }
} // end DataflowThruInnerClass
