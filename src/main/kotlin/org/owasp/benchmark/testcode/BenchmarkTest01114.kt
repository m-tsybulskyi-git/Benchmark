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
import org.owasp.benchmark.helpers.*
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
import org.owasp.esapi.ESAPI
import java.lang.Exception
import java.util.HashMap

@WebServlet(value = ["/pathtraver-01/BenchmarkTest01114"])
class BenchmarkTest01114 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param: String? = ""
        val names = request.headerNames
        while (names.hasMoreElements()) {
            val name = names.nextElement() as String
            if (Utils.commonHeaders.contains(name)) {
                continue
            }
            val values = request.getHeaders(name)
            if (values != null && values.hasMoreElements()) {
                param = name
                break
            }
        }
        // Note: We don't URL decode header names because people don't normally do that
        val bar: String? = param?.let { Test().doSomething(request, it) }
        bar ?: return
        var fileName: String? = null
        var fos: FileOutputStream? = null
        try {
            fileName = Utils.TESTFILES_DIR + bar
            fos = FileOutputStream(File(fileName), false)
            response.writer.println(
                "Now ready to write to file: " + ESAPI.encoder().encodeForHTML(fileName)
            )
        } catch (e: Exception) {
            println("Couldn't open FileOutputStream on file: '$fileName'")
            //			System.out.println("File exception caught and swallowed: " + e.getMessage());
        } finally {
            if (fos != null) {
                try {
                    fos.close()
                    fos = null
                } catch (e: Exception) {
                    // we tried...
                }
            }
        }
    } // end doPost

    private inner class Test {
        @Throws(ServletException::class, IOException::class)
        fun doSomething(request: HttpServletRequest?, param: String): String {

            // Chain a bunch of propagators in sequence
            val b97099 = StringBuilder(
                param //assign
            ) // stick in stringbuilder
            b97099.append(" SafeStuff") // append some safe content
            b97099.replace(b97099.length - "Chars".length, b97099.length, "Chars") //replace some of the end content
            val map97099 = HashMap<String, Any>()
            map97099["key97099"] = b97099.toString() // put in a collection
            val c97099 = map97099["key97099"] as String? // get it back out
            val d97099 = c97099!!.substring(0, c97099.length - 1) // extract most of it
            val e97099 = String(
                Base64.decodeBase64(
                    Base64.encodeBase64(d97099.toByteArray())
                )
            ) // B64 encode and decode it
            val f97099 = e97099.split(" ".toRegex()).toTypedArray()[0] // split it on a space
            val thing = ThingFactory.createThing()
            val g97099 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
            return thing.doSomething(g97099) // reflection
        }
    } // end innerclass Test

    companion object {
        private const val serialVersionUID = 1L
    }
} // end DataflowThruInnerClass
