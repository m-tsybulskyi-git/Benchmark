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
import java.net.URI
import java.util.HashMap

@WebServlet(value = ["/pathtraver-01/BenchmarkTest01328"])
class BenchmarkTest01328 : HttpServlet() {
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
            val values = map["BenchmarkTest01328"]
            if (values != null) param = values[0]
        }
        val bar: String = Test().doSomething(request, param)

        // FILE URIs are tricky because they are different between Mac and Windows because of lack of standardization.
        // Mac requires an extra slash for some reason.
        var startURIslashes = ""
        if (System.getProperty("os.name").indexOf("Windows") != -1) startURIslashes =
            if (System.getProperty("os.name").indexOf("Windows") != -1) "/" else "//"
        try {
            val fileURI = URI(
                "file:" + startURIslashes
                        + Utils.TESTFILES_DIR.replace('\\', '/').replace(' ', '_') + bar
            )
            val fileTarget = File(fileURI)
            response.writer.println(
                "Access to file: '" + ESAPI.encoder().encodeForHTML(fileTarget.toString()) + "' created."
            )
            if (fileTarget.exists()) {
                response.writer.println(
                    " And file already exists."
                )
            } else {
                response.writer.println(
                    " But file doesn't exist yet."
                )
            }
        } catch (e: URISyntaxException) {
            throw ServletException(e)
        }
    } // end doPost

    private inner class Test {
        @Throws(ServletException::class, IOException::class)
        fun doSomething(request: HttpServletRequest?, param: String): String {

            // Chain a bunch of propagators in sequence
            val b17973 = StringBuilder(
                param //assign
            ) // stick in stringbuilder
            b17973.append(" SafeStuff") // append some safe content
            b17973.replace(b17973.length - "Chars".length, b17973.length, "Chars") //replace some of the end content
            val map17973 = HashMap<String, Any>()
            map17973["key17973"] = b17973.toString() // put in a collection
            val c17973 = map17973["key17973"] as String? // get it back out
            val d17973 = c17973!!.substring(0, c17973.length - 1) // extract most of it
            val e17973 = String(
                Base64.decodeBase64(
                    Base64.encodeBase64(d17973.toByteArray())
                )
            ) // B64 encode and decode it
            val f17973 = e17973.split(" ".toRegex()).toTypedArray()[0] // split it on a space
            val thing = ThingFactory.createThing()
            val g17973 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
            return thing.doSomething(g17973) // reflection
        }
    } // end innerclass Test

    companion object {
        private const val serialVersionUID = 1L
    }
} // end DataflowThruInnerClass
