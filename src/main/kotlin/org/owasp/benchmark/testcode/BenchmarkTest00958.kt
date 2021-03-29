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

import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServlet
import kotlin.Throws
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.lang.StringBuilder
import java.lang.Runtime
import org.owasp.benchmark.helpers.ThingInterface
import java.security.NoSuchAlgorithmException
import java.sql.PreparedStatement
import java.sql.SQLException
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.dao.DataAccessException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.security.InvalidAlgorithmParameterException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import java.net.URISyntaxException
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
import org.owasp.benchmark.helpers.Utils
import org.owasp.esapi.ESAPI
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.io.*
import java.lang.Exception
import java.net.URL
import java.net.URLDecoder
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.util.HashMap
import javax.servlet.http.Cookie

@WebServlet(value = ["/pathtraver-01/BenchmarkTest00958"])
class BenchmarkTest00958 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val userCookie = Cookie("BenchmarkTest00958", "FileName")
        userCookie.maxAge = 60 * 3 //Store cookie for 3 minutes
        userCookie.secure = true
        userCookie.path = request.requestURI
        userCookie.domain = URL(request.requestURL.toString()).host
        response.addCookie(userCookie)
        val rd = request.getRequestDispatcher("/pathtraver-01/BenchmarkTest00958.html")
        rd.include(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val theCookies = request.cookies
        var param: String? = "noCookieValueSupplied"
        if (theCookies != null) {
            for (theCookie in theCookies) {
                if (theCookie.name == "BenchmarkTest00958") {
                    param = URLDecoder.decode(theCookie.value, "UTF-8")
                    break
                }
            }
        }
        val bar: String? = param?.let { Test().doSomething(request, it) }
        bar ?: return
        val fileName = Utils.TESTFILES_DIR + bar
        var `is`: InputStream? = null
        try {
            val path = Paths.get(fileName)
            `is` = Files.newInputStream(path, StandardOpenOption.READ)
            val b = ByteArray(1000)
            val size = `is`.read(b)
            response.writer.println(
                """
                    The beginning of file: '${ESAPI.encoder().encodeForHTML(fileName)}' is:
                    
                    
                    """.trimIndent()
            )
            response.writer.println(
                ESAPI.encoder().encodeForHTML(String(b, 0, size))
            )
            `is`.close()
        } catch (e: Exception) {
            println("Couldn't open InputStream on file: '$fileName'")
            response.writer.println(
                "Problem getting InputStream: "
                        + ESAPI.encoder().encodeForHTML(e.message)
            )
        } finally {
            if (`is` != null) {
                try {
                    `is`.close()
                    `is` = null
                } catch (e: Exception) {
                    // we tried...
                }
            }
        }
    } // end doPost

    private inner class Test {
        @Throws(ServletException::class, IOException::class)
        fun doSomething(request: HttpServletRequest?, param: String): String? {
            var bar: String? = "safe!"
            val map37053 = HashMap<String, Any>()
            map37053["keyA-37053"] = "a_Value" // put some stuff in the collection
            map37053["keyB-37053"] = param // put it in a collection
            map37053["keyC"] = "another_Value" // put some stuff in the collection
            bar = map37053["keyB-37053"] as String? // get it back out
            bar = map37053["keyA-37053"] as String? // get safe value back out
            return bar
        }
    } // end innerclass Test

    companion object {
        private const val serialVersionUID = 1L
    }
} // end DataflowThruInnerClass
