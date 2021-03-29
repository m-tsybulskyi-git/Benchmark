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
import java.net.URL
import java.net.URLDecoder
import java.util.*
import javax.servlet.http.Cookie

@WebServlet(value = ["/hash-01/BenchmarkTest00965"])
class BenchmarkTest00965 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val userCookie = Cookie("BenchmarkTest00965", "someSecret")
        userCookie.maxAge = 60 * 3 //Store cookie for 3 minutes
        userCookie.secure = true
        userCookie.path = request.requestURI
        userCookie.domain = URL(request.requestURL.toString()).host
        response.addCookie(userCookie)
        val rd = request.getRequestDispatcher("/hash-01/BenchmarkTest00965.html")
        rd.include(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val theCookies = request.cookies
        var param: String? = "noCookieValueSupplied"
        if (theCookies != null) {
            for (theCookie in theCookies) {
                if (theCookie.name == "BenchmarkTest00965") {
                    param = URLDecoder.decode(theCookie.value, "UTF-8")
                    break
                }
            }
        }
        val bar: String? = param?.let { Test().doSomething(request, it) }
        bar ?: return
        try {
            val benchmarkprops = Properties()
            benchmarkprops.load(this.javaClass.classLoader.getResourceAsStream("benchmark.properties"))
            val algorithm = benchmarkprops.getProperty("hashAlg2", "SHA5")
            val md = MessageDigest.getInstance(algorithm)
            var input: ByteArray? = byteArrayOf('?'.toByte())
            val inputParam: Any = bar
            if (inputParam is String) input = inputParam.toByteArray()
            if (inputParam is InputStream) {
                val strInput = ByteArray(1000)
                val i = inputParam.read(strInput)
                if (i == -1) {
                    response.writer.println(
                        "This input source requires a POST, not a GET. Incompatible UI for the InputStream source."
                    )
                    return
                }
                input = Arrays.copyOf(strInput, i)
            }
            md.update(input)
            val result = md.digest()
            val fileTarget = File(
                File(Utils.TESTFILES_DIR), "passwordFile.txt"
            )
            val fw = FileWriter(fileTarget, true) //the true will append the new data
            fw.write(
                """
    hash_value=${ESAPI.encoder().encodeForBase64(result, true)}
    
    """.trimIndent()
            )
            fw.close()
            response.writer.println(
                "Sensitive value '" + ESAPI.encoder().encodeForHTML(String(input!!)) + "' hashed and stored<br/>"
            )
        } catch (e: NoSuchAlgorithmException) {
            println("Problem executing hash - TestCase")
            throw ServletException(e)
        }
        response.writer.println(
            "Hash Test java.security.MessageDigest.getInstance(java.lang.String) executed"
        )
    } // end doPost

    private inner class Test {
        @Throws(ServletException::class, IOException::class)
        fun doSomething(request: HttpServletRequest?, param: String): String? {
            var bar: String? = "safe!"
            val map47189 = HashMap<String, Any>()
            map47189["keyA-47189"] = "a-Value" // put some stuff in the collection
            map47189["keyB-47189"] = param // put it in a collection
            map47189["keyC"] = "another-Value" // put some stuff in the collection
            bar = map47189["keyB-47189"] as String? // get it back out
            return bar
        }
    } // end innerclass Test

    companion object {
        private const val serialVersionUID = 1L
    }
} // end DataflowThruInnerClass
