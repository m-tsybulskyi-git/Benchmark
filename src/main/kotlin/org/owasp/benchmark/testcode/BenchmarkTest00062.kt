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
import java.io.FileInputStream
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.io.FileWriter
import java.security.NoSuchAlgorithmException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.security.InvalidAlgorithmParameterException
import java.lang.ProcessBuilder
import java.lang.Runtime
import java.sql.CallableStatement
import java.sql.SQLException
import java.util.Enumeration
import org.owasp.benchmark.helpers.LDAPManager
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import java.sql.PreparedStatement
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.dao.DataAccessException
import org.springframework.jdbc.support.rowset.SqlRowSet
import org.owasp.benchmark.helpers.SeparateClassRequest
import javax.crypto.spec.GCMParameterSpec
import java.lang.StringBuilder
import org.owasp.benchmark.helpers.ThingInterface
import org.owasp.benchmark.helpers.Utils
import org.owasp.esapi.ESAPI
import java.lang.Exception
import java.net.URL
import java.net.URLDecoder
import java.util.HashMap
import javax.servlet.http.Cookie

@WebServlet(value = ["/pathtraver-00/BenchmarkTest00062"])
class BenchmarkTest00062 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val userCookie = Cookie("BenchmarkTest00062", "FileName")
        userCookie.maxAge = 60 * 3 //Store cookie for 3 minutes
        userCookie.secure = true
        userCookie.path = request.requestURI
        userCookie.domain = URL(request.requestURL.toString()).host
        response.addCookie(userCookie)
        val rd = request.getRequestDispatcher("/pathtraver-00/BenchmarkTest00062.html")
        rd.include(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val theCookies = request.cookies
        var param = "noCookieValueSupplied"
        if (theCookies != null) {
            for (theCookie in theCookies) {
                if (theCookie.name == "BenchmarkTest00062") {
                    param = URLDecoder.decode(theCookie.value, "UTF-8")
                    break
                }
            }
        }
        var bar: String? = "safe!"
        val map77232 = HashMap<String, Any>()
        map77232["keyA-77232"] = "a-Value" // put some stuff in the collection
        map77232["keyB-77232"] = param // put it in a collection
        map77232["keyC"] = "another-Value" // put some stuff in the collection
        bar = map77232["keyB-77232"] as String? // get it back out
        var fileName: String? = null
        var fis: FileInputStream? = null
        try {
            fileName = Utils.TESTFILES_DIR + bar
            fis = FileInputStream(File(fileName))
            val b = ByteArray(1000)
            val size = fis.read(b)
            response.writer.println(
                """
                    The beginning of file: '${ESAPI.encoder().encodeForHTML(fileName)}' is:
                    
                    ${ESAPI.encoder().encodeForHTML(String(b, 0, size))}
                    """.trimIndent()
            )
        } catch (e: Exception) {
            println("Couldn't open FileInputStream on file: '$fileName'")
            response.writer.println(
                "Problem getting FileInputStream: "
                        + ESAPI.encoder().encodeForHTML(e.message)
            )
        } finally {
            if (fis != null) {
                try {
                    fis.close()
                    fis = null
                } catch (e: Exception) {
                    // we tried...
                }
            }
        }
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}