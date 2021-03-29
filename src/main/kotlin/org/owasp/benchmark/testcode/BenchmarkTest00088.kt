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
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.security.MessageDigest
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
import org.owasp.esapi.ESAPI
import java.io.*
import java.net.URL
import java.net.URLDecoder
import javax.servlet.http.Cookie

@WebServlet(value = ["/securecookie-00/BenchmarkTest00088"])
class BenchmarkTest00088 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val userCookie = Cookie("BenchmarkTest00088", "whatever")
        userCookie.maxAge = 60 * 3 //Store cookie for 3 minutes
        userCookie.secure = true
        userCookie.path = request.requestURI
        userCookie.domain = URL(request.requestURL.toString()).host
        response.addCookie(userCookie)
        val rd = request.getRequestDispatcher("/securecookie-00/BenchmarkTest00088.html")
        rd.include(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val theCookies = request.cookies
        var param = "noCookieValueSupplied"
        if (theCookies != null) {
            for (theCookie in theCookies) {
                if (theCookie.name == "BenchmarkTest00088") {
                    param = URLDecoder.decode(theCookie.value, "UTF-8")
                    break
                }
            }
        }
        val bar = ESAPI.encoder().encodeForHTML(param)
        val input = ByteArray(1000)
        var str = "?"
        val inputParam: Any = param
        if (inputParam is String) str = inputParam
        if (inputParam is InputStream) {
            val i = inputParam.read(input)
            if (i == -1) {
                response.writer.println(
                    "This input source requires a POST, not a GET. Incompatible UI for the InputStream source."
                )
                return
            }
            str = String(input, 0, i)
        }
        if ("" == str) str = "No cookie value supplied"
        val cookie = Cookie("SomeCookie", str)
        cookie.secure = true
        cookie.isHttpOnly = true
        cookie.path = request.requestURI // i.e., set path to JUST this servlet
        // e.g., /benchmark/sql-01/BenchmarkTest01001
        response.addCookie(cookie)
        response.writer.println(
            "Created cookie: 'SomeCookie': with value: '"
                    + ESAPI.encoder().encodeForHTML(str) + "' and secure flag set to: true"
        )
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}