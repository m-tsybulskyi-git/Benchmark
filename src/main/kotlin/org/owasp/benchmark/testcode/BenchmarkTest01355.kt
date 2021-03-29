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

import org.apache.commons.lang.StringEscapeUtils
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
import javax.crypto.spec.GCMParameterSpec
import java.lang.ProcessBuilder
import java.sql.CallableStatement
import javax.naming.directory.InitialDirContext
import org.owasp.benchmark.helpers.SeparateClassRequest
import java.net.URL
import java.util.*
import javax.servlet.http.Cookie

@WebServlet(value = ["/weakrand-03/BenchmarkTest01355"])
class BenchmarkTest01355 : HttpServlet() {
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
            val values = map["BenchmarkTest01355"]
            if (values != null) param = values[0]
        }
        val bar: String = Test().doSomething(request, param)
        val rand = Random().nextFloat()
        val rememberMeKey = java.lang.Float.toString(rand).substring(2) // Trim off the 0. at the front.
        var user = "Floyd"
        val fullClassName = this.javaClass.name
        val testCaseNumber = fullClassName.substring(fullClassName.lastIndexOf('.') + 1 + "BenchmarkTest".length)
        user += testCaseNumber
        val cookieName = "rememberMe$testCaseNumber"
        var foundUser = false
        val cookies = request.cookies
        if (cookies != null) {
            var i = 0
            while (!foundUser && i < cookies.size) {
                val cookie = cookies[i]
                if (cookieName == cookie.name) {
                    if (cookie.value == request.session.getAttribute(cookieName)) {
                        foundUser = true
                    }
                }
                i++
            }
        }
        if (foundUser) {
            response.writer.println(
                "Welcome back: $user<br/>"
            )
        } else {
            val rememberMe = Cookie(cookieName, rememberMeKey)
            rememberMe.secure = true
            rememberMe.isHttpOnly = true
            rememberMe.domain = URL(request.requestURL.toString()).host
            rememberMe.path = request.requestURI // i.e., set path to JUST this servlet 
            // e.g., /benchmark/sql-01/BenchmarkTest01001
            request.session.setAttribute(cookieName, rememberMeKey)
            response.addCookie(rememberMe)
            response.writer.println(
                user + " has been remembered with cookie: " + rememberMe.name
                        + " whose value is: " + rememberMe.value + "<br/>"
            )
        }
        response.writer.println(
            "Weak Randomness Test java.util.Random.nextFloat() executed"
        )
    } // end doPost

    private inner class Test {
        @Throws(ServletException::class, IOException::class)
        fun doSomething(request: HttpServletRequest?, param: String?): String {
            return StringEscapeUtils.escapeHtml(param)
        }
    } // end innerclass Test

    companion object {
        private const val serialVersionUID = 1L
    }
} // end DataflowThruInnerClass
