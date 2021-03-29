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
import java.util.Enumeration
import org.owasp.benchmark.testcode.BenchmarkTest02001
import org.owasp.benchmark.testcode.BenchmarkTest02002
import org.owasp.benchmark.testcode.BenchmarkTest02003
import java.lang.StringBuilder
import org.owasp.benchmark.helpers.ThingInterface
import org.owasp.benchmark.testcode.BenchmarkTest02004
import org.owasp.benchmark.testcode.BenchmarkTest02005
import org.owasp.benchmark.testcode.BenchmarkTest02006
import org.owasp.benchmark.testcode.BenchmarkTest02007
import java.security.NoSuchAlgorithmException
import org.owasp.benchmark.testcode.BenchmarkTest02008
import org.owasp.benchmark.testcode.BenchmarkTest02009
import org.owasp.benchmark.testcode.BenchmarkTest02010
import org.owasp.benchmark.testcode.BenchmarkTest02011
import org.owasp.benchmark.testcode.BenchmarkTest02012
import org.owasp.benchmark.testcode.BenchmarkTest02013
import org.owasp.benchmark.testcode.BenchmarkTest02014
import org.owasp.benchmark.testcode.BenchmarkTest02015
import org.owasp.benchmark.testcode.BenchmarkTest02016
import org.owasp.benchmark.testcode.BenchmarkTest02017
import javax.crypto.Cipher
import javax.crypto.SecretKey
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import java.io.File
import java.io.FileWriter
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.security.InvalidAlgorithmParameterException
import org.owasp.benchmark.testcode.BenchmarkTest02018
import org.owasp.benchmark.testcode.BenchmarkTest02019
import org.owasp.benchmark.testcode.BenchmarkTest02020
import org.owasp.benchmark.testcode.BenchmarkTest02021
import org.owasp.benchmark.testcode.BenchmarkTest02022
import org.owasp.benchmark.testcode.BenchmarkTest02023
import org.owasp.benchmark.testcode.BenchmarkTest02024
import org.owasp.benchmark.testcode.BenchmarkTest02025
import org.owasp.benchmark.helpers.LDAPManager
import javax.naming.directory.DirContext
import javax.naming.directory.SearchControls
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import org.owasp.benchmark.testcode.BenchmarkTest02026
import org.owasp.benchmark.testcode.BenchmarkTest02027
import org.owasp.benchmark.testcode.BenchmarkTest02028
import org.owasp.benchmark.testcode.BenchmarkTest02029
import org.owasp.benchmark.testcode.BenchmarkTest02030
import java.net.URISyntaxException
import org.owasp.benchmark.testcode.BenchmarkTest02031
import java.io.FileInputStream
import org.owasp.benchmark.testcode.BenchmarkTest02032
import org.owasp.benchmark.testcode.BenchmarkTest02033
import java.io.FileOutputStream
import org.owasp.benchmark.testcode.BenchmarkTest02034
import org.owasp.benchmark.testcode.BenchmarkTest02035
import org.owasp.benchmark.testcode.BenchmarkTest02036
import javax.naming.directory.InitialDirContext
import org.owasp.benchmark.testcode.BenchmarkTest02037
import org.owasp.benchmark.testcode.BenchmarkTest02038
import org.owasp.benchmark.testcode.BenchmarkTest02039
import org.owasp.benchmark.testcode.BenchmarkTest02040
import org.owasp.benchmark.testcode.BenchmarkTest02041
import java.security.MessageDigest
import org.owasp.benchmark.testcode.BenchmarkTest02042
import org.owasp.benchmark.testcode.BenchmarkTest02043
import org.owasp.benchmark.testcode.BenchmarkTest02044
import org.owasp.benchmark.testcode.BenchmarkTest02045
import java.io.PrintWriter
import org.owasp.benchmark.testcode.BenchmarkTest02046
import org.owasp.benchmark.testcode.BenchmarkTest02047
import org.owasp.benchmark.testcode.BenchmarkTest02048
import org.owasp.benchmark.testcode.BenchmarkTest02049
import org.owasp.benchmark.testcode.BenchmarkTest02050
import org.owasp.benchmark.testcode.BenchmarkTest02051
import org.owasp.benchmark.testcode.BenchmarkTest02052
import org.owasp.benchmark.testcode.BenchmarkTest02053
import org.owasp.benchmark.testcode.BenchmarkTest02054
import org.owasp.benchmark.testcode.BenchmarkTest02055
import org.owasp.benchmark.testcode.BenchmarkTest02056
import org.owasp.benchmark.testcode.BenchmarkTest02057
import org.owasp.benchmark.testcode.BenchmarkTest02058
import java.lang.ProcessBuilder
import org.owasp.benchmark.testcode.BenchmarkTest02059
import org.owasp.benchmark.testcode.BenchmarkTest02060
import org.owasp.benchmark.testcode.BenchmarkTest02061
import org.owasp.benchmark.testcode.BenchmarkTest02062
import org.owasp.benchmark.testcode.BenchmarkTest02063
import org.owasp.benchmark.testcode.BenchmarkTest02064
import org.owasp.benchmark.testcode.BenchmarkTest02065
import org.owasp.benchmark.testcode.BenchmarkTest02066
import org.owasp.benchmark.testcode.BenchmarkTest02067
import java.lang.Runtime
import org.owasp.benchmark.testcode.BenchmarkTest02068
import org.owasp.benchmark.testcode.BenchmarkTest02069
import org.owasp.benchmark.testcode.BenchmarkTest02070
import org.owasp.benchmark.testcode.BenchmarkTest02071
import org.owasp.benchmark.testcode.BenchmarkTest02072
import org.owasp.benchmark.testcode.BenchmarkTest02073
import org.owasp.benchmark.testcode.BenchmarkTest02074
import org.owasp.benchmark.testcode.BenchmarkTest02075
import org.owasp.benchmark.testcode.BenchmarkTest02076
import org.owasp.benchmark.testcode.BenchmarkTest02077
import org.owasp.benchmark.testcode.BenchmarkTest02078
import org.owasp.benchmark.testcode.BenchmarkTest02079
import org.owasp.benchmark.testcode.BenchmarkTest02080
import org.owasp.benchmark.testcode.BenchmarkTest02081
import org.owasp.benchmark.testcode.BenchmarkTest02082
import org.owasp.benchmark.testcode.BenchmarkTest02083
import org.owasp.benchmark.testcode.BenchmarkTest02084
import org.owasp.benchmark.testcode.BenchmarkTest02085
import org.owasp.benchmark.testcode.BenchmarkTest02086
import org.owasp.benchmark.testcode.BenchmarkTest02087
import java.sql.PreparedStatement
import java.sql.SQLException
import org.owasp.benchmark.testcode.BenchmarkTest02088
import org.owasp.benchmark.testcode.BenchmarkTest02089
import org.owasp.benchmark.testcode.BenchmarkTest02090
import org.springframework.dao.DataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02091
import org.springframework.dao.EmptyResultDataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02092
import org.owasp.benchmark.testcode.BenchmarkTest02093
import org.owasp.benchmark.testcode.BenchmarkTest02094
import org.owasp.benchmark.testcode.BenchmarkTest02095
import org.owasp.benchmark.testcode.BenchmarkTest02096
import org.owasp.benchmark.testcode.BenchmarkTest02097
import org.owasp.benchmark.testcode.BenchmarkTest02098
import org.owasp.benchmark.testcode.BenchmarkTest02099
import org.owasp.benchmark.testcode.BenchmarkTest02100
import java.net.URLDecoder
import java.security.SecureRandom
import javax.servlet.http.Cookie

@WebServlet(value = ["/weakrand-04/BenchmarkTest02078"])
class BenchmarkTest02078 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param: String? = ""
        val headers = request.getHeaders("BenchmarkTest02078")
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement() // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = URLDecoder.decode(param, "UTF-8")
        val bar = doSomething(request, param)
        try {
            val rand = SecureRandom.getInstance("SHA1PRNG").nextDouble()
            val rememberMeKey = java.lang.Double.toString(rand).substring(2) // Trim off the 0. at the front.
            var user = "SafeDonna"
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
                rememberMe.path = request.requestURI // i.e., set path to JUST this servlet 
                // e.g., /benchmark/sql-01/BenchmarkTest01001
                request.session.setAttribute(cookieName, rememberMeKey)
                response.addCookie(rememberMe)
                response.writer.println(
                    user + " has been remembered with cookie: " + rememberMe.name
                            + " whose value is: " + rememberMe.value + "<br/>"
                )
            }
        } catch (e: NoSuchAlgorithmException) {
            println("Problem executing SecureRandom.nextDouble() - TestCase")
            throw ServletException(e)
        }
        response.writer.println(
            "Weak Randomness Test java.security.SecureRandom.nextDouble() executed"
        )
    } // end doPost

    companion object {
        private const val serialVersionUID = 1L
        @Throws(ServletException::class, IOException::class)
        private fun doSomething(request: HttpServletRequest, param: String?): String? {
            var bar = param
            if (param != null && param.length > 1) {
                bar = param.substring(0, param.length - 1)
            }
            return bar
        }
    }
}