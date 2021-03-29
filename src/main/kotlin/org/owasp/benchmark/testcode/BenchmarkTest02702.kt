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
import org.owasp.benchmark.helpers.SeparateClassRequest
import org.owasp.benchmark.testcode.BenchmarkTest02701
import java.lang.StringBuilder
import org.owasp.benchmark.testcode.BenchmarkTest02702
import org.owasp.benchmark.testcode.BenchmarkTest02703
import org.owasp.benchmark.testcode.BenchmarkTest02704
import org.owasp.benchmark.testcode.BenchmarkTest02705
import org.owasp.benchmark.testcode.BenchmarkTest02706
import org.owasp.benchmark.testcode.BenchmarkTest02707
import org.owasp.benchmark.testcode.BenchmarkTest02708
import org.owasp.benchmark.testcode.BenchmarkTest02709
import org.owasp.benchmark.testcode.BenchmarkTest02710
import org.owasp.benchmark.testcode.BenchmarkTest02711
import org.owasp.benchmark.testcode.BenchmarkTest02712
import org.owasp.benchmark.testcode.BenchmarkTest02713
import java.lang.Runtime
import java.io.File
import org.owasp.benchmark.testcode.BenchmarkTest02714
import org.owasp.benchmark.testcode.BenchmarkTest02715
import java.security.NoSuchAlgorithmException
import org.owasp.benchmark.testcode.BenchmarkTest02716
import org.owasp.benchmark.helpers.ThingInterface
import org.owasp.benchmark.testcode.BenchmarkTest02717
import org.owasp.benchmark.testcode.BenchmarkTest02718
import org.owasp.benchmark.testcode.BenchmarkTest02719
import org.owasp.benchmark.testcode.BenchmarkTest02720
import org.owasp.benchmark.testcode.BenchmarkTest02721
import org.owasp.benchmark.testcode.BenchmarkTest02722
import org.owasp.benchmark.testcode.BenchmarkTest02723
import org.owasp.benchmark.testcode.BenchmarkTest02724
import org.owasp.benchmark.testcode.BenchmarkTest02725
import org.owasp.benchmark.testcode.BenchmarkTest02726
import org.owasp.benchmark.testcode.BenchmarkTest02727
import java.sql.PreparedStatement
import java.sql.SQLException
import org.owasp.benchmark.testcode.BenchmarkTest02728
import org.owasp.benchmark.testcode.BenchmarkTest02729
import org.owasp.benchmark.testcode.BenchmarkTest02730
import org.owasp.benchmark.testcode.BenchmarkTest02731
import org.springframework.dao.DataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02732
import org.springframework.dao.EmptyResultDataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02733
import org.owasp.benchmark.testcode.BenchmarkTest02734
import org.owasp.benchmark.testcode.BenchmarkTest02735
import org.owasp.benchmark.testcode.BenchmarkTest02736
import org.owasp.benchmark.testcode.BenchmarkTest02737
import org.springframework.jdbc.support.rowset.SqlRowSet
import org.owasp.benchmark.testcode.BenchmarkTest02738
import org.owasp.benchmark.testcode.BenchmarkTest02739
import org.owasp.benchmark.testcode.BenchmarkTest02740
import java.net.URL
import java.util.*
import javax.servlet.http.Cookie

@WebServlet(value = ["/weakrand-05/BenchmarkTest02702"])
class BenchmarkTest02702 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val scr = SeparateClassRequest(request)
        val param = scr.getTheValue("BenchmarkTest02702")
        val bar = doSomething(request, param)
        val value = Random().nextDouble()
        val rememberMeKey = java.lang.Double.toString(value).substring(2) // Trim off the 0. at the front.
        var user = "Donna"
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
            "Weak Randomness Test java.util.Random.nextDouble() executed"
        )
    } // end doPost

    companion object {
        private const val serialVersionUID = 1L
        @Throws(ServletException::class, IOException::class)
        private fun doSomething(request: HttpServletRequest, param: String): String {
            val bar: String

            // Simple ? condition that assigns param to bar on false condition
            val num = 106
            bar = if (7 * 42 - num > 200) "This should never happen" else param
            return bar
        }
    }
}