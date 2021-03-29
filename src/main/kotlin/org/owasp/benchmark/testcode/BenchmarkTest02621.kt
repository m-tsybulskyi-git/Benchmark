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
import org.owasp.benchmark.testcode.BenchmarkTest02601
import org.owasp.benchmark.testcode.BenchmarkTest02602
import java.lang.StringBuilder
import org.owasp.benchmark.helpers.ThingInterface
import org.owasp.benchmark.testcode.BenchmarkTest02603
import org.owasp.benchmark.testcode.BenchmarkTest02604
import org.owasp.benchmark.testcode.BenchmarkTest02605
import org.owasp.benchmark.testcode.BenchmarkTest02606
import org.owasp.benchmark.testcode.BenchmarkTest02607
import org.owasp.benchmark.testcode.BenchmarkTest02608
import org.owasp.benchmark.testcode.BenchmarkTest02609
import org.owasp.benchmark.testcode.BenchmarkTest02610
import java.lang.Runtime
import org.owasp.benchmark.testcode.BenchmarkTest02611
import java.io.File
import org.owasp.benchmark.testcode.BenchmarkTest02612
import org.owasp.benchmark.testcode.BenchmarkTest02613
import org.owasp.benchmark.testcode.BenchmarkTest02614
import java.security.NoSuchAlgorithmException
import org.owasp.benchmark.testcode.BenchmarkTest02615
import org.owasp.benchmark.testcode.BenchmarkTest02616
import org.owasp.benchmark.testcode.BenchmarkTest02617
import org.owasp.benchmark.testcode.BenchmarkTest02618
import org.owasp.benchmark.testcode.BenchmarkTest02619
import org.owasp.benchmark.testcode.BenchmarkTest02620
import org.owasp.benchmark.testcode.BenchmarkTest02621
import org.owasp.benchmark.testcode.BenchmarkTest02622
import org.owasp.benchmark.testcode.BenchmarkTest02623
import org.owasp.benchmark.testcode.BenchmarkTest02624
import org.owasp.benchmark.testcode.BenchmarkTest02625
import java.sql.CallableStatement
import java.sql.SQLException
import org.owasp.benchmark.testcode.BenchmarkTest02626
import org.owasp.benchmark.testcode.BenchmarkTest02627
import org.owasp.benchmark.testcode.BenchmarkTest02628
import org.owasp.benchmark.testcode.BenchmarkTest02629
import org.owasp.benchmark.testcode.BenchmarkTest02630
import org.owasp.benchmark.testcode.BenchmarkTest02631
import java.sql.PreparedStatement
import org.owasp.benchmark.testcode.BenchmarkTest02632
import org.owasp.benchmark.testcode.BenchmarkTest02633
import org.owasp.benchmark.testcode.BenchmarkTest02634
import org.owasp.benchmark.testcode.BenchmarkTest02635
import org.owasp.benchmark.testcode.BenchmarkTest02636
import org.owasp.benchmark.testcode.BenchmarkTest02637
import org.owasp.benchmark.testcode.BenchmarkTest02638
import org.springframework.dao.DataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02639
import org.owasp.benchmark.testcode.BenchmarkTest02640
import org.owasp.benchmark.testcode.BenchmarkTest02641
import org.springframework.dao.EmptyResultDataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02642
import org.owasp.benchmark.testcode.BenchmarkTest02643
import org.owasp.benchmark.testcode.BenchmarkTest02644
import org.springframework.jdbc.support.rowset.SqlRowSet
import org.owasp.benchmark.testcode.BenchmarkTest02645
import org.owasp.benchmark.testcode.BenchmarkTest02646
import org.owasp.benchmark.testcode.BenchmarkTest02647
import org.owasp.benchmark.testcode.BenchmarkTest02648
import org.owasp.benchmark.testcode.BenchmarkTest02649
import org.owasp.benchmark.testcode.BenchmarkTest02650
import org.owasp.benchmark.testcode.BenchmarkTest02651
import org.owasp.benchmark.testcode.BenchmarkTest02652
import org.owasp.benchmark.testcode.BenchmarkTest02653
import org.owasp.benchmark.testcode.BenchmarkTest02654
import org.owasp.benchmark.testcode.BenchmarkTest02655
import org.owasp.benchmark.testcode.BenchmarkTest02656
import org.owasp.benchmark.testcode.BenchmarkTest02657
import org.owasp.benchmark.helpers.SeparateClassRequest
import org.owasp.benchmark.testcode.BenchmarkTest02658
import javax.crypto.Cipher
import javax.crypto.SecretKey
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import java.io.FileWriter
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.security.InvalidAlgorithmParameterException
import org.owasp.benchmark.testcode.BenchmarkTest02659
import javax.crypto.spec.GCMParameterSpec
import org.owasp.benchmark.testcode.BenchmarkTest02660
import org.owasp.benchmark.testcode.BenchmarkTest02661
import org.owasp.benchmark.testcode.BenchmarkTest02662
import org.owasp.benchmark.testcode.BenchmarkTest02663
import org.owasp.benchmark.testcode.BenchmarkTest02664
import org.owasp.benchmark.testcode.BenchmarkTest02665
import java.io.FileInputStream
import org.owasp.benchmark.testcode.BenchmarkTest02666
import org.owasp.benchmark.testcode.BenchmarkTest02667
import org.owasp.benchmark.testcode.BenchmarkTest02668
import java.io.FileOutputStream
import org.owasp.benchmark.testcode.BenchmarkTest02669
import org.owasp.benchmark.testcode.BenchmarkTest02670
import java.security.MessageDigest
import org.owasp.benchmark.testcode.BenchmarkTest02671
import org.owasp.benchmark.testcode.BenchmarkTest02672
import org.owasp.benchmark.testcode.BenchmarkTest02673
import org.owasp.benchmark.testcode.BenchmarkTest02674
import org.owasp.benchmark.testcode.BenchmarkTest02675
import org.owasp.benchmark.testcode.BenchmarkTest02676
import org.owasp.benchmark.testcode.BenchmarkTest02677
import org.owasp.benchmark.testcode.BenchmarkTest02678
import org.owasp.benchmark.testcode.BenchmarkTest02679
import java.io.PrintWriter
import org.owasp.benchmark.testcode.BenchmarkTest02680
import org.owasp.benchmark.testcode.BenchmarkTest02681
import org.owasp.benchmark.testcode.BenchmarkTest02682
import org.owasp.benchmark.testcode.BenchmarkTest02683
import org.owasp.benchmark.testcode.BenchmarkTest02684
import org.owasp.benchmark.testcode.BenchmarkTest02685
import org.owasp.benchmark.testcode.BenchmarkTest02686
import org.owasp.benchmark.testcode.BenchmarkTest02687
import org.owasp.benchmark.testcode.BenchmarkTest02688
import org.owasp.benchmark.testcode.BenchmarkTest02689
import org.owasp.benchmark.testcode.BenchmarkTest02690
import org.owasp.benchmark.testcode.BenchmarkTest02691
import org.owasp.benchmark.testcode.BenchmarkTest02692
import org.owasp.benchmark.testcode.BenchmarkTest02693
import org.owasp.benchmark.testcode.BenchmarkTest02694
import org.owasp.benchmark.testcode.BenchmarkTest02695
import org.owasp.benchmark.testcode.BenchmarkTest02696
import org.owasp.benchmark.testcode.BenchmarkTest02697
import java.lang.ProcessBuilder
import org.owasp.benchmark.testcode.BenchmarkTest02698
import org.owasp.benchmark.testcode.BenchmarkTest02699
import org.owasp.benchmark.testcode.BenchmarkTest02700
import java.net.URLDecoder
import java.security.SecureRandom
import javax.servlet.http.Cookie

@WebServlet(value = ["/weakrand-05/BenchmarkTest02621"])
class BenchmarkTest02621 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val queryString = request.queryString
        val paramval = "BenchmarkTest02621" + "="
        var paramLoc = -1
        if (queryString != null) paramLoc = queryString.indexOf(paramval)
        if (paramLoc == -1) {
            response.writer.println("getQueryString() couldn't find expected parameter '" + "BenchmarkTest02621" + "' in query string.")
            return
        }
        var param: String? =
            queryString!!.substring(paramLoc + paramval.length) // 1st assume "BenchmarkTest02621" param is last parameter in query string.
        // And then check to see if its in the middle of the query string and if so, trim off what comes after.
        val ampersandLoc = queryString.indexOf("&", paramLoc)
        if (ampersandLoc != -1) {
            param = queryString.substring(paramLoc + paramval.length, ampersandLoc)
        }
        param = URLDecoder.decode(param, "UTF-8")
        val bar = doSomething(request, param)
        try {
            val r = SecureRandom.getInstance("SHA1PRNG").nextInt()
            val rememberMeKey = Integer.toString(r)
            var user = "SafeIngrid"
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
            println("Problem executing SecureRandom.nextInt() - TestCase")
            throw ServletException(e)
        }
        response.writer.println(
            "Weak Randomness Test java.security.SecureRandom.nextInt() executed"
        )
    } // end doPost

    companion object {
        private const val serialVersionUID = 1L
        @Throws(ServletException::class, IOException::class)
        private fun doSomething(request: HttpServletRequest, param: String?): String? {
            var bar = param
            if (param != null && param.length > 1) {
                val sbxyz33448 = StringBuilder(param)
                bar = sbxyz33448.replace(param.length - "Z".length, param.length, "Z").toString()
            }
            return bar
        }
    }
}