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

import org.apache.commons.codec.binary.Base64
import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServlet
import kotlin.Throws
import javax.servlet.ServletException
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.sql.PreparedStatement
import java.sql.SQLException
import org.owasp.benchmark.helpers.ThingInterface
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.dao.DataAccessException
import java.lang.StringBuilder
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
import javax.crypto.spec.GCMParameterSpec
import java.io.FileOutputStream
import org.owasp.benchmark.helpers.LDAPManager
import org.owasp.benchmark.helpers.ThingFactory
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import java.security.MessageDigest
import java.lang.ProcessBuilder
import java.lang.Runtime
import java.sql.CallableStatement
import java.util.Enumeration
import java.net.URISyntaxException
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.net.URLDecoder
import java.security.SecureRandom
import java.util.HashMap
import javax.servlet.http.Cookie

@WebServlet(value = ["/weakrand-00/BenchmarkTest00316"])
class BenchmarkTest00316 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param = ""
        val headers = request.getHeaders("BenchmarkTest00316")
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement() // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = URLDecoder.decode(param, "UTF-8")


        // Chain a bunch of propagators in sequence
        val a78780 = param //assign
        val b78780 = StringBuilder(a78780) // stick in stringbuilder
        b78780.append(" SafeStuff") // append some safe content
        b78780.replace(b78780.length - "Chars".length, b78780.length, "Chars") //replace some of the end content
        val map78780 = HashMap<String, Any>()
        map78780["key78780"] = b78780.toString() // put in a collection
        val c78780 = map78780["key78780"] as String? // get it back out
        val d78780 = c78780!!.substring(0, c78780.length - 1) // extract most of it
        val e78780 = String(
            Base64.decodeBase64(
                Base64.encodeBase64(d78780.toByteArray())
            )
        ) // B64 encode and decode it
        val f78780 = e78780.split(" ".toRegex()).toTypedArray()[0] // split it on a space
        val thing = ThingFactory.createThing()
        val bar = thing.doSomething(f78780) // reflection
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
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}