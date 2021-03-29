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
import org.owasp.benchmark.helpers.ThingFactory
import org.owasp.esapi.ESAPI
import java.net.URLDecoder
import java.security.SecureRandom
import java.util.*
import javax.servlet.http.Cookie

@WebServlet(value = ["/weakrand-02/BenchmarkTest01070"])
class BenchmarkTest01070 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param: String? = ""
        if (request.getHeader("BenchmarkTest01070") != null) {
            param = request.getHeader("BenchmarkTest01070")
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = URLDecoder.decode(param, "UTF-8")
        val bar: String = Test().doSomething(request, param)
        try {
            val numGen: Random = SecureRandom.getInstance("SHA1PRNG")

            // Get 40 random bytes
            val randomBytes = ByteArray(40)
            getNextNumber(numGen, randomBytes)
            val rememberMeKey = ESAPI.encoder().encodeForBase64(randomBytes, true)
            var user = "SafeBystander"
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
            println("Problem executing SecureRandom.nextBytes() - TestCase")
            throw ServletException(e)
        } finally {
            response.writer.println(
                "Randomness Test java.security.SecureRandom.nextBytes(byte[]) executed"
            )
        }
    } // end doPost

    fun getNextNumber(generator: Random, barray: ByteArray?) {
        generator.nextBytes(barray)
    }

    private inner class Test {
        @Throws(ServletException::class, IOException::class)
        fun doSomething(request: HttpServletRequest?, param: String): String {

            // Chain a bunch of propagators in sequence
            val b85812 = StringBuilder(
                param //assign
            ) // stick in stringbuilder
            b85812.append(" SafeStuff") // append some safe content
            b85812.replace(b85812.length - "Chars".length, b85812.length, "Chars") //replace some of the end content
            val map85812 = HashMap<String, Any>()
            map85812["key85812"] = b85812.toString() // put in a collection
            val c85812 = map85812["key85812"] as String? // get it back out
            val d85812 = c85812!!.substring(0, c85812.length - 1) // extract most of it
            val e85812 = String(
                Base64.decodeBase64(
                    Base64.encodeBase64(d85812.toByteArray())
                )
            ) // B64 encode and decode it
            val f85812 = e85812.split(" ".toRegex()).toTypedArray()[0] // split it on a space
            val thing = ThingFactory.createThing()
            return thing.doSomething(f85812) // reflection
        }
    } // end innerclass Test

    companion object {
        private const val serialVersionUID = 1L
    }
} // end DataflowThruInnerClass
