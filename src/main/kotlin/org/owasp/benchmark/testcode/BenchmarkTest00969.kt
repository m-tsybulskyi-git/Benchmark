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
import org.owasp.benchmark.helpers.*
import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServlet
import kotlin.Throws
import javax.servlet.ServletException
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.lang.StringBuilder
import java.lang.Runtime
import java.io.File
import java.security.NoSuchAlgorithmException
import java.sql.PreparedStatement
import java.sql.SQLException
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.dao.DataAccessException
import java.io.FileInputStream
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.io.FileWriter
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.security.InvalidAlgorithmParameterException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import java.net.URISyntaxException
import java.io.FileOutputStream
import java.security.MessageDigest
import java.lang.ProcessBuilder
import java.sql.CallableStatement
import java.util.Enumeration
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import java.io.PrintWriter
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.net.URL
import java.net.URLDecoder
import java.util.ArrayList
import java.util.HashMap
import javax.servlet.http.Cookie

@WebServlet(value = ["/cmdi-01/BenchmarkTest00969"])
class BenchmarkTest00969 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val userCookie = Cookie("BenchmarkTest00969", "ECHOOO")
        userCookie.maxAge = 60 * 3 //Store cookie for 3 minutes
        userCookie.secure = true
        userCookie.path = request.requestURI
        userCookie.domain = URL(request.requestURL.toString()).host
        response.addCookie(userCookie)
        val rd = request.getRequestDispatcher("/cmdi-01/BenchmarkTest00969.html")
        rd.include(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val theCookies = request.cookies
        var param: String? = "noCookieValueSupplied"
        if (theCookies != null) {
            for (theCookie in theCookies) {
                if (theCookie.name == "BenchmarkTest00969") {
                    param = URLDecoder.decode(theCookie.value, "UTF-8")
                    break
                }
            }
        }
        val bar: String? = param?.let { Test().doSomething(request, it) }
        bar ?: return
        val argList: MutableList<String> = ArrayList()
        val osName = System.getProperty("os.name")
        if (osName.indexOf("Windows") != -1) {
            argList.add("cmd.exe")
            argList.add("/c")
        } else {
            argList.add("sh")
            argList.add("-c")
        }
        argList.add("echo $bar")
        val pb = ProcessBuilder(argList)
        try {
            val p = pb.start()
            Utils.printOSCommandResults(p, response)
        } catch (e: IOException) {
            println("Problem executing cmdi - java.lang.ProcessBuilder(java.util.List) Test Case")
            throw ServletException(e)
        }
    } // end doPost

    private inner class Test {
        @Throws(ServletException::class, IOException::class)
        fun doSomething(request: HttpServletRequest?, param: String): String {

            // Chain a bunch of propagators in sequence
            val b10263 = StringBuilder(
                param //assign
            ) // stick in stringbuilder
            b10263.append(" SafeStuff") // append some safe content
            b10263.replace(b10263.length - "Chars".length, b10263.length, "Chars") //replace some of the end content
            val map10263 = HashMap<String, Any>()
            map10263["key10263"] = b10263.toString() // put in a collection
            val c10263 = map10263["key10263"] as String? // get it back out
            val d10263 = c10263!!.substring(0, c10263.length - 1) // extract most of it
            val e10263 = String(
                Base64.decodeBase64(
                    Base64.encodeBase64(d10263.toByteArray())
                )
            ) // B64 encode and decode it
            val f10263 = e10263.split(" ".toRegex()).toTypedArray()[0] // split it on a space
            val thing = ThingFactory.createThing()
            val g10263 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
            return thing.doSomething(g10263) // reflection
        }
    } // end innerclass Test

    companion object {
        private const val serialVersionUID = 1L
    }
} // end DataflowThruInnerClass
