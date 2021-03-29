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
import java.util.Enumeration
import javax.crypto.spec.GCMParameterSpec
import java.lang.ProcessBuilder
import java.sql.CallableStatement
import javax.naming.directory.InitialDirContext
import org.owasp.esapi.ESAPI
import java.util.HashMap

@WebServlet(value = ["/sqli-02/BenchmarkTest01309"])
class BenchmarkTest01309 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param = request.getParameter("BenchmarkTest01309")
        if (param == null) param = ""
        val bar: String = Test().doSomething(request, param)
        val sql = "SELECT TOP 1 USERNAME from USERS where USERNAME='foo' and PASSWORD='$bar'"
        try {
            val results: Any = DatabaseHelper.JDBCtemplate.queryForObject(sql, arrayOf(), String::class.java)
            response.writer.println(
                "Your results are: "
            )

            //		System.out.println("Your results are");
            response.writer.println(
                ESAPI.encoder().encodeForHTML(results.toString())
            )
            //		System.out.println(results.toString());
        } catch (e: EmptyResultDataAccessException) {
            response.writer.println(
                "No results returned for query: " + ESAPI.encoder().encodeForHTML(sql)
            )
        } catch (e: DataAccessException) {
            if (DatabaseHelper.hideSQLErrors) {
                response.writer.println(
                    "Error processing request."
                )
            } else throw ServletException(e)
        }
    } // end doPost

    private inner class Test {
        @Throws(ServletException::class, IOException::class)
        fun doSomething(request: HttpServletRequest?, param: String): String {

            // Chain a bunch of propagators in sequence
            val b9334 = StringBuilder(
                param //assign
            ) // stick in stringbuilder
            b9334.append(" SafeStuff") // append some safe content
            b9334.replace(b9334.length - "Chars".length, b9334.length, "Chars") //replace some of the end content
            val map9334 = HashMap<String, Any>()
            map9334["key9334"] = b9334.toString() // put in a collection
            val c9334 = map9334["key9334"] as String? // get it back out
            val d9334 = c9334!!.substring(0, c9334.length - 1) // extract most of it
            val e9334 = String(
                Base64.decodeBase64(
                    Base64.encodeBase64(d9334.toByteArray())
                )
            ) // B64 encode and decode it
            val f9334 = e9334.split(" ".toRegex()).toTypedArray()[0] // split it on a space
            val thing = ThingFactory.createThing()
            val g9334 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
            return thing.doSomething(g9334) // reflection
        }
    } // end innerclass Test

    companion object {
        private const val serialVersionUID = 1L
    }
} // end DataflowThruInnerClass
