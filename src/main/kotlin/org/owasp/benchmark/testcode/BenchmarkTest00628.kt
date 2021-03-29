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
import org.owasp.benchmark.helpers.*
import org.owasp.esapi.ESAPI
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
import java.lang.Exception
import java.util.HashMap

@WebServlet(value = ["/pathtraver-00/BenchmarkTest00628"])
class BenchmarkTest00628 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val scr = SeparateClassRequest(request)
        var param = scr.getTheParameter("BenchmarkTest00628")
        if (param == null) param = ""


        // Chain a bunch of propagators in sequence
        val a24315 = param //assign
        val b24315 = StringBuilder(a24315) // stick in stringbuilder
        b24315.append(" SafeStuff") // append some safe content
        b24315.replace(b24315.length - "Chars".length, b24315.length, "Chars") //replace some of the end content
        val map24315 = HashMap<String, Any>()
        map24315["key24315"] = b24315.toString() // put in a collection
        val c24315 = map24315["key24315"] as String? // get it back out
        val d24315 = c24315!!.substring(0, c24315.length - 1) // extract most of it
        val e24315 = String(
            Base64.decodeBase64(
                Base64.encodeBase64(d24315.toByteArray())
            )
        ) // B64 encode and decode it
        val f24315 = e24315.split(" ".toRegex()).toTypedArray()[0] // split it on a space
        val thing = ThingFactory.createThing()
        val g24315 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
        val bar = thing.doSomething(g24315) // reflection
        var fileName: String? = null
        var fos: FileOutputStream? = null
        try {
            fileName = Utils.TESTFILES_DIR + bar
            fos = FileOutputStream(fileName)
            response.writer.println(
                "Now ready to write to file: " + ESAPI.encoder().encodeForHTML(fileName)
            )
        } catch (e: Exception) {
            println("Couldn't open FileOutputStream on file: '$fileName'")
            //			System.out.println("File exception caught and swallowed: " + e.getMessage());
        } finally {
            if (fos != null) {
                try {
                    fos.close()
                    fos = null
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