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
import java.lang.StringBuilder
import java.lang.Runtime
import java.io.File
import org.owasp.benchmark.helpers.ThingInterface
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
import org.owasp.benchmark.helpers.LDAPManager
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import org.owasp.benchmark.helpers.SeparateClassRequest
import org.owasp.benchmark.helpers.ThingFactory
import java.io.PrintWriter
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.util.HashMap

@WebServlet(value = ["/xss-01/BenchmarkTest00650"])
class BenchmarkTest00650 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val scr = SeparateClassRequest(request)
        var param = scr.getTheParameter("BenchmarkTest00650")
        if (param == null) param = ""


        // Chain a bunch of propagators in sequence
        val a17321 = param //assign
        val b17321 = StringBuilder(a17321) // stick in stringbuilder
        b17321.append(" SafeStuff") // append some safe content
        b17321.replace(b17321.length - "Chars".length, b17321.length, "Chars") //replace some of the end content
        val map17321 = HashMap<String, Any>()
        map17321["key17321"] = b17321.toString() // put in a collection
        val c17321 = map17321["key17321"] as String? // get it back out
        val d17321 = c17321!!.substring(0, c17321.length - 1) // extract most of it
        val e17321 = String(
            Base64.decodeBase64(
                Base64.encodeBase64(d17321.toByteArray())
            )
        ) // B64 encode and decode it
        val f17321 = e17321.split(" ".toRegex()).toTypedArray()[0] // split it on a space
        val thing = ThingFactory.createThing()
        val g17321 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
        val bar = thing.doSomething(g17321) // reflection
        response.setHeader("X-XSS-Protection", "0")
        response.writer.write(bar.toCharArray())
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}