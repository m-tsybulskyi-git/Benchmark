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
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.lang.StringBuilder
import java.lang.Runtime
import java.security.NoSuchAlgorithmException
import java.sql.PreparedStatement
import java.sql.SQLException
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.dao.DataAccessException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.security.InvalidAlgorithmParameterException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import java.net.URISyntaxException
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
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.io.*
import java.lang.Exception
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.util.HashMap

@WebServlet(value = ["/pathtraver-00/BenchmarkTest00460"])
class BenchmarkTest00460 : HttpServlet() {
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
            val values = map["BenchmarkTest00460"]
            if (values != null) param = values[0]
        }


        // Chain a bunch of propagators in sequence
        val a62588 = param //assign
        val b62588 = StringBuilder(a62588) // stick in stringbuilder
        b62588.append(" SafeStuff") // append some safe content
        b62588.replace(b62588.length - "Chars".length, b62588.length, "Chars") //replace some of the end content
        val map62588 = HashMap<String, Any>()
        map62588["key62588"] = b62588.toString() // put in a collection
        val c62588 = map62588["key62588"] as String? // get it back out
        val d62588 = c62588!!.substring(0, c62588.length - 1) // extract most of it
        val e62588 = String(
            Base64.decodeBase64(
                Base64.encodeBase64(d62588.toByteArray())
            )
        ) // B64 encode and decode it
        val f62588 = e62588.split(" ".toRegex()).toTypedArray()[0] // split it on a space
        val thing = ThingFactory.createThing()
        val g62588 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
        val bar = thing.doSomething(g62588) // reflection
        val fileName = Utils.TESTFILES_DIR + bar
        var `is`: InputStream? = null
        try {
            val path = Paths.get(fileName)
            `is` = Files.newInputStream(path, StandardOpenOption.READ)
            val b = ByteArray(1000)
            val size = `is`.read(b)
            response.writer.println(
                """
                    The beginning of file: '${ESAPI.encoder().encodeForHTML(fileName)}' is:
                    
                    
                    """.trimIndent()
            )
            response.writer.println(
                ESAPI.encoder().encodeForHTML(String(b, 0, size))
            )
            `is`.close()
        } catch (e: Exception) {
            println("Couldn't open InputStream on file: '$fileName'")
            response.writer.println(
                "Problem getting InputStream: "
                        + ESAPI.encoder().encodeForHTML(e.message)
            )
        } finally {
            if (`is` != null) {
                try {
                    `is`.close()
                    `is` = null
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