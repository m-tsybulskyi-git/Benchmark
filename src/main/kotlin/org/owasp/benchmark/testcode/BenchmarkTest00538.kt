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
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.io.*
import java.util.*

@WebServlet(value = ["/hash-00/BenchmarkTest00538"])
class BenchmarkTest00538 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param = ""
        var flag = true
        val names = request.parameterNames
        while (names.hasMoreElements() && flag) {
            val name = names.nextElement() as String
            val values = request.getParameterValues(name)
            if (values != null) {
                var i = 0
                while (i < values.size && flag) {
                    val value = values[i]
                    if (value == "BenchmarkTest00538") {
                        param = name
                        flag = false
                    }
                    i++
                }
            }
        }


        // Chain a bunch of propagators in sequence
        val a75053 = param //assign
        val b75053 = StringBuilder(a75053) // stick in stringbuilder
        b75053.append(" SafeStuff") // append some safe content
        b75053.replace(b75053.length - "Chars".length, b75053.length, "Chars") //replace some of the end content
        val map75053 = HashMap<String, Any>()
        map75053["key75053"] = b75053.toString() // put in a collection
        val c75053 = map75053["key75053"] as String? // get it back out
        val d75053 = c75053!!.substring(0, c75053.length - 1) // extract most of it
        val e75053 = String(
            Base64.decodeBase64(
                Base64.encodeBase64(d75053.toByteArray())
            )
        ) // B64 encode and decode it
        val f75053 = e75053.split(" ".toRegex()).toTypedArray()[0] // split it on a space
        val thing = ThingFactory.createThing()
        val bar = thing.doSomething(f75053) // reflection
        try {
            val md = MessageDigest.getInstance("SHA-256")
            var input: ByteArray? = byteArrayOf('?'.toByte())
            val inputParam: Any = bar
            if (inputParam is String) input = inputParam.toByteArray()
            if (inputParam is InputStream) {
                val strInput = ByteArray(1000)
                val i = inputParam.read(strInput)
                if (i == -1) {
                    response.writer.println(
                        "This input source requires a POST, not a GET. Incompatible UI for the InputStream source."
                    )
                    return
                }
                input = Arrays.copyOf(strInput, i)
            }
            md.update(input)
            val result = md.digest()
            val fileTarget = File(
                File(Utils.TESTFILES_DIR), "passwordFile.txt"
            )
            val fw = FileWriter(fileTarget, true) //the true will append the new data
            fw.write(
                """
    hash_value=${ESAPI.encoder().encodeForBase64(result, true)}
    
    """.trimIndent()
            )
            fw.close()
            response.writer.println(
                "Sensitive value '" + ESAPI.encoder().encodeForHTML(String(input!!)) + "' hashed and stored<br/>"
            )
        } catch (e: NoSuchAlgorithmException) {
            println("Problem executing hash - TestCase")
            throw ServletException(e)
        }
        response.writer.println(
            "Hash Test java.security.MessageDigest.getInstance(java.lang.String) executed"
        )
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}