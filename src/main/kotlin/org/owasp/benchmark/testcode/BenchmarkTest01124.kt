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

import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServlet
import kotlin.Throws
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.sql.PreparedStatement
import java.sql.SQLException
import org.springframework.dao.DataAccessException
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.jdbc.support.rowset.SqlRowSet
import javax.crypto.Cipher
import javax.crypto.SecretKey
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
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
import java.security.MessageDigest
import java.lang.Runtime
import javax.crypto.spec.GCMParameterSpec
import java.lang.ProcessBuilder
import java.sql.CallableStatement
import javax.naming.directory.InitialDirContext
import org.owasp.benchmark.helpers.SeparateClassRequest
import org.owasp.benchmark.helpers.Utils
import org.owasp.esapi.ESAPI
import java.io.*
import java.util.*

@WebServlet(value = ["/hash-01/BenchmarkTest01124"])
class BenchmarkTest01124 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param: String? = ""
        val names = request.headerNames
        while (names.hasMoreElements()) {
            val name = names.nextElement() as String
            if (Utils.commonHeaders.contains(name)) {
                continue
            }
            val values = request.getHeaders(name)
            if (values != null && values.hasMoreElements()) {
                param = name
                break
            }
        }
        // Note: We don't URL decode header names because people don't normally do that
        val bar: String? = param?.let { Test().doSomething(request, it) }
        bar ?: return
        try {
            val benchmarkprops = Properties()
            benchmarkprops.load(this.javaClass.classLoader.getResourceAsStream("benchmark.properties"))
            val algorithm = benchmarkprops.getProperty("hashAlg1", "SHA512")
            val md = MessageDigest.getInstance(algorithm)
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
    } // end doPost

    private inner class Test {
        @Throws(ServletException::class, IOException::class)
        fun doSomething(request: HttpServletRequest?, param: String): String? {
            var bar: String? = "safe!"
            val map74702 = HashMap<String, Any>()
            map74702["keyA-74702"] = "a_Value" // put some stuff in the collection
            map74702["keyB-74702"] = param // put it in a collection
            map74702["keyC"] = "another_Value" // put some stuff in the collection
            bar = map74702["keyB-74702"] as String? // get it back out
            bar = map74702["keyA-74702"] as String? // get safe value back out
            return bar
        }
    } // end innerclass Test

    companion object {
        private const val serialVersionUID = 1L
    }
} // end DataflowThruInnerClass
