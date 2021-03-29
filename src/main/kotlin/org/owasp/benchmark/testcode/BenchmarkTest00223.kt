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
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.sql.PreparedStatement
import java.sql.SQLException
import org.owasp.benchmark.helpers.ThingInterface
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.dao.DataAccessException
import java.lang.StringBuilder
import javax.crypto.Cipher
import javax.crypto.SecretKey
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import javax.crypto.spec.GCMParameterSpec
import org.owasp.benchmark.helpers.LDAPManager
import org.owasp.benchmark.helpers.Utils
import org.owasp.esapi.ESAPI
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import java.lang.ProcessBuilder
import java.lang.Runtime
import java.sql.CallableStatement
import java.net.URISyntaxException
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.io.*
import java.security.*
import java.util.*

@WebServlet(value = ["/hash-00/BenchmarkTest00223"])
class BenchmarkTest00223 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param = ""
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
        var bar: String? = "safe!"
        val map13848 = HashMap<String, Any>()
        map13848["keyA-13848"] = "a-Value" // put some stuff in the collection
        map13848["keyB-13848"] = param // put it in a collection
        map13848["keyC"] = "another-Value" // put some stuff in the collection
        bar = map13848["keyB-13848"] as String? // get it back out
        val provider = Security.getProviders()
        val md: MessageDigest
        try {
            md = if (provider.size > 1) {
                MessageDigest.getInstance("SHA1", provider[0])
            } else {
                MessageDigest.getInstance("SHA1", "SUN")
            }
            var input: ByteArray? = byteArrayOf('?'.toByte())
            val inputParam: Any? = bar
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
            println("Problem executing hash - TestCase java.security.MessageDigest.getInstance(java.lang.String,java.security.Provider)")
            throw ServletException(e)
        } catch (e: NoSuchProviderException) {
            println("Problem executing hash - TestCase java.security.MessageDigest.getInstance(java.lang.String,java.security.Provider)")
            throw ServletException(e)
        }
        response.writer.println(
            "Hash Test java.security.MessageDigest.getInstance(java.lang.String,java.security.Provider) executed"
        )
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}