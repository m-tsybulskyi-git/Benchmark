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
import org.owasp.benchmark.helpers.Utils
import org.owasp.esapi.ESAPI
import java.io.PrintWriter
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.net.URI
import java.util.HashMap

@WebServlet(value = ["/pathtraver-00/BenchmarkTest00528"])
class BenchmarkTest00528 : HttpServlet() {
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
                    if (value == "BenchmarkTest00528") {
                        param = name
                        flag = false
                    }
                    i++
                }
            }
        }
        var bar: String? = "safe!"
        val map6751 = HashMap<String, Any>()
        map6751["keyA-6751"] = "a-Value" // put some stuff in the collection
        map6751["keyB-6751"] = param // put it in a collection
        map6751["keyC"] = "another-Value" // put some stuff in the collection
        bar = map6751["keyB-6751"] as String? // get it back out


        // FILE URIs are tricky because they are different between Mac and Windows because of lack of standardization.
        // Mac requires an extra slash for some reason.
        var startURIslashes = ""
        if (System.getProperty("os.name").indexOf("Windows") != -1) startURIslashes =
            if (System.getProperty("os.name").indexOf("Windows") != -1) "/" else "//"
        try {
            val fileURI = URI(
                "file", null, startURIslashes
                        + Utils.TESTFILES_DIR.replace('\\', File.separatorChar).replace(' ', '_') + bar, null, null
            )
            val fileTarget = File(fileURI)
            response.writer.println(
                "Access to file: '" + ESAPI.encoder().encodeForHTML(fileTarget.toString()) + "' created."
            )
            if (fileTarget.exists()) {
                response.writer.println(
                    " And file already exists."
                )
            } else {
                response.writer.println(
                    " But file doesn't exist yet."
                )
            }
        } catch (e: URISyntaxException) {
            throw ServletException(e)
        }
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}