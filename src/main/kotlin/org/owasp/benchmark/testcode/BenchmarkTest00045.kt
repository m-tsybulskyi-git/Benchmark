/**
 * OWASP Benchmark v1.2
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
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.io.FileInputStream
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.io.FileWriter
import java.security.NoSuchAlgorithmException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.security.InvalidAlgorithmParameterException
import java.lang.ProcessBuilder
import java.lang.Runtime
import java.sql.CallableStatement
import java.sql.SQLException
import java.util.Enumeration
import org.owasp.benchmark.helpers.LDAPManager
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import java.sql.PreparedStatement
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.dao.DataAccessException
import org.springframework.jdbc.support.rowset.SqlRowSet
import org.owasp.benchmark.helpers.SeparateClassRequest
import javax.crypto.spec.GCMParameterSpec
import java.lang.StringBuilder
import org.owasp.benchmark.helpers.ThingInterface
import org.owasp.benchmark.helpers.Utils
import org.owasp.esapi.ESAPI
import java.lang.Exception

@WebServlet(value = ["/pathtraver-00/BenchmarkTest00045"])
class BenchmarkTest00045 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        // some code
        response.contentType = "text/html;charset=UTF-8"
        val values = request.getParameterValues("BenchmarkTest00045")
        val param: String
        param = if (values != null && values.size > 0) values[0] else ""
        val fileName = Utils.TESTFILES_DIR + param
        try {
            FileOutputStream(
                FileInputStream(fileName).fd
            ).use { fos ->
                response.writer.println(
                    "Now ready to write to file: " + ESAPI.encoder().encodeForHTML(fileName)
                )
            }
        } catch (e: Exception) {
            println("Couldn't open FileOutputStream on file: '$fileName'")
        }
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}