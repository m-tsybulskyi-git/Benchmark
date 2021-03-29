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

@WebServlet(value = ["/pathtraver-01/BenchmarkTest00866"])
class BenchmarkTest00866 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val scr = SeparateClassRequest(request)
        val param = scr.getTheValue("BenchmarkTest00866")
        val thing = ThingFactory.createThing()
        val bar = thing.doSomething(param)
        var fileName: String? = null
        var fos: FileOutputStream? = null
        try {
            fileName = Utils.TESTFILES_DIR + bar
            fos = FileOutputStream(File(fileName))
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