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
import java.sql.ResultSet
import java.util.HashMap

@WebServlet(value = ["/sqli-01/BenchmarkTest00592"])
class BenchmarkTest00592 : HttpServlet() {
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
                    if (value == "BenchmarkTest00592") {
                        param = name
                        flag = false
                    }
                    i++
                }
            }
        }


        // Chain a bunch of propagators in sequence
        val a36502 = param //assign
        val b36502 = StringBuilder(a36502) // stick in stringbuilder
        b36502.append(" SafeStuff") // append some safe content
        b36502.replace(b36502.length - "Chars".length, b36502.length, "Chars") //replace some of the end content
        val map36502 = HashMap<String, Any>()
        map36502["key36502"] = b36502.toString() // put in a collection
        val c36502 = map36502["key36502"] as String? // get it back out
        val d36502 = c36502!!.substring(0, c36502.length - 1) // extract most of it
        val e36502 = String(
            Base64.decodeBase64(
                Base64.encodeBase64(d36502.toByteArray())
            )
        ) // B64 encode and decode it
        val f36502 = e36502.split(" ".toRegex()).toTypedArray()[0] // split it on a space
        val thing = ThingFactory.createThing()
        val g36502 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
        val bar = thing.doSomething(g36502) // reflection
        val sql = "SELECT * from USERS where USERNAME=? and PASSWORD='$bar'"
        try {
            val connection = DatabaseHelper.getSqlConnection()
            val statement = connection.prepareStatement(
                sql,
                ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY,
                ResultSet.CLOSE_CURSORS_AT_COMMIT
            )
            statement.setString(1, "foo")
            statement.execute()
            DatabaseHelper.printResults(statement, sql, response)
        } catch (e: SQLException) {
            if (DatabaseHelper.hideSQLErrors) {
                response.writer.println(
                    "Error processing request."
                )
                return
            } else throw ServletException(e)
        }
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}