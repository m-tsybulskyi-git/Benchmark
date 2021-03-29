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
import org.owasp.benchmark.helpers.DatabaseHelper
import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServlet
import kotlin.Throws
import javax.servlet.ServletException
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.owasp.benchmark.helpers.SeparateClassRequest
import org.owasp.benchmark.helpers.ThingFactory
import org.owasp.benchmark.testcode.BenchmarkTest02701
import java.lang.StringBuilder
import org.owasp.benchmark.testcode.BenchmarkTest02702
import org.owasp.benchmark.testcode.BenchmarkTest02703
import org.owasp.benchmark.testcode.BenchmarkTest02704
import org.owasp.benchmark.testcode.BenchmarkTest02705
import org.owasp.benchmark.testcode.BenchmarkTest02706
import org.owasp.benchmark.testcode.BenchmarkTest02707
import org.owasp.benchmark.testcode.BenchmarkTest02708
import org.owasp.benchmark.testcode.BenchmarkTest02709
import org.owasp.benchmark.testcode.BenchmarkTest02710
import org.owasp.benchmark.testcode.BenchmarkTest02711
import org.owasp.benchmark.testcode.BenchmarkTest02712
import org.owasp.benchmark.testcode.BenchmarkTest02713
import java.lang.Runtime
import java.io.File
import org.owasp.benchmark.testcode.BenchmarkTest02714
import org.owasp.benchmark.testcode.BenchmarkTest02715
import java.security.NoSuchAlgorithmException
import org.owasp.benchmark.testcode.BenchmarkTest02716
import org.owasp.benchmark.helpers.ThingInterface
import org.owasp.benchmark.testcode.BenchmarkTest02717
import org.owasp.benchmark.testcode.BenchmarkTest02718
import org.owasp.benchmark.testcode.BenchmarkTest02719
import org.owasp.benchmark.testcode.BenchmarkTest02720
import org.owasp.benchmark.testcode.BenchmarkTest02721
import org.owasp.benchmark.testcode.BenchmarkTest02722
import org.owasp.benchmark.testcode.BenchmarkTest02723
import org.owasp.benchmark.testcode.BenchmarkTest02724
import org.owasp.benchmark.testcode.BenchmarkTest02725
import org.owasp.benchmark.testcode.BenchmarkTest02726
import org.owasp.benchmark.testcode.BenchmarkTest02727
import java.sql.PreparedStatement
import java.sql.SQLException
import org.owasp.benchmark.testcode.BenchmarkTest02728
import org.owasp.benchmark.testcode.BenchmarkTest02729
import org.owasp.benchmark.testcode.BenchmarkTest02730
import org.owasp.benchmark.testcode.BenchmarkTest02731
import org.springframework.dao.DataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02732
import org.springframework.dao.EmptyResultDataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02733
import org.owasp.benchmark.testcode.BenchmarkTest02734
import org.owasp.benchmark.testcode.BenchmarkTest02735
import org.owasp.benchmark.testcode.BenchmarkTest02736
import org.owasp.benchmark.testcode.BenchmarkTest02737
import org.springframework.jdbc.support.rowset.SqlRowSet
import org.owasp.benchmark.testcode.BenchmarkTest02738
import org.owasp.benchmark.testcode.BenchmarkTest02739
import org.owasp.benchmark.testcode.BenchmarkTest02740
import java.util.HashMap

@WebServlet(value = ["/sqli-06/BenchmarkTest02730"])
class BenchmarkTest02730 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val scr = SeparateClassRequest(request)
        val param = scr.getTheValue("BenchmarkTest02730")
        val bar = doSomething(request, param)
        val sql = "SELECT * from USERS where USERNAME=? and PASSWORD='$bar'"
        try {
            val connection = DatabaseHelper.getSqlConnection()
            val statement = connection.prepareStatement(sql, arrayOf("Column1", "Column2"))
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
    } // end doPost

    companion object {
        private const val serialVersionUID = 1L

        @Throws(ServletException::class, IOException::class)
        private fun doSomething(request: HttpServletRequest, param: String): String {

            // Chain a bunch of propagators in sequence
            val b81593 = StringBuilder(
                param //assign
            ) // stick in stringbuilder
            b81593.append(" SafeStuff") // append some safe content
            b81593.replace(b81593.length - "Chars".length, b81593.length, "Chars") //replace some of the end content
            val map81593 =
                HashMap<String, Any>()
            map81593["key81593"] = b81593.toString() // put in a collection
            val c81593 = map81593["key81593"] as String? // get it back out
            val d81593 = c81593!!.substring(0, c81593.length - 1) // extract most of it
            val e81593 = String(
                Base64.decodeBase64(
                    Base64.encodeBase64(d81593.toByteArray())
                )
            ) // B64 encode and decode it
            val f81593 = e81593.split(" ".toRegex()).toTypedArray()[0] // split it on a space
            val thing = ThingFactory.createThing()
            val g81593 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
            return thing.doSomething(g81593) // reflection
        }
    }
}