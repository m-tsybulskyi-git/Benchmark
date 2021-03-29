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
import org.owasp.esapi.ESAPI

@WebServlet(value = ["/sqli-06/BenchmarkTest02736"])
class BenchmarkTest02736 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val scr = SeparateClassRequest(request)
        val param = scr.getTheValue("BenchmarkTest02736")
        val bar = doSomething(request, param)
        val sql = "SELECT TOP 1 userid from USERS where USERNAME='foo' and PASSWORD='$bar'"
        try {
            val results = DatabaseHelper.JDBCtemplate.queryForMap(sql)
            response.writer.println(
                "Your results are: "
            )

            //		System.out.println("Your results are");
            response.writer.println(
                ESAPI.encoder().encodeForHTML(results.toString())
            )
            //		System.out.println(results.toString());
        } catch (e: EmptyResultDataAccessException) {
            response.writer.println(
                "No results returned for query: " + ESAPI.encoder().encodeForHTML(sql)
            )
        } catch (e: DataAccessException) {
            if (DatabaseHelper.hideSQLErrors) {
                response.writer.println(
                    "Error processing request."
                )
            } else throw ServletException(e)
        }
    } // end doPost

    companion object {
        private const val serialVersionUID = 1L

        @Throws(ServletException::class, IOException::class)
        private fun doSomething(request: HttpServletRequest, param: String): String {
            val thing = ThingFactory.createThing()
            return thing.doSomething(param)
        }
    }
}