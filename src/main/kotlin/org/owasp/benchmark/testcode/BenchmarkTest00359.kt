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

import org.owasp.esapi.ESAPI
import java.io.File
import java.io.IOException
import javax.servlet.ServletException
import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServlet
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@WebServlet(value = ["/pathtraver-00/BenchmarkTest00359"])
class BenchmarkTest00359 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param = request.getParameter("BenchmarkTest00359")
        if (param == null) param = ""
        val bar: String

        // Simple if statement that assigns param to bar on true condition
        val num = 196
        bar = if (500 / 42 + num > 200) param else "This should never happen"
        val fileTarget = File(bar)
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
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}