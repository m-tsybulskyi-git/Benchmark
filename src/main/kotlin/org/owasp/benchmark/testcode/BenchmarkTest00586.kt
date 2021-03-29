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

import org.owasp.benchmark.helpers.Utils
import java.io.IOException
import java.util.*
import javax.servlet.ServletException
import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServlet
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@WebServlet(value = ["/trustbound-00/BenchmarkTest00586"])
class BenchmarkTest00586 : HttpServlet() {
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
                    if (value == "BenchmarkTest00586") {
                        param = name
                        flag = false
                    }
                    i++
                }
            }
        }
        var bar: String? = "safe!"
        val map58886 = HashMap<String, Any>()
        map58886["keyA-58886"] = "a_Value" // put some stuff in the collection
        map58886["keyB-58886"] = param // put it in a collection
        map58886["keyC"] = "another_Value" // put some stuff in the collection
        bar = map58886["keyB-58886"] as String? // get it back out
        bar = map58886["keyA-58886"] as String? // get safe value back out


        // javax.servlet.http.HttpSession.putValue(java.lang.String^,java.lang.Object)
        request.session.putValue(bar, "10340")
        response.writer.println(
            "Item: '" + Utils.encodeForHTML(bar)
                    + "' with value: 10340 saved in session."
        )
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}