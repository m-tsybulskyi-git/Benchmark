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
import java.sql.PreparedStatement
import java.sql.SQLException
import org.owasp.benchmark.helpers.ThingInterface
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.dao.DataAccessException
import java.lang.StringBuilder
import java.io.FileInputStream
import javax.crypto.Cipher
import javax.crypto.SecretKey
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import java.io.File
import java.io.FileWriter
import java.security.NoSuchAlgorithmException
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.security.InvalidAlgorithmParameterException
import javax.crypto.spec.GCMParameterSpec
import java.io.FileOutputStream
import org.owasp.benchmark.helpers.LDAPManager
import org.owasp.benchmark.helpers.Utils
import org.owasp.esapi.ESAPI
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import java.security.MessageDigest
import java.lang.ProcessBuilder
import java.lang.Runtime
import java.sql.CallableStatement
import java.util.Enumeration
import java.net.URISyntaxException
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.net.URLDecoder
import java.util.ArrayList

@WebServlet(value = ["/cmdi-00/BenchmarkTest00304"])
class BenchmarkTest00304 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param: String? = ""
        val headers = request.getHeaders("BenchmarkTest00304")
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement() // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = URLDecoder.decode(param, "UTF-8")
        var bar = ""
        if (param != null) {
            val valuesList: MutableList<String> = ArrayList()
            valuesList.add("safe")
            valuesList.add(param)
            valuesList.add("moresafe")
            valuesList.removeAt(0) // remove the 1st safe value
            bar = valuesList[0] // get the param value
        }
        var cmd = ""
        var a1 = ""
        var a2 = ""
        var args: Array<String>? = null
        val osName = System.getProperty("os.name")
        if (osName.indexOf("Windows") != -1) {
            a1 = "cmd.exe"
            a2 = "/c"
            cmd = "echo "
            args = arrayOf(a1, a2, cmd, bar)
        } else {
            a1 = "sh"
            a2 = "-c"
            cmd = Utils.getOSCommandString("ls ")
            args = arrayOf(a1, a2, cmd + bar)
        }
        val argsEnv = arrayOf("foo=bar")
        val r = Runtime.getRuntime()
        try {
            val p = r.exec(args, argsEnv, File(System.getProperty("user.dir")))
            Utils.printOSCommandResults(p, response)
        } catch (e: IOException) {
            println("Problem executing cmdi - TestCase")
            response.writer.println(
                ESAPI.encoder().encodeForHTML(e.message)
            )
            return
        }
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}