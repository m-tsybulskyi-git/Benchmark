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
import java.sql.PreparedStatement
import java.sql.SQLException
import org.springframework.dao.DataAccessException
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.jdbc.support.rowset.SqlRowSet
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
import java.lang.StringBuilder
import org.owasp.benchmark.helpers.ThingInterface
import org.owasp.benchmark.helpers.LDAPManager
import javax.naming.directory.DirContext
import javax.naming.directory.SearchControls
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import java.net.URISyntaxException
import java.io.FileOutputStream
import java.security.MessageDigest
import java.io.PrintWriter
import java.lang.Runtime
import java.util.Enumeration
import javax.crypto.spec.GCMParameterSpec
import java.lang.ProcessBuilder
import java.sql.CallableStatement
import javax.naming.directory.InitialDirContext
import org.owasp.benchmark.helpers.SeparateClassRequest
import org.owasp.benchmark.helpers.Utils
import org.owasp.esapi.ESAPI
import org.w3c.dom.Element
import org.w3c.dom.NodeList
import org.xml.sax.SAXException
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.ParserConfigurationException
import javax.xml.xpath.XPathConstants
import javax.xml.xpath.XPathExpressionException
import javax.xml.xpath.XPathFactory

@WebServlet(value = ["/xpathi-00/BenchmarkTest01479"])
class BenchmarkTest01479 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param: String? = ""
        var flag = true
        val names = request.parameterNames
        while (names.hasMoreElements() && flag) {
            val name = names.nextElement() as String
            val values = request.getParameterValues(name)
            if (values != null) {
                var i = 0
                while (i < values.size && flag) {
                    val value = values[i]
                    if (value == "BenchmarkTest01479") {
                        param = name
                        flag = false
                    }
                    i++
                }
            }
        }
        val bar: String? = param?.let { Test().doSomething(request, it) }
        bar ?: return
        try {
            val file = FileInputStream(Utils.getFileFromClasspath("employees.xml", this.javaClass.classLoader))
            val builderFactory = DocumentBuilderFactory.newInstance()
            // Prevent XXE
            builderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            val builder = builderFactory.newDocumentBuilder()
            val xmlDocument = builder.parse(file)
            val xpf = XPathFactory.newInstance()
            val xp = xpf.newXPath()
            val expression = "/Employees/Employee[@emplid='$bar']"
            val nodeList = xp.compile(expression).evaluate(xmlDocument, XPathConstants.NODESET) as NodeList
            response.writer.println(
                "Your query results are: <br/>"
            )
            for (i in 0 until nodeList.length) {
                val value = nodeList.item(i) as Element
                response.writer.println(
                    value.textContent + "<br/>"
                )
            }
        } catch (e: XPathExpressionException) {
            response.writer.println(
                "Error parsing XPath input: '" + ESAPI.encoder().encodeForHTML(bar) + "'"
            )
            throw ServletException(e)
        } catch (e: ParserConfigurationException) {
            response.writer.println(
                "Error parsing XPath input: '" + ESAPI.encoder().encodeForHTML(bar) + "'"
            )
            throw ServletException(e)
        } catch (e: SAXException) {
            response.writer.println(
                "Error parsing XPath input: '" + ESAPI.encoder().encodeForHTML(bar) + "'"
            )
            throw ServletException(e)
        }
    } // end doPost

    private inner class Test {
        @Throws(ServletException::class, IOException::class)
        fun doSomething(request: HttpServletRequest?, param: String): String {
            val bar: String

            // Simple if statement that assigns constant to bar on true condition
            val num = 86
            bar = if (7 * 42 - num > 200) "This_should_always_happen" else param
            return bar
        }
    } // end innerclass Test

    companion object {
        private const val serialVersionUID = 1L
    }
} // end DataflowThruInnerClass
