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
import org.w3c.dom.Element
import org.w3c.dom.NodeList
import org.xml.sax.SAXException
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.ParserConfigurationException
import javax.xml.xpath.XPathConstants
import javax.xml.xpath.XPathExpressionException
import javax.xml.xpath.XPathFactory

@WebServlet(value = ["/xpathi-00/BenchmarkTest00941"])
class BenchmarkTest00941 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val scr = SeparateClassRequest(request)
        val param = scr.getTheValue("BenchmarkTest00941")
        var bar = ""
        if (param != null) {
            bar = String(
                Base64.decodeBase64(
                    Base64.encodeBase64(param.toByteArray())
                )
            )
        }
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
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}