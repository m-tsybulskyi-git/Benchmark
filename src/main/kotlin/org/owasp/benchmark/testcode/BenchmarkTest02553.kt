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
import org.owasp.benchmark.testcode.BenchmarkTest02551
import javax.crypto.Cipher
import javax.crypto.SecretKey
import java.io.File
import java.io.FileWriter
import java.security.NoSuchAlgorithmException
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.lang.StringBuilder
import org.owasp.benchmark.testcode.BenchmarkTest02552
import org.owasp.benchmark.testcode.BenchmarkTest02553
import org.owasp.benchmark.helpers.LDAPManager
import javax.naming.directory.DirContext
import javax.naming.directory.SearchControls
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import org.owasp.benchmark.testcode.BenchmarkTest02554
import org.owasp.benchmark.testcode.BenchmarkTest02555
import org.owasp.benchmark.testcode.BenchmarkTest02556
import org.owasp.benchmark.testcode.BenchmarkTest02557
import org.owasp.benchmark.testcode.BenchmarkTest02558
import org.owasp.benchmark.testcode.BenchmarkTest02559
import java.net.URISyntaxException
import org.owasp.benchmark.helpers.ThingInterface
import org.owasp.benchmark.testcode.BenchmarkTest02560
import java.io.FileInputStream
import org.owasp.benchmark.testcode.BenchmarkTest02561
import org.owasp.benchmark.testcode.BenchmarkTest02562
import org.owasp.benchmark.testcode.BenchmarkTest02563
import java.io.FileOutputStream
import org.owasp.benchmark.testcode.BenchmarkTest02564
import org.owasp.benchmark.testcode.BenchmarkTest02565
import org.owasp.benchmark.testcode.BenchmarkTest02566
import org.owasp.benchmark.testcode.BenchmarkTest02567
import org.owasp.benchmark.testcode.BenchmarkTest02568
import org.owasp.benchmark.testcode.BenchmarkTest02569
import org.owasp.benchmark.testcode.BenchmarkTest02570
import org.owasp.benchmark.testcode.BenchmarkTest02571
import javax.naming.directory.InitialDirContext
import org.owasp.benchmark.testcode.BenchmarkTest02572
import org.owasp.benchmark.testcode.BenchmarkTest02573
import java.security.MessageDigest
import org.owasp.benchmark.testcode.BenchmarkTest02574
import org.owasp.benchmark.testcode.BenchmarkTest02575
import org.owasp.benchmark.testcode.BenchmarkTest02576
import org.owasp.benchmark.testcode.BenchmarkTest02577
import org.owasp.benchmark.testcode.BenchmarkTest02578
import org.owasp.benchmark.testcode.BenchmarkTest02579
import org.owasp.benchmark.testcode.BenchmarkTest02580
import org.owasp.benchmark.testcode.BenchmarkTest02581
import org.owasp.benchmark.testcode.BenchmarkTest02582
import org.owasp.benchmark.testcode.BenchmarkTest02583
import org.owasp.benchmark.testcode.BenchmarkTest02584
import org.owasp.benchmark.testcode.BenchmarkTest02585
import org.owasp.benchmark.testcode.BenchmarkTest02586
import org.owasp.benchmark.testcode.BenchmarkTest02587
import org.owasp.benchmark.testcode.BenchmarkTest02588
import org.owasp.benchmark.testcode.BenchmarkTest02589
import org.owasp.benchmark.testcode.BenchmarkTest02590
import org.owasp.benchmark.testcode.BenchmarkTest02591
import org.owasp.benchmark.testcode.BenchmarkTest02592
import org.owasp.benchmark.testcode.BenchmarkTest02593
import org.owasp.benchmark.testcode.BenchmarkTest02594
import org.owasp.benchmark.testcode.BenchmarkTest02595
import org.owasp.benchmark.testcode.BenchmarkTest02596
import org.owasp.benchmark.testcode.BenchmarkTest02597
import org.owasp.benchmark.testcode.BenchmarkTest02598
import org.owasp.benchmark.testcode.BenchmarkTest02599
import org.owasp.benchmark.testcode.BenchmarkTest02600
import org.owasp.esapi.ESAPI
import java.lang.Exception
import java.net.URLDecoder
import java.util.HashMap

@WebServlet(value = ["/ldapi-00/BenchmarkTest02553"])
class BenchmarkTest02553 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val queryString = request.queryString
        val paramval = "BenchmarkTest02553" + "="
        var paramLoc = -1
        if (queryString != null) paramLoc = queryString.indexOf(paramval)
        if (paramLoc == -1) {
            response.writer.println("getQueryString() couldn't find expected parameter '" + "BenchmarkTest02553" + "' in query string.")
            return
        }
        var param =
            queryString!!.substring(paramLoc + paramval.length) // 1st assume "BenchmarkTest02553" param is last parameter in query string.
        // And then check to see if its in the middle of the query string and if so, trim off what comes after.
        val ampersandLoc = queryString.indexOf("&", paramLoc)
        if (ampersandLoc != -1) {
            param = queryString.substring(paramLoc + paramval.length, ampersandLoc)
        }
        param = URLDecoder.decode(param, "UTF-8")
        val bar = doSomething(request, param)
        val ads = LDAPManager()
        try {
            response.contentType = "text/html;charset=UTF-8"
            val ctx = ads.dirContext
            val base = "ou=users,ou=system"
            val sc = SearchControls()
            sc.searchScope = SearchControls.SUBTREE_SCOPE
            val filter = "(&(objectclass=person))(|(uid=$bar)(street={0}))"
            val filters = arrayOf<Any>("The streetz 4 Ms bar")
            // System.out.println("Filter " + filter);
            var found = false
            val results = ctx.search(base, filter, filters, sc)
            while (results.hasMore()) {
                val sr = results.next() as SearchResult
                val attrs = sr.attributes
                val attr = attrs["uid"]
                val attr2 = attrs["street"]
                if (attr != null) {
                    response.writer.println(
                        "LDAP query results:<br>"
                                + "Record found with name " + attr.get() + "<br>"
                                + "Address: " + attr2.get() + "<br>"
                    )
                    // System.out.println("record found " + attr.get());
                    found = true
                }
            }
            if (!found) {
                response.writer.println(
                    "LDAP query results: nothing found for query: " + ESAPI.encoder().encodeForHTML(filter)
                )
            }
        } catch (e: NamingException) {
            throw ServletException(e)
        } finally {
            try {
                ads.closeDirContext()
            } catch (e: Exception) {
                throw ServletException(e)
            }
        }
    } // end doPost

    companion object {
        private const val serialVersionUID = 1L
        @Throws(ServletException::class, IOException::class)
        private fun doSomething(request: HttpServletRequest, param: String): String? {
            var bar: String? = "safe!"
            val map11026 = HashMap<String, Any>()
            map11026["keyA-11026"] = "a_Value" // put some stuff in the collection
            map11026["keyB-11026"] = param // put it in a collection
            map11026["keyC"] = "another_Value" // put some stuff in the collection
            bar = map11026["keyB-11026"] as String? // get it back out
            bar = map11026["keyA-11026"] as String? // get safe value back out
            return bar
        }
    }
}