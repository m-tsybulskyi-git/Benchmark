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
import org.owasp.benchmark.testcode.BenchmarkTest02601
import org.owasp.benchmark.testcode.BenchmarkTest02602
import java.lang.StringBuilder
import org.owasp.benchmark.helpers.ThingInterface
import org.owasp.benchmark.testcode.BenchmarkTest02603
import org.owasp.benchmark.testcode.BenchmarkTest02604
import org.owasp.benchmark.testcode.BenchmarkTest02605
import org.owasp.benchmark.testcode.BenchmarkTest02606
import org.owasp.benchmark.testcode.BenchmarkTest02607
import org.owasp.benchmark.testcode.BenchmarkTest02608
import org.owasp.benchmark.testcode.BenchmarkTest02609
import org.owasp.benchmark.testcode.BenchmarkTest02610
import java.lang.Runtime
import org.owasp.benchmark.testcode.BenchmarkTest02611
import java.io.File
import org.owasp.benchmark.testcode.BenchmarkTest02612
import org.owasp.benchmark.testcode.BenchmarkTest02613
import org.owasp.benchmark.testcode.BenchmarkTest02614
import java.security.NoSuchAlgorithmException
import org.owasp.benchmark.testcode.BenchmarkTest02615
import org.owasp.benchmark.testcode.BenchmarkTest02616
import org.owasp.benchmark.testcode.BenchmarkTest02617
import org.owasp.benchmark.testcode.BenchmarkTest02618
import org.owasp.benchmark.testcode.BenchmarkTest02619
import org.owasp.benchmark.testcode.BenchmarkTest02620
import org.owasp.benchmark.testcode.BenchmarkTest02621
import org.owasp.benchmark.testcode.BenchmarkTest02622
import org.owasp.benchmark.testcode.BenchmarkTest02623
import org.owasp.benchmark.testcode.BenchmarkTest02624
import org.owasp.benchmark.testcode.BenchmarkTest02625
import java.sql.CallableStatement
import java.sql.SQLException
import org.owasp.benchmark.testcode.BenchmarkTest02626
import org.owasp.benchmark.testcode.BenchmarkTest02627
import org.owasp.benchmark.testcode.BenchmarkTest02628
import org.owasp.benchmark.testcode.BenchmarkTest02629
import org.owasp.benchmark.testcode.BenchmarkTest02630
import org.owasp.benchmark.testcode.BenchmarkTest02631
import java.sql.PreparedStatement
import org.owasp.benchmark.testcode.BenchmarkTest02632
import org.owasp.benchmark.testcode.BenchmarkTest02633
import org.owasp.benchmark.testcode.BenchmarkTest02634
import org.owasp.benchmark.testcode.BenchmarkTest02635
import org.owasp.benchmark.testcode.BenchmarkTest02636
import org.owasp.benchmark.testcode.BenchmarkTest02637
import org.owasp.benchmark.testcode.BenchmarkTest02638
import org.springframework.dao.DataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02639
import org.owasp.benchmark.testcode.BenchmarkTest02640
import org.owasp.benchmark.testcode.BenchmarkTest02641
import org.springframework.dao.EmptyResultDataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02642
import org.owasp.benchmark.testcode.BenchmarkTest02643
import org.owasp.benchmark.testcode.BenchmarkTest02644
import org.springframework.jdbc.support.rowset.SqlRowSet
import org.owasp.benchmark.testcode.BenchmarkTest02645
import org.owasp.benchmark.testcode.BenchmarkTest02646
import org.owasp.benchmark.testcode.BenchmarkTest02647
import org.owasp.benchmark.testcode.BenchmarkTest02648
import org.owasp.benchmark.testcode.BenchmarkTest02649
import org.owasp.benchmark.testcode.BenchmarkTest02650
import org.owasp.benchmark.testcode.BenchmarkTest02651
import org.owasp.benchmark.testcode.BenchmarkTest02652
import org.owasp.benchmark.testcode.BenchmarkTest02653
import org.owasp.benchmark.testcode.BenchmarkTest02654
import org.owasp.benchmark.testcode.BenchmarkTest02655
import org.owasp.benchmark.testcode.BenchmarkTest02656
import org.owasp.benchmark.testcode.BenchmarkTest02657
import org.owasp.benchmark.helpers.SeparateClassRequest
import org.owasp.benchmark.helpers.ThingFactory
import org.owasp.benchmark.testcode.BenchmarkTest02658
import javax.crypto.Cipher
import javax.crypto.SecretKey
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import java.io.FileWriter
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.security.InvalidAlgorithmParameterException
import org.owasp.benchmark.testcode.BenchmarkTest02659
import javax.crypto.spec.GCMParameterSpec
import org.owasp.benchmark.testcode.BenchmarkTest02660
import org.owasp.benchmark.testcode.BenchmarkTest02661
import org.owasp.benchmark.testcode.BenchmarkTest02662
import org.owasp.benchmark.testcode.BenchmarkTest02663
import org.owasp.benchmark.testcode.BenchmarkTest02664
import org.owasp.benchmark.testcode.BenchmarkTest02665
import java.io.FileInputStream
import org.owasp.benchmark.testcode.BenchmarkTest02666
import org.owasp.benchmark.testcode.BenchmarkTest02667
import org.owasp.benchmark.testcode.BenchmarkTest02668
import java.io.FileOutputStream
import org.owasp.benchmark.testcode.BenchmarkTest02669
import org.owasp.benchmark.testcode.BenchmarkTest02670
import java.security.MessageDigest
import org.owasp.benchmark.testcode.BenchmarkTest02671
import org.owasp.benchmark.testcode.BenchmarkTest02672
import org.owasp.benchmark.testcode.BenchmarkTest02673
import org.owasp.benchmark.testcode.BenchmarkTest02674
import org.owasp.benchmark.testcode.BenchmarkTest02675
import org.owasp.benchmark.testcode.BenchmarkTest02676
import org.owasp.benchmark.testcode.BenchmarkTest02677
import org.owasp.benchmark.testcode.BenchmarkTest02678
import org.owasp.benchmark.testcode.BenchmarkTest02679
import java.io.PrintWriter
import org.owasp.benchmark.testcode.BenchmarkTest02680
import org.owasp.benchmark.testcode.BenchmarkTest02681
import org.owasp.benchmark.testcode.BenchmarkTest02682
import org.owasp.benchmark.testcode.BenchmarkTest02683
import org.owasp.benchmark.testcode.BenchmarkTest02684
import org.owasp.benchmark.testcode.BenchmarkTest02685
import org.owasp.benchmark.testcode.BenchmarkTest02686
import org.owasp.benchmark.testcode.BenchmarkTest02687
import org.owasp.benchmark.testcode.BenchmarkTest02688
import org.owasp.benchmark.testcode.BenchmarkTest02689
import org.owasp.benchmark.testcode.BenchmarkTest02690
import org.owasp.benchmark.testcode.BenchmarkTest02691
import org.owasp.benchmark.testcode.BenchmarkTest02692
import org.owasp.benchmark.testcode.BenchmarkTest02693
import org.owasp.benchmark.testcode.BenchmarkTest02694
import org.owasp.benchmark.testcode.BenchmarkTest02695
import org.owasp.benchmark.testcode.BenchmarkTest02696
import org.owasp.benchmark.testcode.BenchmarkTest02697
import java.lang.ProcessBuilder
import org.owasp.benchmark.testcode.BenchmarkTest02698
import org.owasp.benchmark.testcode.BenchmarkTest02699
import org.owasp.benchmark.testcode.BenchmarkTest02700
import java.util.HashMap

@WebServlet(value = ["/xss-05/BenchmarkTest02683"])
class BenchmarkTest02683 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val scr = SeparateClassRequest(request)
        val param = scr.getTheValue("BenchmarkTest02683")
        val bar = doSomething(request, param)
        response.setHeader("X-XSS-Protection", "0")
        response.writer.print(bar)
    } // end doPost

    companion object {
        private const val serialVersionUID = 1L

        @Throws(ServletException::class, IOException::class)
        private fun doSomething(request: HttpServletRequest, param: String): String {

            // Chain a bunch of propagators in sequence
            val b47309 = StringBuilder(
                param //assign
            ) // stick in stringbuilder
            b47309.append(" SafeStuff") // append some safe content
            b47309.replace(b47309.length - "Chars".length, b47309.length, "Chars") //replace some of the end content
            val map47309 =
                HashMap<String, Any>()
            map47309["key47309"] = b47309.toString() // put in a collection
            val c47309 = map47309["key47309"] as String? // get it back out
            val d47309 = c47309!!.substring(0, c47309.length - 1) // extract most of it
            val e47309 = String(
                Base64.decodeBase64(
                    Base64.encodeBase64(d47309.toByteArray())
                )
            ) // B64 encode and decode it
            val f47309 = e47309.split(" ".toRegex()).toTypedArray()[0] // split it on a space
            val thing = ThingFactory.createThing()
            val g47309 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
            return thing.doSomething(g47309) // reflection
        }
    }
}