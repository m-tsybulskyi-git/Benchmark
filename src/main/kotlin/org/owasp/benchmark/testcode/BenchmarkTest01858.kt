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
import org.owasp.benchmark.helpers.SeparateClassRequest
import org.owasp.benchmark.helpers.LDAPManager
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import java.lang.StringBuilder
import org.owasp.benchmark.helpers.ThingInterface
import java.security.MessageDigest
import java.io.File
import java.io.FileWriter
import java.security.NoSuchAlgorithmException
import java.io.PrintWriter
import java.lang.ProcessBuilder
import java.lang.Runtime
import java.sql.PreparedStatement
import java.sql.SQLException
import org.springframework.dao.DataAccessException
import org.springframework.dao.EmptyResultDataAccessException
import java.io.FileInputStream
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.security.InvalidAlgorithmParameterException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import java.io.FileOutputStream
import java.sql.CallableStatement
import java.net.URISyntaxException
import org.springframework.jdbc.support.rowset.SqlRowSet
import org.owasp.benchmark.testcode.BenchmarkTest01822
import org.owasp.benchmark.testcode.BenchmarkTest01823
import org.owasp.benchmark.testcode.BenchmarkTest01824
import org.owasp.benchmark.testcode.BenchmarkTest01825
import org.owasp.benchmark.testcode.BenchmarkTest01826
import org.owasp.benchmark.testcode.BenchmarkTest01827
import org.owasp.benchmark.testcode.BenchmarkTest01828
import org.owasp.benchmark.testcode.BenchmarkTest01829
import org.owasp.benchmark.testcode.BenchmarkTest01830
import org.owasp.benchmark.testcode.BenchmarkTest01831
import org.owasp.benchmark.testcode.BenchmarkTest01832
import org.owasp.benchmark.testcode.BenchmarkTest01833
import org.owasp.benchmark.testcode.BenchmarkTest01834
import org.owasp.benchmark.testcode.BenchmarkTest01835
import org.owasp.benchmark.testcode.BenchmarkTest01836
import org.owasp.benchmark.testcode.BenchmarkTest01837
import org.owasp.benchmark.testcode.BenchmarkTest01838
import org.owasp.benchmark.testcode.BenchmarkTest01839
import org.owasp.benchmark.testcode.BenchmarkTest01840
import org.owasp.benchmark.testcode.BenchmarkTest01841
import org.owasp.benchmark.testcode.BenchmarkTest01842
import org.owasp.benchmark.testcode.BenchmarkTest01843
import org.owasp.benchmark.testcode.BenchmarkTest01844
import org.owasp.benchmark.testcode.BenchmarkTest01845
import org.owasp.benchmark.testcode.BenchmarkTest01846
import org.owasp.benchmark.testcode.BenchmarkTest01847
import org.owasp.benchmark.testcode.BenchmarkTest01848
import org.owasp.benchmark.testcode.BenchmarkTest01849
import org.owasp.benchmark.testcode.BenchmarkTest01850
import org.owasp.benchmark.testcode.BenchmarkTest01851
import org.owasp.benchmark.testcode.BenchmarkTest01852
import org.owasp.benchmark.testcode.BenchmarkTest01853
import org.owasp.benchmark.testcode.BenchmarkTest01854
import org.owasp.benchmark.testcode.BenchmarkTest01855
import org.owasp.benchmark.testcode.BenchmarkTest01856
import org.owasp.benchmark.testcode.BenchmarkTest01857
import org.owasp.benchmark.testcode.BenchmarkTest01858
import org.owasp.benchmark.testcode.BenchmarkTest01859
import org.owasp.benchmark.testcode.BenchmarkTest01860
import org.owasp.benchmark.testcode.BenchmarkTest01861
import org.owasp.benchmark.testcode.BenchmarkTest01862
import org.owasp.benchmark.testcode.BenchmarkTest01863
import org.owasp.benchmark.testcode.BenchmarkTest01864
import org.owasp.benchmark.testcode.BenchmarkTest01865
import org.owasp.benchmark.testcode.BenchmarkTest01866
import org.owasp.benchmark.testcode.BenchmarkTest01867
import org.owasp.benchmark.testcode.BenchmarkTest01868
import org.owasp.benchmark.testcode.BenchmarkTest01869
import org.owasp.benchmark.testcode.BenchmarkTest01870
import org.owasp.benchmark.testcode.BenchmarkTest01871
import org.owasp.benchmark.testcode.BenchmarkTest01872
import org.owasp.benchmark.testcode.BenchmarkTest01873
import org.owasp.benchmark.testcode.BenchmarkTest01874
import org.owasp.benchmark.testcode.BenchmarkTest01875
import org.owasp.benchmark.testcode.BenchmarkTest01876
import org.owasp.benchmark.testcode.BenchmarkTest01877
import org.owasp.benchmark.testcode.BenchmarkTest01878
import org.owasp.benchmark.testcode.BenchmarkTest01879
import org.owasp.benchmark.testcode.BenchmarkTest01880
import org.owasp.benchmark.testcode.BenchmarkTest01881
import org.owasp.benchmark.testcode.BenchmarkTest01882
import org.owasp.benchmark.testcode.BenchmarkTest01883
import org.owasp.benchmark.testcode.BenchmarkTest01884
import org.owasp.benchmark.testcode.BenchmarkTest01885
import org.owasp.benchmark.testcode.BenchmarkTest01886
import org.owasp.benchmark.testcode.BenchmarkTest01887
import org.owasp.benchmark.testcode.BenchmarkTest01888
import org.owasp.benchmark.testcode.BenchmarkTest01889
import org.owasp.benchmark.testcode.BenchmarkTest01890
import org.owasp.benchmark.testcode.BenchmarkTest01891
import org.owasp.benchmark.testcode.BenchmarkTest01892
import org.owasp.benchmark.testcode.BenchmarkTest01893
import org.owasp.benchmark.testcode.BenchmarkTest01894
import org.owasp.benchmark.testcode.BenchmarkTest01895
import org.owasp.benchmark.testcode.BenchmarkTest01896
import org.owasp.benchmark.testcode.BenchmarkTest01897
import org.owasp.benchmark.testcode.BenchmarkTest01898
import org.owasp.benchmark.testcode.BenchmarkTest01899
import org.owasp.benchmark.testcode.BenchmarkTest01900
import org.owasp.benchmark.testcode.BenchmarkTest01901
import org.owasp.benchmark.testcode.BenchmarkTest01902
import org.owasp.benchmark.testcode.BenchmarkTest01903
import org.owasp.benchmark.testcode.BenchmarkTest01904
import org.owasp.benchmark.testcode.BenchmarkTest01905
import org.owasp.benchmark.testcode.BenchmarkTest01906
import org.owasp.benchmark.testcode.BenchmarkTest01907
import org.owasp.benchmark.testcode.BenchmarkTest01908
import org.owasp.benchmark.testcode.BenchmarkTest01909
import org.owasp.benchmark.testcode.BenchmarkTest01910
import org.owasp.benchmark.testcode.BenchmarkTest01911
import org.owasp.benchmark.testcode.BenchmarkTest01912
import org.owasp.benchmark.testcode.BenchmarkTest01913
import org.owasp.benchmark.testcode.BenchmarkTest01914
import org.owasp.benchmark.testcode.BenchmarkTest01915
import org.owasp.benchmark.testcode.BenchmarkTest01916
import org.owasp.benchmark.testcode.BenchmarkTest01917
import org.owasp.benchmark.testcode.BenchmarkTest01918
import org.owasp.benchmark.testcode.BenchmarkTest01919
import org.owasp.benchmark.testcode.BenchmarkTest01920
import org.owasp.benchmark.testcode.BenchmarkTest01921
import org.owasp.benchmark.testcode.BenchmarkTest01922
import org.owasp.benchmark.testcode.BenchmarkTest01923
import org.owasp.benchmark.testcode.BenchmarkTest01924
import org.owasp.benchmark.testcode.BenchmarkTest01925
import org.owasp.benchmark.testcode.BenchmarkTest01926
import org.owasp.benchmark.testcode.BenchmarkTest01927
import org.owasp.benchmark.testcode.BenchmarkTest01928
import org.owasp.benchmark.testcode.BenchmarkTest01929
import org.owasp.benchmark.testcode.BenchmarkTest01930
import org.owasp.benchmark.testcode.BenchmarkTest01931
import org.owasp.benchmark.testcode.BenchmarkTest01932
import org.owasp.benchmark.testcode.BenchmarkTest01933
import org.owasp.benchmark.testcode.BenchmarkTest01934
import org.owasp.benchmark.testcode.BenchmarkTest01935
import org.owasp.benchmark.testcode.BenchmarkTest01936
import org.owasp.benchmark.testcode.BenchmarkTest01937
import org.owasp.benchmark.testcode.BenchmarkTest01938
import org.owasp.benchmark.testcode.BenchmarkTest01939
import org.owasp.benchmark.testcode.BenchmarkTest01940
import org.owasp.benchmark.testcode.BenchmarkTest01941
import org.owasp.benchmark.testcode.BenchmarkTest01942
import org.owasp.benchmark.testcode.BenchmarkTest01943
import org.owasp.benchmark.testcode.BenchmarkTest01944
import org.owasp.benchmark.testcode.BenchmarkTest01945
import org.owasp.benchmark.testcode.BenchmarkTest01946
import org.owasp.benchmark.testcode.BenchmarkTest01947
import org.owasp.benchmark.testcode.BenchmarkTest01948
import org.owasp.benchmark.testcode.BenchmarkTest01949
import org.owasp.benchmark.testcode.BenchmarkTest01950
import org.owasp.benchmark.testcode.BenchmarkTest01951
import org.owasp.benchmark.testcode.BenchmarkTest01952
import org.owasp.benchmark.testcode.BenchmarkTest01953
import org.owasp.benchmark.testcode.BenchmarkTest01954
import org.owasp.benchmark.testcode.BenchmarkTest01955
import org.owasp.benchmark.testcode.BenchmarkTest01956
import org.owasp.benchmark.testcode.BenchmarkTest01957
import org.owasp.benchmark.testcode.BenchmarkTest01958
import org.owasp.benchmark.testcode.BenchmarkTest01959
import org.owasp.benchmark.testcode.BenchmarkTest01960
import org.owasp.benchmark.testcode.BenchmarkTest01961
import org.owasp.benchmark.testcode.BenchmarkTest01962
import org.owasp.benchmark.testcode.BenchmarkTest01963
import org.owasp.benchmark.testcode.BenchmarkTest01964
import org.owasp.benchmark.testcode.BenchmarkTest01965
import org.owasp.benchmark.testcode.BenchmarkTest01966
import org.owasp.benchmark.testcode.BenchmarkTest01967
import org.owasp.benchmark.testcode.BenchmarkTest01968
import org.owasp.benchmark.testcode.BenchmarkTest01969
import org.owasp.benchmark.testcode.BenchmarkTest01970
import org.owasp.benchmark.testcode.BenchmarkTest01971
import org.owasp.benchmark.testcode.BenchmarkTest01972
import org.owasp.benchmark.testcode.BenchmarkTest01973
import org.owasp.benchmark.testcode.BenchmarkTest01974
import org.owasp.benchmark.testcode.BenchmarkTest01975
import org.owasp.benchmark.testcode.BenchmarkTest01976
import org.owasp.benchmark.testcode.BenchmarkTest01977
import org.owasp.benchmark.testcode.BenchmarkTest01978
import org.owasp.benchmark.testcode.BenchmarkTest01979
import org.owasp.benchmark.testcode.BenchmarkTest01980
import org.owasp.benchmark.testcode.BenchmarkTest01981
import org.owasp.benchmark.testcode.BenchmarkTest01982
import org.owasp.benchmark.testcode.BenchmarkTest01983
import org.owasp.benchmark.testcode.BenchmarkTest01984
import org.owasp.benchmark.testcode.BenchmarkTest01985
import org.owasp.benchmark.testcode.BenchmarkTest01986
import org.owasp.benchmark.testcode.BenchmarkTest01987
import org.owasp.benchmark.testcode.BenchmarkTest01988
import org.owasp.benchmark.testcode.BenchmarkTest01989
import org.owasp.benchmark.testcode.BenchmarkTest01990
import org.owasp.benchmark.testcode.BenchmarkTest01991
import org.owasp.benchmark.testcode.BenchmarkTest01992
import org.owasp.benchmark.testcode.BenchmarkTest01993
import org.owasp.benchmark.testcode.BenchmarkTest01994
import org.owasp.benchmark.testcode.BenchmarkTest01995
import org.owasp.benchmark.testcode.BenchmarkTest01996
import org.owasp.benchmark.testcode.BenchmarkTest01997
import org.owasp.benchmark.testcode.BenchmarkTest01998
import org.owasp.benchmark.testcode.BenchmarkTest01999
import org.owasp.benchmark.testcode.BenchmarkTest02000
import java.net.URL
import java.net.URLDecoder
import java.util.*
import javax.servlet.http.Cookie

@WebServlet(value = ["/weakrand-04/BenchmarkTest01858"])
class BenchmarkTest01858 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val userCookie = Cookie("BenchmarkTest01858", "whatever")
        userCookie.maxAge = 60 * 3 //Store cookie for 3 minutes
        userCookie.secure = true
        userCookie.path = request.requestURI
        userCookie.domain = URL(request.requestURL.toString()).host
        response.addCookie(userCookie)
        val rd = request.getRequestDispatcher("/weakrand-04/BenchmarkTest01858.html")
        rd.include(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val theCookies = request.cookies
        var param = "noCookieValueSupplied"
        if (theCookies != null) {
            for (theCookie in theCookies) {
                if (theCookie.name == "BenchmarkTest01858") {
                    param = URLDecoder.decode(theCookie.value, "UTF-8")
                    break
                }
            }
        }
        val bar = doSomething(request, param)
        val l = Random().nextLong()
        val rememberMeKey = java.lang.Long.toString(l)
        var user = "Logan"
        val fullClassName = this.javaClass.name
        val testCaseNumber = fullClassName.substring(fullClassName.lastIndexOf('.') + 1 + "BenchmarkTest".length)
        user += testCaseNumber
        val cookieName = "rememberMe$testCaseNumber"
        var foundUser = false
        val cookies = request.cookies
        if (cookies != null) {
            var i = 0
            while (!foundUser && i < cookies.size) {
                val cookie = cookies[i]
                if (cookieName == cookie.name) {
                    if (cookie.value == request.session.getAttribute(cookieName)) {
                        foundUser = true
                    }
                }
                i++
            }
        }
        if (foundUser) {
            response.writer.println(
                "Welcome back: $user<br/>"
            )
        } else {
            val rememberMe = Cookie(cookieName, rememberMeKey)
            rememberMe.secure = true
            rememberMe.isHttpOnly = true
            rememberMe.path = request.requestURI // i.e., set path to JUST this servlet 
            // e.g., /benchmark/sql-01/BenchmarkTest01001
            request.session.setAttribute(cookieName, rememberMeKey)
            response.addCookie(rememberMe)
            response.writer.println(
                user + " has been remembered with cookie: " + rememberMe.name
                        + " whose value is: " + rememberMe.value + "<br/>"
            )
        }
        response.writer.println(
            "Weak Randomness Test java.util.Random.nextLong() executed"
        )
    } // end doPost

    companion object {
        private const val serialVersionUID = 1L
        @Throws(ServletException::class, IOException::class)
        private fun doSomething(request: HttpServletRequest, param: String): String? {
            var bar: String? = "safe!"
            val map95052 = HashMap<String, Any>()
            map95052["keyA-95052"] = "a_Value" // put some stuff in the collection
            map95052["keyB-95052"] = param // put it in a collection
            map95052["keyC"] = "another_Value" // put some stuff in the collection
            bar = map95052["keyB-95052"] as String? // get it back out
            bar = map95052["keyA-95052"] as String? // get safe value back out
            return bar
        }
    }
}