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
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.owasp.benchmark.testcode.BenchmarkTest02001
import org.owasp.benchmark.testcode.BenchmarkTest02002
import org.owasp.benchmark.testcode.BenchmarkTest02003
import java.lang.StringBuilder
import org.owasp.benchmark.helpers.ThingInterface
import org.owasp.benchmark.testcode.BenchmarkTest02004
import org.owasp.benchmark.testcode.BenchmarkTest02005
import org.owasp.benchmark.testcode.BenchmarkTest02006
import org.owasp.benchmark.testcode.BenchmarkTest02007
import org.owasp.benchmark.testcode.BenchmarkTest02008
import org.owasp.benchmark.testcode.BenchmarkTest02009
import org.owasp.benchmark.testcode.BenchmarkTest02010
import org.owasp.benchmark.testcode.BenchmarkTest02011
import org.owasp.benchmark.testcode.BenchmarkTest02012
import org.owasp.benchmark.testcode.BenchmarkTest02013
import org.owasp.benchmark.testcode.BenchmarkTest02014
import org.owasp.benchmark.testcode.BenchmarkTest02015
import org.owasp.benchmark.testcode.BenchmarkTest02016
import org.owasp.benchmark.testcode.BenchmarkTest02017
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import org.owasp.benchmark.testcode.BenchmarkTest02018
import org.owasp.benchmark.testcode.BenchmarkTest02019
import org.owasp.benchmark.testcode.BenchmarkTest02020
import org.owasp.benchmark.testcode.BenchmarkTest02021
import org.owasp.benchmark.testcode.BenchmarkTest02022
import org.owasp.benchmark.testcode.BenchmarkTest02023
import org.owasp.benchmark.testcode.BenchmarkTest02024
import org.owasp.benchmark.testcode.BenchmarkTest02025
import org.owasp.benchmark.helpers.LDAPManager
import org.owasp.benchmark.helpers.Utils
import javax.naming.directory.DirContext
import javax.naming.directory.SearchControls
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import org.owasp.benchmark.testcode.BenchmarkTest02026
import org.owasp.benchmark.testcode.BenchmarkTest02027
import org.owasp.benchmark.testcode.BenchmarkTest02028
import org.owasp.benchmark.testcode.BenchmarkTest02029
import org.owasp.benchmark.testcode.BenchmarkTest02030
import java.net.URISyntaxException
import org.owasp.benchmark.testcode.BenchmarkTest02031
import org.owasp.benchmark.testcode.BenchmarkTest02032
import org.owasp.benchmark.testcode.BenchmarkTest02033
import org.owasp.benchmark.testcode.BenchmarkTest02034
import org.owasp.benchmark.testcode.BenchmarkTest02035
import org.owasp.benchmark.testcode.BenchmarkTest02036
import javax.naming.directory.InitialDirContext
import org.owasp.benchmark.testcode.BenchmarkTest02037
import org.owasp.benchmark.testcode.BenchmarkTest02038
import org.owasp.benchmark.testcode.BenchmarkTest02039
import org.owasp.benchmark.testcode.BenchmarkTest02040
import org.owasp.benchmark.testcode.BenchmarkTest02041
import org.owasp.benchmark.testcode.BenchmarkTest02042
import org.owasp.benchmark.testcode.BenchmarkTest02043
import org.owasp.benchmark.testcode.BenchmarkTest02044
import org.owasp.benchmark.testcode.BenchmarkTest02045
import org.owasp.benchmark.testcode.BenchmarkTest02046
import org.owasp.benchmark.testcode.BenchmarkTest02047
import org.owasp.benchmark.testcode.BenchmarkTest02048
import org.owasp.benchmark.testcode.BenchmarkTest02049
import org.owasp.benchmark.testcode.BenchmarkTest02050
import org.owasp.benchmark.testcode.BenchmarkTest02051
import org.owasp.benchmark.testcode.BenchmarkTest02052
import org.owasp.benchmark.testcode.BenchmarkTest02053
import org.owasp.benchmark.testcode.BenchmarkTest02054
import org.owasp.benchmark.testcode.BenchmarkTest02055
import org.owasp.benchmark.testcode.BenchmarkTest02056
import org.owasp.benchmark.testcode.BenchmarkTest02057
import org.owasp.benchmark.testcode.BenchmarkTest02058
import java.lang.ProcessBuilder
import org.owasp.benchmark.testcode.BenchmarkTest02059
import org.owasp.benchmark.testcode.BenchmarkTest02060
import org.owasp.benchmark.testcode.BenchmarkTest02061
import org.owasp.benchmark.testcode.BenchmarkTest02062
import org.owasp.benchmark.testcode.BenchmarkTest02063
import org.owasp.benchmark.testcode.BenchmarkTest02064
import org.owasp.benchmark.testcode.BenchmarkTest02065
import org.owasp.benchmark.testcode.BenchmarkTest02066
import org.owasp.benchmark.testcode.BenchmarkTest02067
import java.lang.Runtime
import org.owasp.benchmark.testcode.BenchmarkTest02068
import org.owasp.benchmark.testcode.BenchmarkTest02069
import org.owasp.benchmark.testcode.BenchmarkTest02070
import org.owasp.benchmark.testcode.BenchmarkTest02071
import org.owasp.benchmark.testcode.BenchmarkTest02072
import org.owasp.benchmark.testcode.BenchmarkTest02073
import org.owasp.benchmark.testcode.BenchmarkTest02074
import org.owasp.benchmark.testcode.BenchmarkTest02075
import org.owasp.benchmark.testcode.BenchmarkTest02076
import org.owasp.benchmark.testcode.BenchmarkTest02077
import org.owasp.benchmark.testcode.BenchmarkTest02078
import org.owasp.benchmark.testcode.BenchmarkTest02079
import org.owasp.benchmark.testcode.BenchmarkTest02080
import org.owasp.benchmark.testcode.BenchmarkTest02081
import org.owasp.benchmark.testcode.BenchmarkTest02082
import org.owasp.benchmark.testcode.BenchmarkTest02083
import org.owasp.benchmark.testcode.BenchmarkTest02084
import org.owasp.benchmark.testcode.BenchmarkTest02085
import org.owasp.benchmark.testcode.BenchmarkTest02086
import org.owasp.benchmark.testcode.BenchmarkTest02087
import java.sql.PreparedStatement
import java.sql.SQLException
import org.owasp.benchmark.testcode.BenchmarkTest02088
import org.owasp.benchmark.testcode.BenchmarkTest02089
import org.owasp.benchmark.testcode.BenchmarkTest02090
import org.springframework.dao.DataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02091
import org.springframework.dao.EmptyResultDataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02092
import org.owasp.benchmark.testcode.BenchmarkTest02093
import org.owasp.benchmark.testcode.BenchmarkTest02094
import org.owasp.benchmark.testcode.BenchmarkTest02095
import org.owasp.benchmark.testcode.BenchmarkTest02096
import org.owasp.benchmark.testcode.BenchmarkTest02097
import org.owasp.benchmark.testcode.BenchmarkTest02098
import org.owasp.benchmark.testcode.BenchmarkTest02099
import org.owasp.benchmark.testcode.BenchmarkTest02100
import org.owasp.esapi.ESAPI
import java.io.*
import java.net.URLDecoder
import java.security.*
import java.util.*
import javax.crypto.*

@WebServlet(value = ["/crypto-02/BenchmarkTest02020"])
class BenchmarkTest02020 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param = ""
        val headers = request.getHeaders("BenchmarkTest02020")
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement() // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = URLDecoder.decode(param, "UTF-8")
        val bar = doSomething(request, param)

        // Code based on example from:
        // http://examples.javacodegeeks.com/core-java/crypto/encrypt-decrypt-file-stream-with-des/
        // 8-byte initialization vector
//	    byte[] iv = {
//	    	(byte)0xB2, (byte)0x12, (byte)0xD5, (byte)0xB2,
//	    	(byte)0x44, (byte)0x21, (byte)0xC3, (byte)0xC3033
//	    };
        val random = SecureRandom()
        val iv = random.generateSeed(8) // DES requires 8 byte keys
        try {
            val c = Cipher.getInstance("DES/CBC/PKCS5Padding", "SunJCE")
            // Prepare the cipher to encrypt
            val key = KeyGenerator.getInstance("DES").generateKey()
            val paramSpec: AlgorithmParameterSpec = IvParameterSpec(iv)
            c.init(Cipher.ENCRYPT_MODE, key, paramSpec)

            // encrypt and store the results
            var input: ByteArray? = byteArrayOf('?'.toByte())
            val inputParam: Any? = bar
            if (inputParam is String) input = inputParam.toByteArray()
            if (inputParam is InputStream) {
                val strInput = ByteArray(1000)
                val i = inputParam.read(strInput)
                if (i == -1) {
                    response.writer.println(
                        "This input source requires a POST, not a GET. Incompatible UI for the InputStream source."
                    )
                    return
                }
                input = Arrays.copyOf(strInput, i)
            }
            val result = c.doFinal(input)
            val fileTarget = File(
                File(Utils.TESTFILES_DIR), "passwordFile.txt"
            )
            val fw = FileWriter(fileTarget, true) //the true will append the new data
            fw.write(
                """
    secret_value=${ESAPI.encoder().encodeForBase64(result, true)}
    
    """.trimIndent()
            )
            fw.close()
            response.writer.println(
                "Sensitive value: '" + ESAPI.encoder().encodeForHTML(String(input!!)) + "' encrypted and stored<br/>"
            )
        } catch (e: NoSuchAlgorithmException) {
            response.writer.println(
                "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case"
            )
            e.printStackTrace(response.writer)
            throw ServletException(e)
        } catch (e: NoSuchProviderException) {
            response.writer.println(
                "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case"
            )
            e.printStackTrace(response.writer)
            throw ServletException(e)
        } catch (e: NoSuchPaddingException) {
            response.writer.println(
                "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case"
            )
            e.printStackTrace(response.writer)
            throw ServletException(e)
        } catch (e: IllegalBlockSizeException) {
            response.writer.println(
                "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case"
            )
            e.printStackTrace(response.writer)
            throw ServletException(e)
        } catch (e: BadPaddingException) {
            response.writer.println(
                "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case"
            )
            e.printStackTrace(response.writer)
            throw ServletException(e)
        } catch (e: InvalidKeyException) {
            response.writer.println(
                "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case"
            )
            e.printStackTrace(response.writer)
            throw ServletException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            response.writer.println(
                "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) Test Case"
            )
            e.printStackTrace(response.writer)
            throw ServletException(e)
        }
        response.writer.println(
            "Crypto Test javax.crypto.Cipher.getInstance(java.lang.String,java.lang.String) executed"
        )
    } // end doPost

    companion object {
        private const val serialVersionUID = 1L
        @Throws(ServletException::class, IOException::class)
        private fun doSomething(request: HttpServletRequest, param: String): String? {
            var bar: String? = "safe!"
            val map95233 = HashMap<String, Any>()
            map95233["keyA-95233"] = "a_Value" // put some stuff in the collection
            map95233["keyB-95233"] = param // put it in a collection
            map95233["keyC"] = "another_Value" // put some stuff in the collection
            bar = map95233["keyB-95233"] as String? // get it back out
            bar = map95233["keyA-95233"] as String? // get safe value back out
            return bar
        }
    }
}