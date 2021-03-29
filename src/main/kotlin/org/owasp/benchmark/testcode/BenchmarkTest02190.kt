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
import org.owasp.benchmark.testcode.BenchmarkTest02101
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import org.owasp.benchmark.testcode.BenchmarkTest02102
import java.lang.StringBuilder
import org.owasp.benchmark.testcode.BenchmarkTest02103
import org.owasp.benchmark.testcode.BenchmarkTest02104
import org.owasp.benchmark.helpers.LDAPManager
import javax.naming.directory.DirContext
import javax.naming.directory.SearchControls
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import org.owasp.benchmark.testcode.BenchmarkTest02105
import org.owasp.benchmark.testcode.BenchmarkTest02106
import org.owasp.benchmark.testcode.BenchmarkTest02107
import org.owasp.benchmark.testcode.BenchmarkTest02108
import org.owasp.benchmark.testcode.BenchmarkTest02109
import org.owasp.benchmark.testcode.BenchmarkTest02110
import org.owasp.benchmark.testcode.BenchmarkTest02111
import org.owasp.benchmark.testcode.BenchmarkTest02112
import org.owasp.benchmark.testcode.BenchmarkTest02113
import org.owasp.benchmark.testcode.BenchmarkTest02114
import javax.naming.directory.InitialDirContext
import org.owasp.benchmark.testcode.BenchmarkTest02115
import org.owasp.benchmark.testcode.BenchmarkTest02116
import org.owasp.benchmark.testcode.BenchmarkTest02117
import org.owasp.benchmark.testcode.BenchmarkTest02118
import org.owasp.benchmark.testcode.BenchmarkTest02119
import org.owasp.benchmark.testcode.BenchmarkTest02120
import org.owasp.benchmark.testcode.BenchmarkTest02121
import org.owasp.benchmark.testcode.BenchmarkTest02122
import org.owasp.benchmark.testcode.BenchmarkTest02123
import org.owasp.benchmark.helpers.ThingInterface
import org.owasp.benchmark.helpers.Utils
import org.owasp.benchmark.testcode.BenchmarkTest02124
import org.owasp.benchmark.testcode.BenchmarkTest02125
import org.owasp.benchmark.testcode.BenchmarkTest02126
import org.owasp.benchmark.testcode.BenchmarkTest02127
import org.owasp.benchmark.testcode.BenchmarkTest02128
import org.owasp.benchmark.testcode.BenchmarkTest02129
import org.owasp.benchmark.testcode.BenchmarkTest02130
import org.owasp.benchmark.testcode.BenchmarkTest02131
import org.owasp.benchmark.testcode.BenchmarkTest02132
import org.owasp.benchmark.testcode.BenchmarkTest02133
import org.owasp.benchmark.testcode.BenchmarkTest02134
import org.owasp.benchmark.testcode.BenchmarkTest02135
import org.owasp.benchmark.testcode.BenchmarkTest02136
import org.owasp.benchmark.testcode.BenchmarkTest02137
import java.lang.ProcessBuilder
import org.owasp.benchmark.testcode.BenchmarkTest02138
import org.owasp.benchmark.testcode.BenchmarkTest02139
import org.owasp.benchmark.testcode.BenchmarkTest02140
import org.owasp.benchmark.testcode.BenchmarkTest02141
import org.owasp.benchmark.testcode.BenchmarkTest02142
import org.owasp.benchmark.testcode.BenchmarkTest02143
import org.owasp.benchmark.testcode.BenchmarkTest02144
import org.owasp.benchmark.testcode.BenchmarkTest02145
import org.owasp.benchmark.testcode.BenchmarkTest02146
import java.lang.Runtime
import org.owasp.benchmark.testcode.BenchmarkTest02147
import org.owasp.benchmark.testcode.BenchmarkTest02148
import org.owasp.benchmark.testcode.BenchmarkTest02149
import org.owasp.benchmark.testcode.BenchmarkTest02150
import org.owasp.benchmark.testcode.BenchmarkTest02151
import org.owasp.benchmark.testcode.BenchmarkTest02152
import org.owasp.benchmark.testcode.BenchmarkTest02153
import org.owasp.benchmark.testcode.BenchmarkTest02154
import org.owasp.benchmark.testcode.BenchmarkTest02155
import org.owasp.benchmark.testcode.BenchmarkTest02156
import org.owasp.benchmark.testcode.BenchmarkTest02157
import org.owasp.benchmark.testcode.BenchmarkTest02158
import org.owasp.benchmark.testcode.BenchmarkTest02159
import org.owasp.benchmark.testcode.BenchmarkTest02160
import org.owasp.benchmark.testcode.BenchmarkTest02161
import org.owasp.benchmark.testcode.BenchmarkTest02162
import org.owasp.benchmark.testcode.BenchmarkTest02163
import org.owasp.benchmark.testcode.BenchmarkTest02164
import org.owasp.benchmark.testcode.BenchmarkTest02165
import org.owasp.benchmark.testcode.BenchmarkTest02166
import org.owasp.benchmark.testcode.BenchmarkTest02167
import org.owasp.benchmark.testcode.BenchmarkTest02168
import org.owasp.benchmark.testcode.BenchmarkTest02169
import java.sql.CallableStatement
import java.sql.SQLException
import org.owasp.benchmark.testcode.BenchmarkTest02170
import org.owasp.benchmark.testcode.BenchmarkTest02171
import java.sql.PreparedStatement
import org.owasp.benchmark.testcode.BenchmarkTest02172
import org.owasp.benchmark.testcode.BenchmarkTest02173
import org.owasp.benchmark.testcode.BenchmarkTest02174
import org.springframework.dao.DataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02175
import org.owasp.benchmark.testcode.BenchmarkTest02176
import org.owasp.benchmark.testcode.BenchmarkTest02177
import org.springframework.dao.EmptyResultDataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02178
import org.owasp.benchmark.testcode.BenchmarkTest02179
import org.owasp.benchmark.testcode.BenchmarkTest02180
import org.owasp.benchmark.testcode.BenchmarkTest02181
import org.owasp.benchmark.testcode.BenchmarkTest02182
import org.owasp.benchmark.testcode.BenchmarkTest02183
import org.owasp.benchmark.testcode.BenchmarkTest02184
import org.springframework.jdbc.support.rowset.SqlRowSet
import org.owasp.benchmark.testcode.BenchmarkTest02185
import org.owasp.benchmark.testcode.BenchmarkTest02186
import org.owasp.benchmark.testcode.BenchmarkTest02187
import org.owasp.benchmark.testcode.BenchmarkTest02188
import org.owasp.benchmark.testcode.BenchmarkTest02189
import org.owasp.benchmark.testcode.BenchmarkTest02190
import javax.crypto.spec.GCMParameterSpec
import org.owasp.benchmark.testcode.BenchmarkTest02191
import org.owasp.benchmark.testcode.BenchmarkTest02192
import org.owasp.benchmark.testcode.BenchmarkTest02193
import org.owasp.benchmark.testcode.BenchmarkTest02194
import org.owasp.benchmark.testcode.BenchmarkTest02195
import org.owasp.benchmark.testcode.BenchmarkTest02196
import org.owasp.benchmark.testcode.BenchmarkTest02197
import org.owasp.benchmark.testcode.BenchmarkTest02198
import org.owasp.benchmark.testcode.BenchmarkTest02199
import org.owasp.benchmark.testcode.BenchmarkTest02200
import org.owasp.benchmark.testcode.BenchmarkTest02201
import org.owasp.benchmark.testcode.BenchmarkTest02202
import org.owasp.benchmark.testcode.BenchmarkTest02203
import org.owasp.benchmark.testcode.BenchmarkTest02204
import org.owasp.benchmark.testcode.BenchmarkTest02205
import org.owasp.benchmark.testcode.BenchmarkTest02206
import org.owasp.benchmark.testcode.BenchmarkTest02207
import org.owasp.benchmark.testcode.BenchmarkTest02208
import org.owasp.benchmark.testcode.BenchmarkTest02209
import org.owasp.benchmark.testcode.BenchmarkTest02210
import org.owasp.benchmark.testcode.BenchmarkTest02211
import org.owasp.benchmark.testcode.BenchmarkTest02212
import org.owasp.benchmark.testcode.BenchmarkTest02213
import org.owasp.benchmark.testcode.BenchmarkTest02214
import org.owasp.benchmark.testcode.BenchmarkTest02215
import org.owasp.benchmark.testcode.BenchmarkTest02216
import org.owasp.benchmark.testcode.BenchmarkTest02217
import org.owasp.benchmark.testcode.BenchmarkTest02218
import org.owasp.benchmark.testcode.BenchmarkTest02219
import org.owasp.benchmark.testcode.BenchmarkTest02220
import org.owasp.benchmark.testcode.BenchmarkTest02221
import org.owasp.benchmark.testcode.BenchmarkTest02222
import org.owasp.benchmark.testcode.BenchmarkTest02223
import org.owasp.benchmark.testcode.BenchmarkTest02224
import org.owasp.benchmark.testcode.BenchmarkTest02225
import org.owasp.benchmark.testcode.BenchmarkTest02226
import org.owasp.benchmark.testcode.BenchmarkTest02227
import org.owasp.benchmark.testcode.BenchmarkTest02228
import org.owasp.benchmark.testcode.BenchmarkTest02229
import org.owasp.benchmark.testcode.BenchmarkTest02230
import org.owasp.benchmark.testcode.BenchmarkTest02231
import org.owasp.benchmark.testcode.BenchmarkTest02232
import org.owasp.benchmark.testcode.BenchmarkTest02233
import org.owasp.benchmark.testcode.BenchmarkTest02234
import org.owasp.benchmark.testcode.BenchmarkTest02235
import org.owasp.benchmark.testcode.BenchmarkTest02236
import org.owasp.benchmark.testcode.BenchmarkTest02237
import org.owasp.benchmark.testcode.BenchmarkTest02238
import org.owasp.benchmark.testcode.BenchmarkTest02239
import org.owasp.benchmark.testcode.BenchmarkTest02240
import org.owasp.benchmark.testcode.BenchmarkTest02241
import org.owasp.benchmark.testcode.BenchmarkTest02242
import org.owasp.benchmark.testcode.BenchmarkTest02243
import org.owasp.benchmark.testcode.BenchmarkTest02244
import org.owasp.benchmark.testcode.BenchmarkTest02245
import org.owasp.benchmark.testcode.BenchmarkTest02246
import org.owasp.benchmark.testcode.BenchmarkTest02247
import org.owasp.benchmark.testcode.BenchmarkTest02248
import org.owasp.benchmark.testcode.BenchmarkTest02249
import org.owasp.benchmark.testcode.BenchmarkTest02250
import org.owasp.benchmark.testcode.BenchmarkTest02251
import org.owasp.benchmark.testcode.BenchmarkTest02252
import org.owasp.benchmark.testcode.BenchmarkTest02253
import org.owasp.benchmark.testcode.BenchmarkTest02254
import org.owasp.benchmark.testcode.BenchmarkTest02255
import org.owasp.esapi.ESAPI
import java.io.*
import java.security.*
import java.util.*
import javax.crypto.*

@WebServlet(value = ["/crypto-02/BenchmarkTest02190"])
class BenchmarkTest02190 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val map = request.parameterMap
        var param = ""
        if (!map.isEmpty()) {
            val values = map["BenchmarkTest02190"]
            if (values != null) param = values[0]
        }
        val bar = doSomething(request, param)

        // Code based on example from:
        // http://examples.javacodegeeks.com/core-java/crypto/encrypt-decrypt-file-stream-with-des/
        // AES/GCM example from: https://javainterviewpoint.com/java-aes-256-gcm-encryption-and-decryption/
        // 16-byte initialization vector
//	    byte[] iv = {
//	    	(byte)0xB2, (byte)0x12, (byte)0xD5, (byte)0xB2,
//	    	(byte)0x44, (byte)0x21, (byte)0xC3, (byte)0xC3,
//	    	(byte)0xF3, (byte)0x3C, (byte)0x23, (byte)0xB9,
//	    	(byte)0x9E, (byte)0xC5, (byte)0x77, (byte)0x0B033
//	    };
        val random = SecureRandom()
        val iv = random.generateSeed(16)
        try {
            val c = Cipher.getInstance("AES/GCM/NOPADDING")

            // Prepare the cipher to encrypt
            val key = KeyGenerator.getInstance("AES").generateKey()
            val paramSpec = GCMParameterSpec(16 * 8, iv)
            c.init(Cipher.ENCRYPT_MODE, key, paramSpec)

            // encrypt and store the results
            var input: ByteArray? = byteArrayOf('?'.toByte())
            val inputParam: Any = bar
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
                "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String) Test Case"
            )
            e.printStackTrace(response.writer)
            throw ServletException(e)
        } catch (e: NoSuchPaddingException) {
            response.writer.println(
                "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String) Test Case"
            )
            e.printStackTrace(response.writer)
            throw ServletException(e)
        } catch (e: IllegalBlockSizeException) {
            response.writer.println(
                "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String) Test Case"
            )
            e.printStackTrace(response.writer)
            throw ServletException(e)
        } catch (e: BadPaddingException) {
            response.writer.println(
                "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String) Test Case"
            )
            e.printStackTrace(response.writer)
            throw ServletException(e)
        } catch (e: InvalidKeyException) {
            response.writer.println(
                "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String) Test Case"
            )
            e.printStackTrace(response.writer)
            throw ServletException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            response.writer.println(
                "Problem executing crypto - javax.crypto.Cipher.getInstance(java.lang.String) Test Case"
            )
            e.printStackTrace(response.writer)
            throw ServletException(e)
        }
        response.writer.println(
            "Crypto Test javax.crypto.Cipher.getInstance(java.lang.String) executed"
        )
    } // end doPost

    companion object {
        private const val serialVersionUID = 1L

        @Throws(ServletException::class, IOException::class)
        private fun doSomething(request: HttpServletRequest, param: String): String {
            return ESAPI.encoder().encodeForHTML(param)
        }
    }
}