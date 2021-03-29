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
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.sql.PreparedStatement
import java.sql.SQLException
import org.owasp.benchmark.helpers.ThingInterface
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.dao.DataAccessException
import java.lang.StringBuilder
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.GCMParameterSpec
import org.owasp.benchmark.helpers.LDAPManager
import org.owasp.benchmark.helpers.ThingFactory
import org.owasp.benchmark.helpers.Utils
import org.owasp.esapi.ESAPI
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import java.lang.ProcessBuilder
import java.lang.Runtime
import java.sql.CallableStatement
import java.net.URISyntaxException
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.io.*
import java.net.URLDecoder
import java.security.*
import java.util.*
import javax.crypto.*

@WebServlet(value = ["/crypto-00/BenchmarkTest00119"])
class BenchmarkTest00119 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param = ""
        if (request.getHeader("BenchmarkTest00119") != null) {
            param = request.getHeader("BenchmarkTest00119")
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = URLDecoder.decode(param, "UTF-8")


        // Chain a bunch of propagators in sequence
        val a8142 = param //assign
        val b8142 = StringBuilder(a8142) // stick in stringbuilder
        b8142.append(" SafeStuff") // append some safe content
        b8142.replace(b8142.length - "Chars".length, b8142.length, "Chars") //replace some of the end content
        val map8142 = HashMap<String, Any>()
        map8142["key8142"] = b8142.toString() // put in a collection
        val c8142 = map8142["key8142"] as String? // get it back out
        val d8142 = c8142!!.substring(0, c8142.length - 1) // extract most of it
        val e8142 = String(
            Base64.decodeBase64(
                Base64.encodeBase64(d8142.toByteArray())
            )
        ) // B64 encode and decode it
        val f8142 = e8142.split(" ".toRegex()).toTypedArray()[0] // split it on a space
        val thing = ThingFactory.createThing()
        val bar = thing.doSomething(f8142) // reflection


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
            val c = Cipher.getInstance("DES/CBC/PKCS5PADDING", Security.getProvider("SunJCE"))

            // Prepare the cipher to encrypt
            val key = KeyGenerator.getInstance("DES").generateKey()
            val paramSpec: AlgorithmParameterSpec = IvParameterSpec(iv)
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
            "Crypto Test javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) executed"
        )
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}