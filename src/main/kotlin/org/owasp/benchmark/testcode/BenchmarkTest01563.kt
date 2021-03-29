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

import org.owasp.benchmark.helpers.*
import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServlet
import kotlin.Throws
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import java.lang.StringBuilder
import java.lang.ProcessBuilder
import java.lang.Runtime
import java.sql.PreparedStatement
import java.sql.SQLException
import org.springframework.dao.DataAccessException
import org.springframework.dao.EmptyResultDataAccessException
import javax.crypto.spec.GCMParameterSpec
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
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
import org.owasp.esapi.ESAPI
import java.io.*
import java.security.*
import java.util.*
import javax.crypto.*

@WebServlet(value = ["/crypto-01/BenchmarkTest01563"])
class BenchmarkTest01563 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val values = request.getParameterValues("BenchmarkTest01563")
        val param: String
        param = if (values != null && values.size > 0) values[0] else ""
        val bar: String = Test().doSomething(request, param)

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

    private inner class Test {
        @Throws(ServletException::class, IOException::class)
        fun doSomething(request: HttpServletRequest?, param: String?): String {
            val thing = ThingFactory.createThing()
            return thing.doSomething(param)
        }
    } // end innerclass Test

    companion object {
        private const val serialVersionUID = 1L
    }
} // end DataflowThruInnerClass
