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
import org.owasp.benchmark.helpers.*
import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServlet
import kotlin.Throws
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.owasp.benchmark.testcode.BenchmarkTest02256
import java.security.NoSuchAlgorithmException
import org.owasp.benchmark.testcode.BenchmarkTest02257
import org.owasp.benchmark.testcode.BenchmarkTest02258
import org.owasp.benchmark.testcode.BenchmarkTest02259
import org.owasp.benchmark.testcode.BenchmarkTest02260
import org.owasp.benchmark.testcode.BenchmarkTest02261
import org.owasp.benchmark.testcode.BenchmarkTest02262
import org.owasp.benchmark.testcode.BenchmarkTest02263
import org.owasp.benchmark.testcode.BenchmarkTest02264
import java.sql.CallableStatement
import java.sql.SQLException
import org.owasp.benchmark.testcode.BenchmarkTest02265
import org.owasp.benchmark.testcode.BenchmarkTest02266
import org.owasp.benchmark.testcode.BenchmarkTest02267
import java.sql.PreparedStatement
import org.owasp.benchmark.testcode.BenchmarkTest02268
import org.owasp.benchmark.testcode.BenchmarkTest02269
import org.owasp.benchmark.testcode.BenchmarkTest02270
import org.owasp.benchmark.testcode.BenchmarkTest02271
import org.owasp.benchmark.testcode.BenchmarkTest02272
import org.springframework.dao.DataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02273
import org.owasp.benchmark.testcode.BenchmarkTest02274
import org.springframework.dao.EmptyResultDataAccessException
import org.owasp.benchmark.testcode.BenchmarkTest02275
import org.owasp.benchmark.testcode.BenchmarkTest02276
import org.owasp.benchmark.testcode.BenchmarkTest02277
import org.owasp.benchmark.testcode.BenchmarkTest02278
import org.owasp.benchmark.testcode.BenchmarkTest02279
import org.owasp.benchmark.testcode.BenchmarkTest02280
import org.owasp.benchmark.testcode.BenchmarkTest02281
import org.owasp.benchmark.testcode.BenchmarkTest02282
import org.owasp.benchmark.testcode.BenchmarkTest02283
import org.owasp.benchmark.testcode.BenchmarkTest02284
import org.owasp.benchmark.testcode.BenchmarkTest02285
import org.owasp.benchmark.testcode.BenchmarkTest02286
import org.owasp.benchmark.testcode.BenchmarkTest02287
import org.owasp.benchmark.testcode.BenchmarkTest02288
import org.owasp.benchmark.testcode.BenchmarkTest02289
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.NoSuchPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import java.security.InvalidAlgorithmParameterException
import org.owasp.benchmark.testcode.BenchmarkTest02290
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import org.owasp.benchmark.testcode.BenchmarkTest02291
import java.lang.StringBuilder
import org.owasp.benchmark.testcode.BenchmarkTest02292
import org.owasp.benchmark.testcode.BenchmarkTest02293
import org.owasp.benchmark.testcode.BenchmarkTest02294
import org.owasp.benchmark.testcode.BenchmarkTest02295
import org.owasp.benchmark.testcode.BenchmarkTest02296
import org.owasp.benchmark.testcode.BenchmarkTest02297
import org.owasp.benchmark.testcode.BenchmarkTest02298
import org.owasp.benchmark.testcode.BenchmarkTest02299
import javax.naming.directory.DirContext
import javax.naming.directory.SearchControls
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import org.owasp.benchmark.testcode.BenchmarkTest02300
import org.owasp.benchmark.testcode.BenchmarkTest02301
import org.owasp.benchmark.testcode.BenchmarkTest02302
import org.owasp.benchmark.testcode.BenchmarkTest02303
import org.owasp.benchmark.testcode.BenchmarkTest02304
import org.owasp.benchmark.testcode.BenchmarkTest02305
import javax.naming.directory.InitialDirContext
import org.owasp.benchmark.testcode.BenchmarkTest02306
import org.owasp.benchmark.testcode.BenchmarkTest02307
import java.security.MessageDigest
import org.owasp.benchmark.testcode.BenchmarkTest02308
import org.owasp.benchmark.testcode.BenchmarkTest02309
import org.owasp.benchmark.testcode.BenchmarkTest02310
import org.owasp.benchmark.testcode.BenchmarkTest02311
import org.owasp.benchmark.testcode.BenchmarkTest02312
import org.owasp.benchmark.testcode.BenchmarkTest02313
import org.owasp.benchmark.testcode.BenchmarkTest02314
import org.owasp.benchmark.testcode.BenchmarkTest02315
import org.owasp.benchmark.testcode.BenchmarkTest02316
import org.owasp.benchmark.testcode.BenchmarkTest02317
import org.owasp.benchmark.testcode.BenchmarkTest02318
import org.owasp.benchmark.testcode.BenchmarkTest02319
import org.owasp.benchmark.testcode.BenchmarkTest02320
import org.owasp.benchmark.testcode.BenchmarkTest02321
import org.owasp.benchmark.testcode.BenchmarkTest02322
import org.owasp.benchmark.testcode.BenchmarkTest02323
import org.owasp.benchmark.testcode.BenchmarkTest02324
import org.owasp.benchmark.testcode.BenchmarkTest02325
import org.owasp.benchmark.testcode.BenchmarkTest02326
import org.owasp.benchmark.testcode.BenchmarkTest02327
import org.owasp.benchmark.testcode.BenchmarkTest02328
import org.owasp.benchmark.testcode.BenchmarkTest02329
import org.owasp.benchmark.testcode.BenchmarkTest02330
import org.owasp.benchmark.testcode.BenchmarkTest02331
import org.owasp.benchmark.testcode.BenchmarkTest02332
import org.owasp.benchmark.testcode.BenchmarkTest02333
import java.lang.ProcessBuilder
import org.owasp.benchmark.testcode.BenchmarkTest02334
import org.owasp.benchmark.testcode.BenchmarkTest02335
import org.owasp.benchmark.testcode.BenchmarkTest02336
import org.owasp.benchmark.testcode.BenchmarkTest02337
import org.owasp.benchmark.testcode.BenchmarkTest02338
import org.owasp.benchmark.testcode.BenchmarkTest02339
import org.owasp.benchmark.testcode.BenchmarkTest02340
import java.lang.Runtime
import org.owasp.benchmark.testcode.BenchmarkTest02341
import org.owasp.benchmark.testcode.BenchmarkTest02342
import org.owasp.benchmark.testcode.BenchmarkTest02343
import org.owasp.benchmark.testcode.BenchmarkTest02344
import org.owasp.benchmark.testcode.BenchmarkTest02345
import org.owasp.benchmark.testcode.BenchmarkTest02346
import org.owasp.benchmark.testcode.BenchmarkTest02347
import org.owasp.benchmark.testcode.BenchmarkTest02348
import org.owasp.benchmark.testcode.BenchmarkTest02349
import org.owasp.benchmark.testcode.BenchmarkTest02350
import org.owasp.benchmark.testcode.BenchmarkTest02351
import org.owasp.benchmark.testcode.BenchmarkTest02352
import org.owasp.benchmark.testcode.BenchmarkTest02353
import org.owasp.benchmark.testcode.BenchmarkTest02354
import org.owasp.benchmark.testcode.BenchmarkTest02355
import org.owasp.benchmark.testcode.BenchmarkTest02356
import org.owasp.benchmark.testcode.BenchmarkTest02357
import org.owasp.benchmark.testcode.BenchmarkTest02358
import org.owasp.benchmark.testcode.BenchmarkTest02359
import org.owasp.benchmark.testcode.BenchmarkTest02360
import org.owasp.benchmark.testcode.BenchmarkTest02361
import org.owasp.benchmark.testcode.BenchmarkTest02362
import org.springframework.jdbc.support.rowset.SqlRowSet
import org.owasp.benchmark.testcode.BenchmarkTest02363
import org.owasp.benchmark.testcode.BenchmarkTest02364
import org.owasp.benchmark.testcode.BenchmarkTest02365
import org.owasp.benchmark.testcode.BenchmarkTest02366
import org.owasp.benchmark.testcode.BenchmarkTest02367
import org.owasp.benchmark.testcode.BenchmarkTest02368
import org.owasp.benchmark.testcode.BenchmarkTest02369
import org.owasp.benchmark.testcode.BenchmarkTest02370
import org.owasp.benchmark.testcode.BenchmarkTest02371
import org.owasp.benchmark.testcode.BenchmarkTest02372
import org.owasp.benchmark.testcode.BenchmarkTest02373
import org.owasp.benchmark.testcode.BenchmarkTest02374
import org.owasp.benchmark.testcode.BenchmarkTest02375
import org.owasp.benchmark.testcode.BenchmarkTest02376
import org.owasp.benchmark.testcode.BenchmarkTest02377
import org.owasp.benchmark.testcode.BenchmarkTest02378
import java.net.URISyntaxException
import org.owasp.benchmark.testcode.BenchmarkTest02379
import org.owasp.benchmark.testcode.BenchmarkTest02380
import org.owasp.benchmark.testcode.BenchmarkTest02381
import org.owasp.benchmark.testcode.BenchmarkTest02382
import org.owasp.benchmark.testcode.BenchmarkTest02383
import org.owasp.benchmark.testcode.BenchmarkTest02384
import org.owasp.benchmark.testcode.BenchmarkTest02385
import org.owasp.benchmark.testcode.BenchmarkTest02386
import org.owasp.benchmark.testcode.BenchmarkTest02387
import org.owasp.benchmark.testcode.BenchmarkTest02388
import org.owasp.benchmark.testcode.BenchmarkTest02389
import org.owasp.benchmark.testcode.BenchmarkTest02390
import org.owasp.benchmark.testcode.BenchmarkTest02391
import org.owasp.benchmark.testcode.BenchmarkTest02392
import org.owasp.benchmark.testcode.BenchmarkTest02393
import org.owasp.benchmark.testcode.BenchmarkTest02394
import org.owasp.benchmark.testcode.BenchmarkTest02395
import org.owasp.benchmark.testcode.BenchmarkTest02396
import org.owasp.benchmark.testcode.BenchmarkTest02397
import org.owasp.benchmark.testcode.BenchmarkTest02398
import org.owasp.benchmark.testcode.BenchmarkTest02399
import org.owasp.benchmark.testcode.BenchmarkTest02400
import org.owasp.benchmark.testcode.BenchmarkTest02401
import org.owasp.benchmark.testcode.BenchmarkTest02402
import org.owasp.benchmark.testcode.BenchmarkTest02403
import org.owasp.benchmark.testcode.BenchmarkTest02404
import org.owasp.benchmark.testcode.BenchmarkTest02405
import org.owasp.benchmark.testcode.BenchmarkTest02406
import org.owasp.benchmark.testcode.BenchmarkTest02407
import org.owasp.benchmark.testcode.BenchmarkTest02408
import org.owasp.benchmark.testcode.BenchmarkTest02409
import org.owasp.benchmark.testcode.BenchmarkTest02410
import org.owasp.esapi.ESAPI
import java.io.*
import java.util.*

@WebServlet(value = ["/hash-02/BenchmarkTest02393"])
class BenchmarkTest02393 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        val scr = SeparateClassRequest(request)
        var param = scr.getTheParameter("BenchmarkTest02393")
        if (param == null) param = ""
        val bar = doSomething(request, param)
        try {
            val benchmarkprops = Properties()
            benchmarkprops.load(this.javaClass.classLoader.getResourceAsStream("benchmark.properties"))
            val algorithm = benchmarkprops.getProperty("hashAlg1", "SHA512")
            val md = MessageDigest.getInstance(algorithm)
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
            md.update(input)
            val result = md.digest()
            val fileTarget = File(
                File(Utils.TESTFILES_DIR), "passwordFile.txt"
            )
            val fw = FileWriter(fileTarget, true) //the true will append the new data
            fw.write(
                """
                    hash_value=${ESAPI.encoder().encodeForBase64(result, true)}
                    
                    """.trimIndent()
            )
            fw.close()
            response.writer.println(
                "Sensitive value '" + ESAPI.encoder().encodeForHTML(String(input!!)) + "' hashed and stored<br/>"
            )
        } catch (e: NoSuchAlgorithmException) {
            println("Problem executing hash - TestCase")
            throw ServletException(e)
        }
        response.writer.println(
            "Hash Test java.security.MessageDigest.getInstance(java.lang.String) executed"
        )
    } // end doPost

    companion object {
        private const val serialVersionUID = 1L

        @Throws(ServletException::class, IOException::class)
        private fun doSomething(request: HttpServletRequest, param: String): String {

            // Chain a bunch of propagators in sequence
            val b24492 = StringBuilder(
                param //assign
            ) // stick in stringbuilder
            b24492.append(" SafeStuff") // append some safe content
            b24492.replace(b24492.length - "Chars".length, b24492.length, "Chars") //replace some of the end content
            val map24492 =
                HashMap<String, Any>()
            map24492["key24492"] = b24492.toString() // put in a collection
            val c24492 = map24492["key24492"] as String? // get it back out
            val d24492 = c24492!!.substring(0, c24492.length - 1) // extract most of it
            val e24492 = String(
                Base64.decodeBase64(
                    Base64.encodeBase64(d24492.toByteArray())
                )
            ) // B64 encode and decode it
            val f24492 = e24492.split(" ".toRegex()).toTypedArray()[0] // split it on a space
            val thing = ThingFactory.createThing()
            val g24492 = "barbarians_at_the_gate" // This is static so this whole flow is 'safe'
            return thing.doSomething(g24492) // reflection
        }
    }
}