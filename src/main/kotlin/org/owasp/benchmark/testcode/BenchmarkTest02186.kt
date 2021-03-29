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

import org.owasp.benchmark.helpers.DatabaseHelper
import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServlet
import kotlin.Throws
import javax.servlet.ServletException
import java.io.IOException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.owasp.benchmark.testcode.BenchmarkTest02101
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
import org.owasp.benchmark.testcode.BenchmarkTest02102
import java.lang.StringBuilder
import org.owasp.benchmark.testcode.BenchmarkTest02103
import org.owasp.benchmark.testcode.BenchmarkTest02104
import org.owasp.benchmark.helpers.LDAPManager
import org.owasp.benchmark.helpers.ThingFactory
import javax.naming.directory.DirContext
import javax.naming.directory.SearchControls
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import org.owasp.benchmark.testcode.BenchmarkTest02105
import org.owasp.benchmark.testcode.BenchmarkTest02106
import org.owasp.benchmark.testcode.BenchmarkTest02107
import org.owasp.benchmark.testcode.BenchmarkTest02108
import java.io.FileOutputStream
import org.owasp.benchmark.testcode.BenchmarkTest02109
import org.owasp.benchmark.testcode.BenchmarkTest02110
import org.owasp.benchmark.testcode.BenchmarkTest02111
import java.io.FileInputStream
import org.owasp.benchmark.testcode.BenchmarkTest02112
import org.owasp.benchmark.testcode.BenchmarkTest02113
import org.owasp.benchmark.testcode.BenchmarkTest02114
import javax.naming.directory.InitialDirContext
import org.owasp.benchmark.testcode.BenchmarkTest02115
import org.owasp.benchmark.testcode.BenchmarkTest02116
import org.owasp.benchmark.testcode.BenchmarkTest02117
import org.owasp.benchmark.testcode.BenchmarkTest02118
import java.security.MessageDigest
import org.owasp.benchmark.testcode.BenchmarkTest02119
import org.owasp.benchmark.testcode.BenchmarkTest02120
import org.owasp.benchmark.testcode.BenchmarkTest02121
import org.owasp.benchmark.testcode.BenchmarkTest02122
import java.io.PrintWriter
import org.owasp.benchmark.testcode.BenchmarkTest02123
import org.owasp.benchmark.helpers.ThingInterface
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

@WebServlet(value = ["/sqli-04/BenchmarkTest02186"])
class BenchmarkTest02186 : HttpServlet() {
    @Throws(ServletException::class, IOException::class)
    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        doPost(request, response)
    }

    @Throws(ServletException::class, IOException::class)
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse) {
        response.contentType = "text/html;charset=UTF-8"
        var param = request.getParameter("BenchmarkTest02186")
        if (param == null) param = ""
        val bar = doSomething(request, param)
        val sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='$bar'"
        try {
            val statement = DatabaseHelper.getSqlStatement()
            statement.execute(sql)
            DatabaseHelper.printResults(statement, sql, response)
        } catch (e: SQLException) {
            if (DatabaseHelper.hideSQLErrors) {
                response.writer.println(
                    "Error processing request."
                )
                return
            } else throw ServletException(e)
        }
    } // end doPost

    companion object {
        private const val serialVersionUID = 1L

        @Throws(ServletException::class, IOException::class)
        private fun doSomething(request: HttpServletRequest, param: String): String {
            val thing = ThingFactory.createThing()
            return thing.doSomething(param)
        }
    }
}