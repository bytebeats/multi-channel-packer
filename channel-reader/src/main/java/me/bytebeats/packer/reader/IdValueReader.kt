package me.bytebeats.packer.reader

import me.bytebeats.packer.base.CONTENT_CHAR_SET
import me.bytebeats.packer.base.SignatureNotFoundException
import me.bytebeats.packer.base.V2SchemeUtils
import java.io.File
import java.io.IOException
import java.io.UnsupportedEncodingException
import java.nio.ByteBuffer
import java.util.*


/**
 * Created by bytebeats on 2022/3/11 : 20:04
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */

/**
 * Read Id-Value pair from apk v2 signing block
 */

/**
 * find all Id-Value Pair from Apk
 *
 * @param channelFile
 * @return
 */
fun getAllIdValueMap(channelFile: File?): Map<Int, ByteBuffer>? {
    if (channelFile == null || !channelFile.exists() || !channelFile.isFile) {
        return null
    }
    try {
        val apkSigningBlock: ByteBuffer = V2SchemeUtils.getApkSigningBlock(channelFile)!!
        return V2SchemeUtils.getAllIdValue(apkSigningBlock)
    } catch (e: IOException) {
        e.printStackTrace()
    } catch (e: SignatureNotFoundException) {
        println("Apk V2 Signing Block is not found in APK ${channelFile.absolutePath}")
    }
    return null
}

/**
 * get ByteBuffer value from apk by id
 *
 * @param channelFile
 * @param id
 * @return
 */
fun getByteBufferValueById(channelFile: File?, id: Int): ByteBuffer? {
    if (channelFile == null || !channelFile.exists() || !channelFile.isFile) {
        return null
    }
    val idValueMap = getAllIdValueMap(channelFile)
    println("getByteBufferValueById , destApk ${channelFile.absolutePath} IdValueMap = $idValueMap")
    return idValueMap?.get(id)
}

/**
 * get byte[] value from apk by id
 *
 * @param channelFile
 * @param id
 * @return
 */
fun getByteValueById(channelFile: File?, id: Int): ByteArray? {
    if (channelFile == null || !channelFile.exists() || !channelFile.isFile) {
        return null
    }
    val value = getByteBufferValueById(channelFile, id)
    println("getByteValueById , id = $id , value = $value")
    return if (value != null) {
        Arrays.copyOfRange(
            value.array(),
            value.arrayOffset() + value.position(),
            value.arrayOffset() + value.limit()
        )
    } else null
}

/**
 * get string value by id
 *
 * @param channelFile
 * @param id
 * @return
 */
fun getStringValueById(channelFile: File?, id: Int): String? {
    if (channelFile == null || !channelFile.exists() || !channelFile.isFile) {
        return null
    }
    val buffer = getByteValueById(channelFile, id)
    try {
        if (buffer != null && buffer.isNotEmpty()) {
            return String(buffer, CONTENT_CHAR_SET)
        }
    } catch (e: UnsupportedEncodingException) {
        e.printStackTrace()
    }
    return null
}
