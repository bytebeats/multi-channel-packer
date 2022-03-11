package me.bytebeats.packer.writer

import me.bytebeats.packer.base.ApkSectionInfo
import me.bytebeats.packer.base.CHANNEL_BLOCK_ID
import me.bytebeats.packer.base.CONTENT_CHAR_SET
import me.bytebeats.packer.base.SignatureNotFoundException
import me.bytebeats.packer.base.V1SchemeUtils
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder


/**
 * Created by bytebeats on 2022/3/11 : 21:11
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */

/**
 * add channel to apk in the v2 signature mode
 *
 * @param apkSectionInfo
 * @param destApk
 * @param channel
 * @throws IOException
 * @throws SignatureNotFoundException
 */
@Throws(IOException::class, SignatureNotFoundException::class)
fun addChannelByV2(apkSectionInfo: ApkSectionInfo, destApk: File?, channel: String?) {
    if (destApk == null || channel == null || channel.isEmpty()) {
        throw RuntimeException("addChannelByV2 , param invalid, channel = $channel , destApk = $destApk")
    }
    if (apkSectionInfo.lowMemory) {
        if (!destApk.exists() || !destApk.isFile || destApk.length() <= 0) {
            throw RuntimeException("addChannelByV2 , destApk invalid in the lowMemory mode")
        }
    } else {
        if (destApk.parentFile?.exists() != true) {
            destApk.parentFile?.mkdirs()
        }
    }
    val buffer: ByteArray = channel.toByteArray(CONTENT_CHAR_SET)
    val channelByteBuffer = ByteBuffer.wrap(buffer)
    //apk中所有字节都是小端模式
    channelByteBuffer.order(ByteOrder.LITTLE_ENDIAN)
    addIdValue(
        apkSectionInfo,
        destApk,
        CHANNEL_BLOCK_ID.toInt(),
        channelByteBuffer
    )
}

/**
 * add channel to apk in the v2 signature mode
 *
 * @param apkFile
 * @param channel
 * @throws IOException
 * @throws SignatureNotFoundException
 */
@Throws(IOException::class, SignatureNotFoundException::class)
fun addChannelByV2(apkFile: File, channel: String?, lowMemory: Boolean) {
    addChannelByV2(apkFile, apkFile, channel, lowMemory)
}

/**
 * add channel to apk in the v2 signature mode
 *
 * @param srcApk  source apk
 * @param destApk dest apk
 * @param channel channel info
 * @throws IOException
 * @throws SignatureNotFoundException
 */
@Throws(IOException::class, SignatureNotFoundException::class)
fun addChannelByV2(srcApk: File, destApk: File, channel: String?, lowMemory: Boolean) {
    val apkSectionInfo: ApkSectionInfo = requireNotNull(getApkSectionInfo(srcApk, lowMemory)) {
        "ApkSectionInfo can't be null"
    }
    addChannelByV2(apkSectionInfo, destApk, channel)
}

/**
 * add channel to apk in the v1 signature mode . if you use v1 signature , not necessary to again to signature after add channel info
 *
 * @param srcApk
 * @param destApk
 * @param channel
 * @throws Exception
 */
@Throws(Exception::class)
fun addChannelByV1(srcApk: File, destApk: File, channel: String?) {
    V1SchemeUtils.copyFile(srcApk, destApk)
    addChannelByV1(destApk, channel)
}

/**
 * add channel to apk in the v1 signature mode . if you use v1 signature , not necessary to again to signature after add channel info
 *
 * @param apkFile
 * @param channel
 * @throws Exception
 */
@Throws(Exception::class)
fun addChannelByV1(apkFile: File, channel: String?) {
    V1SchemeUtils.writeChannel(apkFile, channel)
}

/**
 * remove channel from apk in the v2 signature mode
 *
 * @param destApk
 * @param lowMemory
 * @throws IOException
 * @throws SignatureNotFoundException
 */
@Throws(IOException::class, SignatureNotFoundException::class)
fun removeChannelByV2(destApk: File, lowMemory: Boolean) {
    if (!destApk.isFile || !destApk.exists()) {
        return
    }
    val apkSectionInfo = getApkSectionInfo(destApk, lowMemory)
    val idList: MutableList<Int> = ArrayList()
    idList.add(CHANNEL_BLOCK_ID.toInt())
    removeIdValue(apkSectionInfo, destApk, idList)
    apkSectionInfo?.checkParameters()
}

/**
 * remove channel from apk in the v1 signature mode
 */
@Throws(Exception::class)
fun removeChannelByV1(destApk: File) {
    V1SchemeUtils.removeChannelByV1(destApk)
}

