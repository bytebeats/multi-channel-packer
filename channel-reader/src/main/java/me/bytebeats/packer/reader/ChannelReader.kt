package me.bytebeats.packer.reader

import me.bytebeats.packer.base.CHANNEL_BLOCK_ID
import me.bytebeats.packer.base.V1SchemeUtils
import me.bytebeats.packer.base.V2SchemeUtils
import java.io.File


/**
 * Created by bytebeats on 2022/3/11 : 20:27
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */

/**
 * judge whether apk contain v1 signature
 *
 * @param file
 * @return
 */
fun containV1Signature(file: File?): Boolean =
    if (file == null || !file.exists() || !file.isFile) false
    else V1SchemeUtils.containV1Signature(file)

/**
 * judge whether apk contain v2 signature block
 *
 * @param file
 * @return
 */
fun containV2Signature(file: File?): Boolean =
    if (file == null || !file.exists() || !file.isFile) false
    else V2SchemeUtils.containV2Signature(file)

/**
 * verify channel info in the v2 signature mode
 *
 * @param file
 * @param channel
 * @return
 */
fun verifyChannelByV2(file: File, channel: String): Boolean {
    return channel == getChannelByV2(file)
}

/**
 * verify channel info in the v1 signature mode
 *
 * @param file
 * @param channel
 * @return
 */
fun verifyChannelByV1(file: File, channel: String): Boolean {
    return channel == getChannelByV1(file)
}

/**
 * get channel value from apk in the v2 signature mode
 *
 * @param channelFile
 * @return
 */
fun getChannelByV2(channelFile: File): String? {
    println("try to read channel info from apk : " + channelFile.absolutePath)
    return getStringValueById(channelFile, CHANNEL_BLOCK_ID.toInt())
}

/**
 * get channel info from apk in the v1 signature mode
 *
 * @param channelFile
 * @return
 * @throws Exception
 */
fun getChannelByV1(channelFile: File): String? {
    try {
        return V1SchemeUtils.readChannel(channelFile)
    } catch (e: Exception) {
        println("APK : " + channelFile.absolutePath + " not have channel info from Zip Comment")
    }
    return null
}
