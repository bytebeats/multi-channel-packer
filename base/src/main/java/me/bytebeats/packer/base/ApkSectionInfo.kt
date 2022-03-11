package me.bytebeats.packer.base

import me.bytebeats.packer.base.verify.getCentralDirOffset
import java.nio.ByteBuffer

/**
 * Created by bytebeats on 2022/3/11 : 17:02
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */
data class ApkSectionInfo(
    val lowMemory: Boolean = false,
    val apkSize: Long = 0L,
    val contentEntry: Pair<ByteBuffer, Long>? = null,
    val schemeV2Block: Pair<ByteBuffer, Long>? = null,
    val centralDir: Pair<ByteBuffer, Long>? = null,
    val eocd: Pair<ByteBuffer, Long>? = null,
) {

    @Throws(SignatureNotFoundException::class)
    fun checkParameters() {
        if (!lowMemory && contentEntry == null || schemeV2Block == null || centralDir == null || eocd == null) {
            throw RuntimeException("ApkSectionInfo parameters is not valid : " + toString())
        }

        val result =
            (if (lowMemory) true else contentEntry!!.second == 0L && contentEntry.first.remaining() + contentEntry.second == schemeV2Block.second)
                    && schemeV2Block.first.remaining() + schemeV2Block.second == centralDir.second
                    && centralDir.first.remaining() + centralDir.second == eocd.second
                    && eocd.first.remaining() + eocd.second == apkSize

        if (!result) {
            throw RuntimeException("ApkSectionInfo parameters is not valid : " + toString())
        }
        checkEocdCentralDirOffset()
    }

    @Throws(SignatureNotFoundException::class)
    fun checkEocdCentralDirOffset() {
        //通过eocd找到中央目录的偏移量
        val centralDirOffset = getCentralDirOffset(eocd!!.first, eocd.second)
        if (centralDirOffset != centralDir!!.second) {
            throw RuntimeException("CentralDirOffset mismatch , EocdCentralDirOffset : $centralDirOffset, centralDirOffset : ${centralDir.second}")
        }
    }

    fun rewind() {
        contentEntry?.first?.rewind()
        schemeV2Block?.first?.rewind()
        centralDir?.first?.rewind()
        eocd?.first?.rewind()
    }

    override fun toString(): String {
        return "ApkSectionInfo(lowMemory=$lowMemory, contentEntry=$contentEntry, schemeV2Block=$schemeV2Block, centralDir=$centralDir, eocd=$eocd)"
    }
}
