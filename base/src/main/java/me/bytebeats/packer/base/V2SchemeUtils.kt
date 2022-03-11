package me.bytebeats.packer.base

import me.bytebeats.packer.base.Pair.Companion.invoke
import me.bytebeats.packer.base.verify.ANDROID_COMMON_PAGE_ALIGNMENT_BYTES
import me.bytebeats.packer.base.verify.APK_SIGNATURE_SCHEME_V2_BLOCK_ID
import me.bytebeats.packer.base.verify.APK_SIG_BLOCK_MAGIC_HI
import me.bytebeats.packer.base.verify.APK_SIG_BLOCK_MAGIC_LO
import me.bytebeats.packer.base.verify.VERITY_PADDING_BLOCK_ID
import me.bytebeats.packer.base.verify.checkByteOrderLittleEndian
import me.bytebeats.packer.base.verify.findApkSigningBlock
import me.bytebeats.packer.base.verify.getByteBuffer
import me.bytebeats.packer.base.verify.getCentralDirOffset
import me.bytebeats.packer.base.verify.getEocd
import me.bytebeats.packer.base.verify.hasSignature
import me.bytebeats.packer.base.verify.isZip64EndOfCentralDirectoryLocatorPresent
import me.bytebeats.packer.base.verify.sliceFromTo
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder


/**
 * Created by bytebeats on 2022/3/11 : 19:16
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */
object V2SchemeUtils {
    /**
     * find all Id-Value Pair from ApkSignatureBlock
     * 参考ApkSignatureSchemeV2Verifier.findApkSignatureSchemeV2Block()方法
     *
     * @param apkSigningBlock
     * @return
     * @throws SignatureNotFoundException
     */
    @Throws(SignatureNotFoundException::class)
    fun getAllIdValue(apkSigningBlock: ByteBuffer): Map<Int, ByteBuffer> {
        checkByteOrderLittleEndian(apkSigningBlock)
        // FORMAT:
        // OFFSET       DATA TYPE  DESCRIPTION
        // * @+0  bytes uint64:    size in bytes (excluding this field)
        // * @+8  bytes pairs
        // * @-24 bytes uint64:    size in bytes (same as the one above)
        // * @-16 bytes uint128:   magic
        val pairs: ByteBuffer = sliceFromTo(
            apkSigningBlock,
            8,
            apkSigningBlock.capacity() - 24
        )
        val idValues: MutableMap<Int, ByteBuffer> = LinkedHashMap() // keep order
        var entryCount = 0
        while (pairs.hasRemaining()) {
            entryCount++
            if (pairs.remaining() < 8) {
                throw SignatureNotFoundException(
                    "Insufficient data to read size of APK Signing Block entry #$entryCount"
                )
            }
            val lenLong = pairs.long
            if (lenLong < 4 || lenLong > Int.MAX_VALUE) {
                throw SignatureNotFoundException(
                    "APK Signing Block entry #$entryCount size out of range: $lenLong"
                )
            }
            val len = lenLong.toInt()
            val nextEntryPos = pairs.position() + len
            if (len > pairs.remaining()) {
                throw SignatureNotFoundException(
                    "APK Signing Block entry #$entryCount size out of range: $len, available: ${pairs.remaining()}"
                )
            }
            val id = pairs.int
            idValues[id] = getByteBuffer(pairs, len - 4) //4 is length of id
            if (id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID) {
                println("find V2 signature block Id : $APK_SIGNATURE_SCHEME_V2_BLOCK_ID")
            }
            pairs.position(nextEntryPos)
        }
        if (idValues.isEmpty()) {
            throw SignatureNotFoundException(
                "Id-Value Pair Not found in APK Signing Block entry #$entryCount"
            )
        }
        return idValues
    }

    /**
     * get apk signature block from apk
     *
     * @param apkFile
     * @return
     * @throws IOException
     * @throws SignatureNotFoundException
     */
    @Throws(SignatureNotFoundException::class, IOException::class)
    fun getApkSigningBlock(apkFile: File?): ByteBuffer? {
        if (apkFile == null || !apkFile.exists() || !apkFile.isFile) {
            return null
        }
        var apk: RandomAccessFile? = null
        return try {
            apk = RandomAccessFile(apkFile, "r")
            //1.find the EOCD
            val (eocd, eocdOffset) = getEocd(apk)
            if (isZip64EndOfCentralDirectoryLocatorPresent(apk, eocdOffset)) {
                throw SignatureNotFoundException("ZIP64 APK not supported")
            }
            //2.find the APK Signing Block. The block immediately precedes the Central Directory.
            val centralDirOffset = getCentralDirOffset(eocd, eocdOffset) //通过eocd找到中央目录的偏移量
            //3. find the apk V2 signature block
            val apkSigningBlock = findApkSigningBlock(apk, centralDirOffset) //找到V2签名块的内容和偏移量
            apkSigningBlock.first
        } finally {
            apk?.close()
        }
    }

    /**
     * get the all Apk Section info from apk which is signed by v2
     *
     * @param baseApk
     * @return
     * @throws IOException
     * @throws SignatureNotFoundException not have v2 signed
     */
    @Throws(IOException::class, SignatureNotFoundException::class)
    fun getApkSectionInfo(baseApk: File, lowMemory: Boolean): ApkSectionInfo {
        var apk: RandomAccessFile? = null
        return try {
            apk = RandomAccessFile(baseApk, "r")
            //1.find the EOCD and offset
            val eocdAndOffsetInFile = getEocd(apk)
            val eocd = eocdAndOffsetInFile.first
            val eocdOffset = eocdAndOffsetInFile.second
            if (isZip64EndOfCentralDirectoryLocatorPresent(apk, eocdOffset)) {
                throw SignatureNotFoundException("ZIP64 APK not supported")
            }

            //2.find the APK Signing Block. The block immediately precedes the Central Directory.
            val centralDirOffset: Long = getCentralDirOffset(eocd, eocdOffset) //通过eocd找到中央目录的偏移量
            val apkSchemeV2Block = findApkSigningBlock(apk, centralDirOffset) //找到V2签名块的内容和偏移量

            //3.find the centralDir
            val centralDir =
                findCentralDir(apk, centralDirOffset, (eocdOffset - centralDirOffset).toInt())
            //4.find the contentEntry
            val contentEntry = if (!lowMemory) {
                findContentEntry(apk, apkSchemeV2Block.second.toInt())
            } else null

            val apkSectionInfo = ApkSectionInfo(
                lowMemory = lowMemory,
                apkSize = baseApk.length(),
                contentEntry = contentEntry,
                schemeV2Block = apkSchemeV2Block,
                centralDir = centralDir,
                eocd = eocdAndOffsetInFile
            )
            //5. check Parameters
            apkSectionInfo.checkParameters()
            println("baseApk : ${baseApk.absolutePath} ApkSectionInfo = $apkSectionInfo")
            apkSectionInfo
        } finally {
            apk?.close()
        }
    }

    /**
     * get the CentralDir of apk
     *
     * @param baseApk
     * @param centralDirOffset
     * @param length
     * @return
     * @throws IOException
     */
    @Throws(IOException::class)
    fun findCentralDir(
        baseApk: RandomAccessFile,
        centralDirOffset: Long,
        length: Int
    ): Pair<ByteBuffer, Long> {
        val byteBuffer = getByteBuffer(baseApk, centralDirOffset, length)
        return invoke(byteBuffer, centralDirOffset)
    }

    /**
     * get the ContentEntry of apk
     *
     * @param baseApk
     * @param length
     * @return
     * @throws IOException
     */
    @Throws(IOException::class)
    fun findContentEntry(baseApk: RandomAccessFile, length: Int): Pair<ByteBuffer, Long> {
        val byteBuffer = getByteBuffer(baseApk, 0, length)
        return invoke(byteBuffer, 0L)
    }

    @Throws(IOException::class)
    private fun getByteBuffer(baseApk: RandomAccessFile, offset: Long, length: Int): ByteBuffer {
        val byteBuffer = ByteBuffer.allocate(length)
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN)
        baseApk.seek(offset)
        baseApk.readFully(byteBuffer.array(), byteBuffer.arrayOffset(), byteBuffer.capacity())
        return byteBuffer
    }

    /**
     * generate the new ApkSigningBlock(contain v2 schema block)
     * reference ApkSignerV2.generateApkSigningBlock
     *
     * @param idValueMap
     * @return
     */
    @Throws(RuntimeException::class)
    fun generateApkSigningBlock(idValueMap: MutableMap<Int, ByteBuffer>?): ByteBuffer {
        if (idValueMap == null || idValueMap.isEmpty()) {
            throw RuntimeException("getNewApkV2SchemeBlock , id value pair is empty")
        }

        // FORMAT:
        // uint64:  size (excluding this field)
        // repeated ID-value pairs:
        //     uint64:           size (excluding this field)
        //     uint32:           ID
        //     (size - 4) bytes: value
        // uint64:  size (same as the one above)
        // uint128: magic

        //length is size (excluding this field) , 24 = 16 byte (magic) + 8 byte (length of the signing block excluding first 8 byte)
        var length: Long = 16 + 8
        for ((_, byteBuffer) in idValueMap) {
            length += (8 + 4 + byteBuffer.remaining()).toLong()
        }

        // If there has padding block, it needs to be update.
        val needPadding = idValueMap.containsKey(VERITY_PADDING_BLOCK_ID)
        println("generateApkSigningBlock , needPadding = $needPadding")
        if (needPadding) {
            val paddingBlockSize = 8 + 4 + idValueMap[VERITY_PADDING_BLOCK_ID]!!.remaining()
            // update length of apk signing block
            length -= paddingBlockSize.toLong()
            idValueMap.remove(VERITY_PADDING_BLOCK_ID)
            val remainder = ((length + 8) % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES).toInt()
            if (remainder != 0) {
                // Calculate the number of bytes that need to be filled
                var padding: Int = ANDROID_COMMON_PAGE_ALIGNMENT_BYTES - remainder
                // padding size must not be less than 8 + 4 bytes.
                if (padding < 8 + 4) {
                    padding += ANDROID_COMMON_PAGE_ALIGNMENT_BYTES
                }
                // update length of apk signing block
                length += padding.toLong()
                // Calculate the buffer size of padding block
                //8 is the size of padding block, 4 is the id of padding block.
                val bufferSize = padding - 8 - 4
                val dummy = ByteBuffer.allocate(bufferSize).order(ByteOrder.LITTLE_ENDIAN)
                idValueMap[VERITY_PADDING_BLOCK_ID] = dummy
                println("generateApkSigningBlock , final length = $length padding = $padding bufferSize = $bufferSize")
            }
        }
        val apkV2SigningBlock = ByteBuffer.allocate((length + 8).toInt())
        apkV2SigningBlock.order(ByteOrder.LITTLE_ENDIAN)
        //1.write size (excluding this field)
        apkV2SigningBlock.putLong(length)
        for ((key, byteBuffer) in idValueMap) {
            //2.1 write length of id-value
            apkV2SigningBlock.putLong((byteBuffer.remaining() + 4).toLong()) //4 is length of id
            //2.2 write id
            apkV2SigningBlock.putInt(key)
            //2.3 write value
            apkV2SigningBlock.put(
                byteBuffer.array(),
                byteBuffer.arrayOffset() + byteBuffer.position(),
                byteBuffer.remaining()
            )
        }
        apkV2SigningBlock.putLong(length) //3.write size (same as the one above)
        apkV2SigningBlock.putLong(APK_SIG_BLOCK_MAGIC_LO) //4. write magic
        apkV2SigningBlock.putLong(APK_SIG_BLOCK_MAGIC_HI) //4. write magic
        if (apkV2SigningBlock.remaining() > 0) {
            throw RuntimeException("generateNewApkV2SchemeBlock error")
        }
        apkV2SigningBlock.flip()
        return apkV2SigningBlock
    }

    /**
     * Returns `true` if the provided APK contains an APK Signature Scheme V2 signature.
     *
     * NOTE: This method does not verify the signature.
     *
     * @param apkPath
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    fun hasV2SchemeSignature(apkPath: String): Boolean {
        return hasSignature(apkPath)
    }

    /**
     * judge whether apk contain v2 signature block
     *
     * @param apk
     * @return
     */
    fun containV2Signature(apk: File): Boolean {
        try {
            val apkSigningBlock = getApkSigningBlock(apk)
            val idValueMap = getAllIdValue(apkSigningBlock!!)
            return idValueMap.containsKey(APK_SIGNATURE_SCHEME_V2_BLOCK_ID)
        } catch (e: IOException) {
            e.printStackTrace()
        } catch (e: SignatureNotFoundException) {
            println("Apk V2 Signing block is not found in APK: ${apk.absolutePath}")
        }
        return false
    }

}