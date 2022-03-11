package me.bytebeats.packer.base.verify

import me.bytebeats.packer.base.Pair
import me.bytebeats.packer.base.Pair.Companion.invoke
import me.bytebeats.packer.base.SignatureNotFoundException
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec


/**
 * Created by bytebeats on 2022/3/8 : 19:15
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */

/**
 * `.SF` file header section attribute indicating that the APK is signed not just with
 * JAR signature scheme but also with APK Signature Scheme v2 or newer. This attribute
 * facilitates v2 signature stripping detection.
 *
 *
 *
 * The attribute contains a comma-separated set of signature scheme IDs.
 */
const val SF_ATTRIBUTE_ANDROID_APK_SIGNED_NAME = "X-Android-APK-Signed"
const val SF_ATTRIBUTE_ANDROID_APK_SIGNED_ID = 2

/**
 * Returns {@code true} if the provided APK contains an APK Signature Scheme V2 signature.
 * <p>
 * <p><b>NOTE: This method does not verify the signature.</b>
 */
@Throws(IOException::class)
fun hasSignature(apkFile: String): Boolean {
    var apk: RandomAccessFile? = null
    return try {
        apk = RandomAccessFile(apkFile, "r")
        findSignature(apk)
        true
    } catch (e: SignatureNotFoundException) {
        false
    } finally {
        apk?.close()
    }
}

private const val CHUNK_SIZE_BYTES = 1024 * 1024

private const val SIGNATURE_RSA_PSS_WITH_SHA256 = 0x0101
private const val SIGNATURE_RSA_PSS_WITH_SHA512 = 0x0102
private const val SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256 = 0x0103
private const val SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512 = 0x0104
private const val SIGNATURE_ECDSA_WITH_SHA256 = 0x0201
private const val SIGNATURE_ECDSA_WITH_SHA512 = 0x0202
private const val SIGNATURE_DSA_WITH_SHA256 = 0x0301

private const val CONTENT_DIGEST_CHUNKED_SHA256 = 1
private const val CONTENT_DIGEST_CHUNKED_SHA512 = 2

const val APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L
const val APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L
private const val APK_SIG_BLOCK_MIN_SIZE = 32

const val APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a

/**
 * The padding in APK SIG BLOCK (V3 scheme introduced)
 * See https://android.googlesource.com/platform/tools/apksig/+/master/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java
 */
const val VERITY_PADDING_BLOCK_ID = 0x42726577

const val ANDROID_COMMON_PAGE_ALIGNMENT_BYTES = 4096

/**
 * APK Signature Scheme v2 block and additional information relevant to verifying the signatures
 * contained in the block against the file.
 * @param signatureBlock Contents of APK Signature Scheme v2 block. V2签名块中ID为APK_SIGNATURE_SCHEME_V2_BLOCK_ID的Value值，即具体的签名信息
 * @param apkSigningBlockOffset Position of the APK Signing Block in the file.
 * @param centralDirOffset Position of the ZIP Central Directory in the file.
 * @param eocdOffset Position of the ZIP End of Central Directory (EoCD) in the file.
 * @param eocd Contents of ZIP End of Central Directory (EoCD) of the file.
 */
private data class SignatureInfo(
    private val signatureBlock: ByteBuffer,
    private val apkSigningBlockOffset: Long,
    private val centralDirOffset: Long,
    private val eocdOffset: Long,
    private val eocd: ByteBuffer
)

/**
 * Returns the APK Signature Scheme v2 block contained in the provided APK file and the
 * additional information relevant for verifying the block against the file.
 *
 * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v2.
 * @throws IOException                if an I/O error occurs while reading the APK file.
 */
@Throws(IOException::class, SignatureNotFoundException::class)
private fun findSignature(apk: RandomAccessFile): SignatureInfo {
    // Find the ZIP End of Central Directory (EoCD) record.
    val eocdAndOffsetInFile = getEocd(apk)
    val eocd = eocdAndOffsetInFile.first
    val eocdOffset = eocdAndOffsetInFile.second
    if (isZip64EndOfCentralDirectoryLocatorPresent(apk, eocdOffset)) {
        throw SignatureNotFoundException("ZIP64 APK not supported")
    }

    // Find the APK Signing Block. The block immediately precedes the Central Directory.
    val centralDirOffset = getCentralDirOffset(eocd, eocdOffset) //通过eocd找到中央目录的偏移量
    val apkSigningBlockAndOffsetInFile = findApkSigningBlock(apk, centralDirOffset) //找到签名块的内容和偏移量
    val apkSigningBlock = apkSigningBlockAndOffsetInFile.first
    val apkSigningBlockOffset = apkSigningBlockAndOffsetInFile.second

    // Find the APK Signature Scheme v2 Block inside the APK Signing Block.
    val apkSignatureSchemeV2Block = findApkSignatureSchemeV2Block(apkSigningBlock)
    return SignatureInfo(
        apkSignatureSchemeV2Block,
        apkSigningBlockOffset,
        centralDirOffset,
        eocdOffset,
        eocd
    )
}

/**
 * Returns the ZIP End of Central Directory (EoCD) and its offset in the file.
 * 获取apk中的EOCD和对应的偏移量
 *
 * @throws IOException                if an I/O error occurs while reading the file.
 * @throws SignatureNotFoundException if the EoCD could not be found.
 */
@Throws(IOException::class, SignatureNotFoundException::class)
fun getEocd(apk: RandomAccessFile): Pair<ByteBuffer, Long> {
    return findZipEndOfCentralDirectoryRecord(apk)
        ?: throw SignatureNotFoundException(
            "Not an APK file: ZIP End of Central Directory record not found"
        )
}

@Throws(SignatureNotFoundException::class)
fun getCentralDirOffset(eocd: ByteBuffer, eocdOffset: Long): Long {
    // Look up the offset of ZIP Central Directory.
    val centralDirOffset: Long = getZipEocdCentralDirectoryOffset(eocd)
    if (centralDirOffset >= eocdOffset) {
        throw SignatureNotFoundException(
            "ZIP Central Directory offset out of range: $centralDirOffset. ZIP End of Central Directory offset: $eocdOffset"
        )
    }
    val centralDirSize: Long = getZipEocdCentralDirectorySizeBytes(eocd)
    if (centralDirOffset + centralDirSize != eocdOffset) {
        throw SignatureNotFoundException(
            "ZIP Central Directory is not immediately followed by End of Central Directory"
        )
    }
    return centralDirOffset
}

private fun getChunkCount(inputSizeBytes: Long): Long {
    return (inputSizeBytes + CHUNK_SIZE_BYTES - 1) / CHUNK_SIZE_BYTES
}

private fun isSupportedSignatureAlgorithm(sigAlgorithm: Int): Boolean {
    return when (sigAlgorithm) {
        SIGNATURE_RSA_PSS_WITH_SHA256, SIGNATURE_RSA_PSS_WITH_SHA512, SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256, SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512, SIGNATURE_ECDSA_WITH_SHA256, SIGNATURE_ECDSA_WITH_SHA512, SIGNATURE_DSA_WITH_SHA256 -> true
        else -> false
    }
}

private fun compareSignatureAlgorithm(sigAlgorithm1: Int, sigAlgorithm2: Int): Int {
    val digestAlgorithm1 = getSignatureAlgorithmContentDigestAlgorithm(sigAlgorithm1)
    val digestAlgorithm2 = getSignatureAlgorithmContentDigestAlgorithm(sigAlgorithm2)
    return compareContentDigestAlgorithm(digestAlgorithm1, digestAlgorithm2)
}

private fun compareContentDigestAlgorithm(digestAlgorithm1: Int, digestAlgorithm2: Int): Int {
    return when (digestAlgorithm1) {
        CONTENT_DIGEST_CHUNKED_SHA256 -> when (digestAlgorithm2) {
            CONTENT_DIGEST_CHUNKED_SHA256 -> 0
            CONTENT_DIGEST_CHUNKED_SHA512 -> -1
            else -> throw IllegalArgumentException(
                "Unknown digestAlgorithm2: $digestAlgorithm2"
            )
        }
        CONTENT_DIGEST_CHUNKED_SHA512 -> when (digestAlgorithm2) {
            CONTENT_DIGEST_CHUNKED_SHA256 -> 1
            CONTENT_DIGEST_CHUNKED_SHA512 -> 0
            else -> throw IllegalArgumentException(
                "Unknown digestAlgorithm2: $digestAlgorithm2"
            )
        }
        else -> throw IllegalArgumentException("Unknown digestAlgorithm1: $digestAlgorithm1")
    }
}

private fun getSignatureAlgorithmContentDigestAlgorithm(sigAlgorithm: Int): Int {
    return when (sigAlgorithm) {
        SIGNATURE_RSA_PSS_WITH_SHA256, SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256, SIGNATURE_ECDSA_WITH_SHA256, SIGNATURE_DSA_WITH_SHA256 -> CONTENT_DIGEST_CHUNKED_SHA256
        SIGNATURE_RSA_PSS_WITH_SHA512, SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512, SIGNATURE_ECDSA_WITH_SHA512 -> CONTENT_DIGEST_CHUNKED_SHA512
        else -> throw IllegalArgumentException(
            "Unknown signature algorithm: 0x"
                    + java.lang.Long.toHexString((sigAlgorithm and -0x1).toLong())
        )
    }
}

private fun getContentDigestAlgorithmJcaDigestAlgorithm(digestAlgorithm: Int): String {
    return when (digestAlgorithm) {
        CONTENT_DIGEST_CHUNKED_SHA256 -> "SHA-256"
        CONTENT_DIGEST_CHUNKED_SHA512 -> "SHA-512"
        else -> throw IllegalArgumentException(
            "Unknown content digest algorithm: $digestAlgorithm"
        )
    }
}

private fun getContentDigestAlgorithmOutputSizeBytes(digestAlgorithm: Int): Int {
    return when (digestAlgorithm) {
        CONTENT_DIGEST_CHUNKED_SHA256 -> 256 / 8
        CONTENT_DIGEST_CHUNKED_SHA512 -> 512 / 8
        else -> throw IllegalArgumentException(
            "Unknown content digest algorithm: $digestAlgorithm"
        )
    }
}

private fun getSignatureAlgorithmJcaKeyAlgorithm(sigAlgorithm: Int): String {
    return when (sigAlgorithm) {
        SIGNATURE_RSA_PSS_WITH_SHA256, SIGNATURE_RSA_PSS_WITH_SHA512, SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256, SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512 -> "RSA"
        SIGNATURE_ECDSA_WITH_SHA256, SIGNATURE_ECDSA_WITH_SHA512 -> "EC"
        SIGNATURE_DSA_WITH_SHA256 -> "DSA"
        else -> throw IllegalArgumentException(
            "Unknown signature algorithm: 0x"
                    + java.lang.Long.toHexString((sigAlgorithm and -0x1).toLong())
        )
    }
}

private fun getSignatureAlgorithmJcaSignatureAlgorithm(sigAlgorithm: Int): Pair<String, AlgorithmParameterSpec?> {
    return when (sigAlgorithm) {
        SIGNATURE_RSA_PSS_WITH_SHA256 -> invoke(
            "SHA256withRSA/PSS",
            PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 256 / 8, 1
            )
        )
        SIGNATURE_RSA_PSS_WITH_SHA512 -> invoke(
            "SHA512withRSA/PSS",
            PSSParameterSpec(
                "SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 512 / 8, 1
            )
        )
        SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256 -> invoke("SHA256withRSA", null)
        SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512 -> invoke("SHA512withRSA", null)
        SIGNATURE_ECDSA_WITH_SHA256 -> invoke("SHA256withECDSA", null)
        SIGNATURE_ECDSA_WITH_SHA512 -> invoke("SHA512withECDSA", null)
        SIGNATURE_DSA_WITH_SHA256 -> invoke("SHA256withDSA", null)
        else -> throw IllegalArgumentException(
            "Unknown signature algorithm: 0x"
                    + java.lang.Long.toHexString(sigAlgorithm.toLong() and 0xffffffff)
        )
    }
}


/**
 * Returns new byte buffer whose content is a shared subsequence of this buffer's content
 * between the specified start (inclusive) and end (exclusive) positions. As opposed to
 * [ByteBuffer.slice], the returned buffer's byte order is the same as the source
 * buffer's byte order.
 */
fun sliceFromTo(source: ByteBuffer, start: Int, end: Int): ByteBuffer {
    require(start >= 0) { "start: $start" }
    require(end >= start) { "end < start: $end < $start" }
    val capacity = source.capacity()
    require(end <= source.capacity()) { "end > capacity: $end > $capacity" }
    val originalLimit = source.limit()
    val originalPosition = source.position()
    return try {
        source.position(0)
        source.limit(end)
        source.position(start)
        val result = source.slice()
        result.order(source.order())
        result
    } finally {
        source.position(0)
        source.limit(originalLimit)
        source.position(originalPosition)
    }
}

/**
 * Relative *get* method for reading `size` number of bytes from the current
 * position of this buffer.
 *
 *
 *
 * This method reads the next `size` bytes at this buffer's current position,
 * returning them as a `ByteBuffer` with start set to 0, limit and capacity set to
 * `size`, byte order set to this buffer's byte order; and then increments the position by
 * `size`.
 */
@Throws(BufferUnderflowException::class)
fun getByteBuffer(source: ByteBuffer, size: Int): ByteBuffer {
    require(size >= 0) { "size: $size" }
    val originalLimit = source.limit()
    val position = source.position()
    val limit = position + size
    if (limit < position || limit > originalLimit) {
        throw BufferUnderflowException()
    }
    source.limit(limit)
    return try {
        val result = source.slice()
        result.order(source.order())
        source.position(limit)
        result
    } finally {
        source.limit(originalLimit)
    }
}

@Throws(IOException::class)
private fun getLengthPrefixedSlice(source: ByteBuffer): ByteBuffer {
    if (source.remaining() < 4) {
        throw IOException(
            "Remaining buffer too short to contain length of length-prefixed field.Remaining: ${source.remaining()}"
        )
    }
    val len = source.int
    if (len < 0) {
        throw IllegalArgumentException("Negative length")
    } else if (len > source.remaining()) {
        throw IOException("Length-prefixed field longer than remaining buffer. Field length: $len, remaining: ${source.remaining()}")
    }
    return getByteBuffer(source, len)
}

@Throws(IOException::class)
private fun readLengthPrefixedByteArray(buf: ByteBuffer): ByteArray {
    val len = buf.int
    if (len < 0) {
        throw IOException("Negative length")
    } else if (len > buf.remaining()) {
        throw IOException(
            "Underflow while reading length-prefixed value. Length: $len, available: ${buf.remaining()}"
        )
    }
    val result = ByteArray(len)
    buf[result]
    return result
}

private fun setUnsignedInt32LittleEndian(value: Int, result: ByteArray, offset: Int) {
    result[offset] = (value and 0xff).toByte()
    result[offset + 1] = (value ushr 8 and 0xff).toByte()
    result[offset + 2] = (value ushr 16 and 0xff).toByte()
    result[offset + 3] = (value ushr 24 and 0xff).toByte()
}

@Throws(IOException::class, SignatureNotFoundException::class)
fun findApkSigningBlock(
    apk: RandomAccessFile, centralDirOffset: Long
): Pair<ByteBuffer, Long> {
    // FORMAT:
    // OFFSET       DATA TYPE  DESCRIPTION
    // * @+0  bytes uint64:    size in bytes (excluding this field)
    // * @+8  bytes payload
    // * @-24 bytes uint64:    size in bytes (same as the one above)
    // * @-16 bytes uint128:   magic
    if (centralDirOffset < APK_SIG_BLOCK_MIN_SIZE) {
        throw SignatureNotFoundException(
            "APK too small for APK Signing Block. ZIP Central Directory offset: $centralDirOffset"
        )
    }
    // Read the magic and offset in file from the footer section of the block:
    // * uint64:   size of block
    // * 16 bytes: magic
    val footer = ByteBuffer.allocate(24)
    footer.order(ByteOrder.LITTLE_ENDIAN)
    apk.seek(centralDirOffset - footer.capacity())
    apk.readFully(footer.array(), footer.arrayOffset(), footer.capacity())
    if (footer.getLong(8) != APK_SIG_BLOCK_MAGIC_LO || footer.getLong(16) != APK_SIG_BLOCK_MAGIC_HI) {
        throw SignatureNotFoundException(
            "No APK Signing Block before ZIP Central Directory"
        )
    }
    // Read and compare size fields
    val apkSigBlockSizeInFooter = footer.getLong(0)
    if (apkSigBlockSizeInFooter < footer.capacity() || apkSigBlockSizeInFooter > Int.MAX_VALUE - 8) {
        throw SignatureNotFoundException(
            "APK Signing Block size out of range: $apkSigBlockSizeInFooter"
        )
    }
    val totalSize = (apkSigBlockSizeInFooter + 8).toInt()
    val apkSigBlockOffset = centralDirOffset - totalSize
    if (apkSigBlockOffset < 0) {
        throw SignatureNotFoundException(
            "APK Signing Block offset out of range: $apkSigBlockOffset"
        )
    }
    val apkSigBlock = ByteBuffer.allocate(totalSize)
    apkSigBlock.order(ByteOrder.LITTLE_ENDIAN)
    apk.seek(apkSigBlockOffset)
    apk.readFully(apkSigBlock.array(), apkSigBlock.arrayOffset(), apkSigBlock.capacity())
    val apkSigBlockSizeInHeader = apkSigBlock.getLong(0)
    if (apkSigBlockSizeInHeader != apkSigBlockSizeInFooter) {
        throw SignatureNotFoundException(
            "APK Signing Block sizes in header and footer do not match: $apkSigBlockSizeInHeader vs $apkSigBlockSizeInFooter"
        )
    }
    return invoke(apkSigBlock, apkSigBlockOffset)
}

/**
 * get the v2 schema block from apk signing block
 *
 * @param apkSigningBlock
 * @return
 * @throws SignatureNotFoundException
 */
@Throws(SignatureNotFoundException::class)
private fun findApkSignatureSchemeV2Block(apkSigningBlock: ByteBuffer): ByteBuffer {
    checkByteOrderLittleEndian(apkSigningBlock)
    // FORMAT:
    // OFFSET       DATA TYPE  DESCRIPTION
    // * @+0  bytes uint64:    size in bytes (excluding this field)
    // * @+8  bytes pairs
    // * @-24 bytes uint64:    size in bytes (same as the one above)
    // * @-16 bytes uint128:   magic
    val pairs: ByteBuffer = sliceFromTo(apkSigningBlock, 8, apkSigningBlock.capacity() - 24)
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
        if (id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID) {
            return getByteBuffer(pairs, len - 4)
        }
        pairs.position(nextEntryPos)
    }
    throw SignatureNotFoundException(
        "No APK Signature Scheme v2 block in APK Signing Block"
    )
}

fun checkByteOrderLittleEndian(buffer: ByteBuffer) {
    require(buffer.order() == ByteOrder.LITTLE_ENDIAN) { "ByteBuffer byte order must be little endian" }
}