package me.bytebeats.packer.base.verify

import me.bytebeats.packer.base.Pair
import me.bytebeats.packer.base.Pair.Companion.invoke
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder


/**
 * Created by bytebeats on 2022/3/11 : 16:12
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */

/**
 * Assorted ZIP format helpers.
 *
 * <p>NOTE: Most helper methods operating on {@code ByteBuffer} instances expect that the byte
 * order of these buffers is little-endian.
 */

val ZIP_EOCD_REC_MIN_SIZE: Int = 22
private const val ZIP_EOCD_REC_SIG = 0x06054b50
private const val ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET = 12
private const val ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET = 16
private const val ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET = 20

private const val ZIP64_EOCD_LOCATOR_SIZE = 20
private const val ZIP64_EOCD_LOCATOR_SIG_REVERSE_BYTE_ORDER = 0x504b0607

private const val UINT16_MAX_VALUE = 0xffff


/**
 * Returns the ZIP End of Central Directory record of the provided ZIP file.
 *
 * @return contents of the ZIP End of Central Directory record and the record's offset in the
 * file or `null` if the file does not contain the record.
 *
 * @throws IOException if an I/O error occurs while reading the file.
 */
@Throws(IOException::class)
fun findZipEndOfCentralDirectoryRecord(zip: RandomAccessFile): Pair<ByteBuffer, Long>? {
    // ZIP End of Central Directory (EOCD) record is located at the very end of the ZIP archive.
    // The record can be identified by its 4-byte signature/magic which is located at the very
    // beginning of the record. A complication is that the record is variable-length because of
    // the comment field.
    // The algorithm for locating the ZIP EOCD record is as follows. We search backwards from
    // end of the buffer for the EOCD record signature. Whenever we find a signature, we check
    // the candidate record's comment length is such that the remainder of the record takes up
    // exactly the remaining bytes in the buffer. The search is bounded because the maximum
    // size of the comment field is 65535 bytes because the field is an unsigned 16-bit number.
    val fileSize = zip.length()
    if (fileSize < ZIP_EOCD_REC_MIN_SIZE) {
        return null
    }

    // Optimization: 99.99% of APKs have a zero-length comment field in the EoCD record and thus
    // the EoCD record offset is known in advance. Try that offset first to avoid unnecessarily
    // reading more data.
    val result = findZipEndOfCentralDirectoryRecord(zip, 0)
    // EoCD does not start where we expected it to. Perhaps it contains a non-empty comment
    // field. Expand the search. The maximum size of the comment field in EoCD is 65535 because
    // the comment length field is an unsigned 16-bit number.
    return result ?: findZipEndOfCentralDirectoryRecord(zip, UINT16_MAX_VALUE)

}

/**
 * Returns the ZIP End of Central Directory record of the provided ZIP file.
 *
 * @param maxCommentSize maximum accepted size (in bytes) of EoCD comment field. The permitted
 * value is from 0 to 65535 inclusive. The smaller the value, the faster this method
 * locates the record, provided its comment field is no longer than this value.
 *
 * @return contents of the ZIP End of Central Directory record and the record's offset in the
 * file or `null` if the file does not contain the record.
 *
 * @throws IOException if an I/O error occurs while reading the file.
 */
@Throws(IOException::class)
private fun findZipEndOfCentralDirectoryRecord(
    zip: RandomAccessFile,
    maxCommentSize: Int
): Pair<ByteBuffer, Long>? {
    // ZIP End of Central Directory (EOCD) record is located at the very end of the ZIP archive.
    // The record can be identified by its 4-byte signature/magic which is located at the very
    // beginning of the record. A complication is that the record is variable-length because of
    // the comment field.
    // The algorithm for locating the ZIP EOCD record is as follows. We search backwards from
    // end of the buffer for the EOCD record signature. Whenever we find a signature, we check
    // the candidate record's comment length is such that the remainder of the record takes up
    // exactly the remaining bytes in the buffer. The search is bounded because the maximum
    // size of the comment field is 65535 bytes because the field is an unsigned 16-bit number.
    var maxCommentSize = maxCommentSize
    require(!(maxCommentSize < 0 || maxCommentSize > UINT16_MAX_VALUE)) { "maxCommentSize: $maxCommentSize" }
    val fileSize = zip.length()
    if (fileSize < ZIP_EOCD_REC_MIN_SIZE) {
        // No space for EoCD record in the file.
        return null
    }
    // Lower maxCommentSize if the file is too small.
    maxCommentSize = Math.min(maxCommentSize.toLong(), fileSize - ZIP_EOCD_REC_MIN_SIZE).toInt()
    val buf = ByteBuffer.allocate(ZIP_EOCD_REC_MIN_SIZE + maxCommentSize)
    buf.order(ByteOrder.LITTLE_ENDIAN)
    val bufOffsetInFile = fileSize - buf.capacity()
    zip.seek(bufOffsetInFile)
    zip.readFully(buf.array(), buf.arrayOffset(), buf.capacity())
    val eocdOffsetInBuf: Int = findZipEndOfCentralDirectoryRecord(buf)
    if (eocdOffsetInBuf == -1) {
        // No EoCD record found in the buffer
        return null
    }
    // EoCD found
    buf.position(eocdOffsetInBuf)
    val eocd = buf.slice()
    eocd.order(ByteOrder.LITTLE_ENDIAN)
    return invoke(eocd, bufOffsetInFile + eocdOffsetInBuf)
}

/**
 * Returns the position at which ZIP End of Central Directory record starts in the provided
 * buffer or `-1` if the record is not present.
 *
 *
 * NOTE: Byte order of `zipContents` must be little-endian.
 */
private fun findZipEndOfCentralDirectoryRecord(zipContents: ByteBuffer): Int {
    assertByteOrderLittleEndian(zipContents)

    // ZIP End of Central Directory (EOCD) record is located at the very end of the ZIP archive.
    // The record can be identified by its 4-byte signature/magic which is located at the very
    // beginning of the record. A complication is that the record is variable-length because of
    // the comment field.
    // The algorithm for locating the ZIP EOCD record is as follows. We search backwards from
    // end of the buffer for the EOCD record signature. Whenever we find a signature, we check
    // the candidate record's comment length is such that the remainder of the record takes up
    // exactly the remaining bytes in the buffer. The search is bounded because the maximum
    // size of the comment field is 65535 bytes because the field is an unsigned 16-bit number.
    val archiveSize = zipContents.capacity()
    if (archiveSize < ZIP_EOCD_REC_MIN_SIZE) {
        return -1
    }
    val maxCommentLength = Math.min(archiveSize - ZIP_EOCD_REC_MIN_SIZE, UINT16_MAX_VALUE)
    val eocdWithEmptyCommentStartPosition = archiveSize - ZIP_EOCD_REC_MIN_SIZE
    for (expectedCommentLength in 0..maxCommentLength) {
        val eocdStartPos = eocdWithEmptyCommentStartPosition - expectedCommentLength
        if (zipContents.getInt(eocdStartPos) == ZIP_EOCD_REC_SIG) {
            val actualCommentLength: Int = getUnsignedInt16(
                zipContents, eocdStartPos + ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET
            )
            if (actualCommentLength == expectedCommentLength) {
                return eocdStartPos
            }
        }
    }
    return -1
}

/**
 * Returns `true` if the provided file contains a ZIP64 End of Central Directory
 * Locator.
 *
 * @param zipEndOfCentralDirectoryPosition offset of the ZIP End of Central Directory record
 * in the file.
 *
 * @throws IOException if an I/O error occurs while reading the file.
 */
@Throws(IOException::class)
fun isZip64EndOfCentralDirectoryLocatorPresent(
    zip: RandomAccessFile,
    zipEndOfCentralDirectoryPosition: Long
): Boolean {

    // ZIP64 End of Central Directory Locator immediately precedes the ZIP End of Central
    // Directory Record.
    val locatorPosition = zipEndOfCentralDirectoryPosition - ZIP64_EOCD_LOCATOR_SIZE
    if (locatorPosition < 0) {
        return false
    }
    zip.seek(locatorPosition)
    // RandomAccessFile.readInt assumes big-endian byte order, but ZIP format uses
    // little-endian.
    return zip.readInt() == ZIP64_EOCD_LOCATOR_SIG_REVERSE_BYTE_ORDER
}

/**
 * Returns the offset of the start of the ZIP Central Directory in the archive.
 *
 *
 * NOTE: Byte order of `zipEndOfCentralDirectory` must be little-endian.
 */
fun getZipEocdCentralDirectoryOffset(zipEndOfCentralDirectory: ByteBuffer): Long {
    assertByteOrderLittleEndian(zipEndOfCentralDirectory)
    return getUnsignedInt32(
        zipEndOfCentralDirectory,
        zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET
    )
}

/**
 * Sets the offset of the start of the ZIP Central Directory in the archive.
 *
 *
 * NOTE: Byte order of `zipEndOfCentralDirectory` must be little-endian.
 */
fun setZipEocdCentralDirectoryOffset(zipEndOfCentralDirectory: ByteBuffer, offset: Long) {
    assertByteOrderLittleEndian(zipEndOfCentralDirectory)
    setUnsignedInt32(
        zipEndOfCentralDirectory,
        zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET,
        offset
    )
}

/**
 * Returns the size (in bytes) of the ZIP Central Directory.
 *
 *
 * NOTE: Byte order of `zipEndOfCentralDirectory` must be little-endian.
 */
fun getZipEocdCentralDirectorySizeBytes(zipEndOfCentralDirectory: ByteBuffer): Long {
    assertByteOrderLittleEndian(zipEndOfCentralDirectory)
    return getUnsignedInt32(
        zipEndOfCentralDirectory,
        zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET
    )
}

fun assertByteOrderLittleEndian(buffer: ByteBuffer) {
    require(buffer.order() == ByteOrder.LITTLE_ENDIAN) { "ByteBuffer byte order must be little endian" }
}

fun getUnsignedInt16(buffer: ByteBuffer, offset: Int): Int {
    return buffer.getShort(offset).toInt() and 0xffff
}

fun getUnsignedInt32(buffer: ByteBuffer, offset: Int): Long {
    return buffer.getInt(offset).toLong() and 0xffffffffL
}

private fun setUnsignedInt32(buffer: ByteBuffer, offset: Int, value: Long) {
    require(!(value < 0 || value > 0xffffffffL)) { "uint32 value of out range: $value" }
    buffer.putInt(buffer.position() + offset, value.toInt())
}


