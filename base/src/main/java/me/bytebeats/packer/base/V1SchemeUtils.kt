package me.bytebeats.packer.base

import me.bytebeats.packer.base.verify.ZIP_EOCD_REC_MIN_SIZE
import me.bytebeats.packer.base.verify.getEocd
import me.bytebeats.packer.base.verify.getUnsignedInt16
import me.bytebeats.packer.base.verify.isZip64EndOfCentralDirectoryLocatorPresent
import java.io.DataInput
import java.io.DataOutput
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.util.jar.JarEntry
import java.util.jar.JarFile


/**
 * Created by bytebeats on 2022/3/11 : 17:26
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */
object V1SchemeUtils {

    /**
     * write channel to apk
     *
     * 1, remove original comment length and comments
     * 2, [2][n][2][2]:
     * 2-byte represent comments length, which is n in short
     * n-byte represent comment itself
     * 2-byte represent is the same with the first 2-byte
     * 8-byte represent is the v1 scheme magic number
     *
     * @param file
     * @param channel
     * @throws Exception
     */
    @Throws(Exception::class)
    fun writeChannel(file: File?, channel: String?) {
        if (file == null || !file.exists() || !file.isFile || channel == null || channel.isEmpty()) {
            throw Exception("param error , file : $file , channel : $channel")
        }
        var raf: RandomAccessFile? = null
        val comment: ByteArray = channel.toByteArray(CONTENT_CHAR_SET)
        val eocdAndOffsetInFile = getEocd(file)
        if (eocdAndOffsetInFile!!.first.remaining() == ZIP_EOCD_REC_MIN_SIZE) {
            println("file : " + file.absolutePath + " , has no comment")
            try {
                raf = RandomAccessFile(file, "rw")
                //1.locate comment length field
                raf.seek(file.length() - SHORT_BYTE_COUNT)
                //2.write zip comment length (content field length + length field length + magic field length)
                writeShort(comment.size + SHORT_BYTE_COUNT + V1_MAGIC.size, raf)
                //3.write content
                raf.write(comment)
                //4.write content length
                writeShort(comment.size, raf)
                //5. write magic bytes
                raf.write(V1_MAGIC)
            } finally {
                raf?.close()
            }
        } else {
            println("file : " + file.absolutePath + " , has comment")
            if (containV1Magic(file)) {
                try {
                    val existChannel = readChannel(file)
                    if (existChannel != null) {
                        file.delete()
                        throw ChannelExistException(
                            "file : " + file.absolutePath + " has a channel : " + existChannel
                                    + ", only ignore"
                        )
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
            val existCommentLength: Int = getUnsignedInt16(
                eocdAndOffsetInFile.first,
                ZIP_EOCD_REC_MIN_SIZE - SHORT_BYTE_COUNT
            )
            val newCommentLength: Int =
                existCommentLength + comment.size + SHORT_BYTE_COUNT + V1_MAGIC.size
            try {
                raf = RandomAccessFile(file, "rw")
                //1.locate comment length field
                raf.seek(eocdAndOffsetInFile.second + ZIP_EOCD_REC_MIN_SIZE - SHORT_BYTE_COUNT)
                //2.write zip comment length (existCommentLength + content field length + length field length + magic field length)
                writeShort(newCommentLength, raf)
                //3.locate where channel should begin
                raf.seek(eocdAndOffsetInFile.second + ZIP_EOCD_REC_MIN_SIZE + existCommentLength)
                //4.write content
                raf.write(comment)
                //5.write content length
                writeShort(comment.size, raf)
                //6.write magic bytes
                raf.write(V1_MAGIC)
            } finally {
                raf?.close()
            }
        }
    }

    /**
     * remove channel from apk in the v1 signature mode
     * namely set comment length into 0
     */
    @Throws(Exception::class)
    fun removeChannelByV1(file: File?) {
        if (file == null || !file.exists() || !file.isFile) {
            throw Exception("param error , file : $file")
        }
        val eocdAndOffsetInFile = getEocd(file)
        if (eocdAndOffsetInFile!!.first.remaining() == ZIP_EOCD_REC_MIN_SIZE) {
            println("file : ${file.name} , has no comment")
        } else {
            println("file : ${file.name} , has comment")
            val existCommentLength: Int = getUnsignedInt16(
                eocdAndOffsetInFile.first, ZIP_EOCD_REC_MIN_SIZE - SHORT_BYTE_COUNT
            )
            var raf: RandomAccessFile? = null
            try {
                raf = RandomAccessFile(file, "rw")
                //1.locate comment length field
                raf.seek(eocdAndOffsetInFile.second + ZIP_EOCD_REC_MIN_SIZE - SHORT_BYTE_COUNT)
                //2.write zip comment length (0)
                writeShort(0, raf)
                //3. modify the length of apk file
                raf.setLength(file.length() - existCommentLength)
                println("file : ${file.name} , remove comment success")
            } finally {
                raf?.close()
            }
        }
    }

    /**
     * read channel from apk
     * in v1 scheme of signed apk:
     * [...][n][2][8]
     * the last 8-byte is magic number
     * the 2-byte before magic number is channel length bytes length, the 2-byte is n in short
     * the n-byte before channel length is channel its self, read the n-byte into String in UTF-8 is the channel value
     *
     * @param file
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    fun readChannel(file: File?): String {
        var raf: RandomAccessFile? = null
        return try {
            raf = RandomAccessFile(file, "r")
            var index = raf.length()
            val buffer = ByteArray(V1_MAGIC.size)
            index -= V1_MAGIC.size
            raf.seek(index)
            raf.readFully(buffer)
            // whether magic bytes matched
            if (isV1MagicMatch(buffer)) {
                index -= SHORT_BYTE_COUNT
                raf.seek(index)
                // read channel length field
                val length = readShort(raf).toInt()
                if (length > 0) {
                    index -= length.toLong()
                    raf.seek(index)
                    // read channel bytes
                    val bytesComment = ByteArray(length)
                    raf.readFully(bytesComment)
                    String(bytesComment, CONTENT_CHAR_SET)
                } else {
                    throw Exception("zip channel info not found")
                }
            } else {
                throw Exception("zip v1 magic not found")
            }
        } finally {
            raf?.close()
        }
    }

    @Throws(IOException::class)
    private fun writeShort(i: Int, out: DataOutput) {
        val buffer = ByteBuffer.allocate(SHORT_BYTE_COUNT).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putShort(i.toShort())
        out.write(buffer.array())
    }

    @Throws(IOException::class)
    private fun readShort(input: DataInput): Short {
        val array = ByteArray(SHORT_BYTE_COUNT)
        input.readFully(array)
        val buffer = ByteBuffer.wrap(array).order(ByteOrder.LITTLE_ENDIAN)
        return buffer.getShort(0)
    }

    /**
     * judge whether contain v1 magic int the end of file
     *
     * magic of v1 scheme is at the very end of apk file
     * namely the last 8-byte is the magic of v1 signature of apk
     *
     * @param file
     * @return
     * @throws IOException
     */
    @Throws(IOException::class)
    fun containV1Magic(file: File?): Boolean {
        var raf: RandomAccessFile? = null
        return try {
            raf = RandomAccessFile(file, "r")
            var index = raf.length()
            val buffer = ByteArray(V1_MAGIC.size)
            index -= V1_MAGIC.size
            raf.seek(index)
            raf.readFully(buffer)
            isV1MagicMatch(buffer)
        } finally {
            raf?.close()
        }
    }

    /**
     * check v1 magic
     *
     * @param buffer
     * @return
     */
    private fun isV1MagicMatch(buffer: ByteArray): Boolean {
        if (buffer.size != V1_MAGIC.size) {
            return false
        }
        for (i in V1_MAGIC.indices) {
            if (buffer[i] != V1_MAGIC[i]) {
                return false
            }
        }
        return true
    }

    /**
     * get eocd and offset of central directory from apk
     *
     * @param apk
     * @return Pair<ByteBuffer, Long> eocd and offset of central directory
     * @throws IOException
     * @throws SignatureNotFoundException
     */
    @Throws(IOException::class, SignatureNotFoundException::class)
    fun getEocd(apk: File?): Pair<ByteBuffer, Long>? {
        if (apk == null || !apk.exists() || !apk.isFile) {
            return null
        }
        var raf: RandomAccessFile? = null
        return try {
            raf = RandomAccessFile(apk, "r")
            //find the EOCD
            val eocdAndOffsetInFile = getEocd(raf)
            if (isZip64EndOfCentralDirectoryLocatorPresent(raf, eocdAndOffsetInFile.second)) {
                throw SignatureNotFoundException("ZIP64 APK not supported")
            }
            eocdAndOffsetInFile
        } finally {
            raf?.close()
        }
    }

    /**
     * copy file
     *
     * @param src
     * @param dest
     * @throws IOException
     */
    @Throws(IOException::class)
    fun copyFile(src: File, dest: File) {
        if (!dest.exists()) {
            dest.createNewFile()
        }
        var source: FileChannel? = null
        var destination: FileChannel? = null
        try {
            source = FileInputStream(src).channel
            destination = FileOutputStream(dest).channel
            destination.transferFrom(source, 0, source.size())
        } finally {
            source?.close()
            destination?.close()
        }
    }

    /**
     * judge whether apk contain v1 signature
     *
     * @param file
     * @return true if "META-INF/MANIFEST.MF" and "META-INF/CERT.SF" exists meanwhile or false
     */
    fun containV1Signature(file: File?): Boolean {
        try {
            JarFile(file).use { jarFile ->
                val manifestEntry = jarFile.getJarEntry("META-INF/MANIFEST.MF")
                var sfEntry: JarEntry? = null
                val entries = jarFile.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (entry.name.matches("META-INF/\\w+\\.SF".toRegex())) {
                        sfEntry = jarFile.getJarEntry(entry.name)
                        break
                    }
                }
                jarFile.close()
                if (manifestEntry != null && sfEntry != null) {
                    return true
                }
            }
        } catch (e: IOException) {
            e.printStackTrace()
        }
        return false
    }

    class ChannelExistException(message: String? = null) : Exception(message)
}