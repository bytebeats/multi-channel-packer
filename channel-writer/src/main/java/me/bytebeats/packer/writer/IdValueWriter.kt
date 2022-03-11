package me.bytebeats.packer.writer

import me.bytebeats.packer.base.ApkSectionInfo
import me.bytebeats.packer.base.SignatureNotFoundException
import me.bytebeats.packer.base.V2SchemeUtils
import me.bytebeats.packer.base.verify.APK_SIGNATURE_SCHEME_V2_BLOCK_ID
import me.bytebeats.packer.base.verify.setZipEocdCentralDirectoryOffset
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder


/**
 * Created by bytebeats on 2022/3/11 : 20:04
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */

/**
 * add id-value to apk
 *
 * @param apkSectionInfo
 * @param destApk
 * @param id
 * @param valueBuffer
 * @throws IOException
 * @throws SignatureNotFoundException
 */
@Throws(IOException::class, SignatureNotFoundException::class, RuntimeException)
fun addIdValue(apkSectionInfo: ApkSectionInfo, destApk: File, id: Int, valueBuffer: ByteBuffer) {
    if (id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID) {
        throw RuntimeException(
            "addIdValue , id can not is $APK_SIGNATURE_SCHEME_V2_BLOCK_ID, v2 signature block use it"
        )
    }
    val idValueMap = LinkedHashMap<Int, ByteBuffer>()
    idValueMap[id] = valueBuffer
    addIdValueByteBufferMap(apkSectionInfo, destApk, idValueMap)
}

@Throws(SignatureNotFoundException::class, IOException::class, RuntimeException::class)
fun removeIdValue(apkSectionInfo: ApkSectionInfo?, destApk: File?, idList: List<Int>?) {
    if (apkSectionInfo == null || destApk == null || !destApk.isFile() || !destApk.exists() || idList == null || idList.isEmpty()) {
        return
    }
    val existentIdValueMap =
        V2SchemeUtils.getAllIdValue(apkSectionInfo.schemeV2Block!!.first).toMutableMap()
    val existentIdValueSize = existentIdValueMap.size
    if (!existentIdValueMap.containsKey(APK_SIGNATURE_SCHEME_V2_BLOCK_ID)) {
        throw SignatureNotFoundException(
            "No APK V2 Signature Scheme block in APK Signing Block"
        )
    }
    println("removeIdValue , existed IdValueMap = $existentIdValueMap")
    for (id in idList) {
        if (id != APK_SIGNATURE_SCHEME_V2_BLOCK_ID) {
            existentIdValueMap.remove(id)
        }
    }
    val remainderIdValueSize = existentIdValueMap.size
    if (existentIdValueSize == remainderIdValueSize) {
        println("removeIdValue , No idValue was deleted")
    } else {
        println("removeIdValue , final IdValueMap = $existentIdValueMap")
        val newApkSigningBlock = V2SchemeUtils.generateApkSigningBlock(existentIdValueMap)
        println("removeIdValue , oldApkSigningBlock size = ${apkSectionInfo.schemeV2Block!!.first.remaining()}, newApkSigningBlock size = ${newApkSigningBlock.remaining()}")
        val centralDir = apkSectionInfo.centralDir!!.first
        val eocd = apkSectionInfo.eocd!!.first
        val centralDirOffset = apkSectionInfo.centralDir!!.second
        val apkChangeSize: Int =
            newApkSigningBlock.remaining() - apkSectionInfo.schemeV2Block!!.first.remaining()
        //update the offset of centralDir
        //修改了EOCD中保存的中央目录偏移量
        setZipEocdCentralDirectoryOffset(eocd, centralDirOffset + apkChangeSize)
        val apkLength = apkSectionInfo.apkSize + apkChangeSize
        var raf: RandomAccessFile? = null
        try {
            raf = RandomAccessFile(destApk, "rw")
            if (apkSectionInfo.lowMemory) {
                raf.seek(apkSectionInfo.schemeV2Block!!.second)
            } else {
                val contentEntry = apkSectionInfo.contentEntry!!.first
                raf.seek(apkSectionInfo.contentEntry!!.second)
                //1. write real content Entry block
                raf.write(
                    contentEntry.array(),
                    contentEntry.arrayOffset() + contentEntry.position(),
                    contentEntry.remaining()
                )
            }

            //2. write new apk v2 scheme block
            raf.write(
                newApkSigningBlock.array(),
                newApkSigningBlock.arrayOffset() + newApkSigningBlock.position(),
                newApkSigningBlock.remaining()
            )
            //3. write central dir block
            raf.write(
                centralDir.array(),
                centralDir.arrayOffset() + centralDir.position(),
                centralDir.remaining()
            )
            //4. write eocd block
            raf.write(eocd.array(), eocd.arrayOffset() + eocd.position(), eocd.remaining())
            //5. modify the length of apk file
            if (raf.getFilePointer() != apkLength) {
                throw RuntimeException("after removeIdValue , file size wrong , FilePointer : ${raf.getFilePointer()}, apkLength : $apkLength")
            }
            raf.setLength(apkLength)
            println("removeIdValue , after remove channel , apk is ${destApk.getAbsolutePath()}, length = $destApk.length()")
        } finally {
            //恢复EOCD中保存的中央目录偏移量，满足基础包的APK结构
            setZipEocdCentralDirectoryOffset(eocd, centralDirOffset)
            raf?.close()
        }
    }
}

/**
 * add id-value pairs to apk
 *
 * @param apkSectionInfo
 * @param destApk
 * @param idValueMap
 * @throws IOException
 * @throws SignatureNotFoundException
 */
@Throws(IOException::class, SignatureNotFoundException::class)
fun addIdValueByteBufferMap(
    apkSectionInfo: ApkSectionInfo,
    destApk: File,
    idValueMap: MutableMap<Int, ByteBuffer>?
) {
    if (idValueMap == null || idValueMap.isEmpty()) {
        throw RuntimeException("addIdValueByteBufferMap , id value pair is empty")
    }
    if (idValueMap.containsKey(APK_SIGNATURE_SCHEME_V2_BLOCK_ID)) { //不能和系统V2签名块的ID冲突
        idValueMap.remove(APK_SIGNATURE_SCHEME_V2_BLOCK_ID)
    }
    println("addIdValueByteBufferMap , new IdValueMap = $idValueMap")
    val existentIdValueMap: MutableMap<Int, ByteBuffer> = V2SchemeUtils.getAllIdValue(
        apkSectionInfo.schemeV2Block!!.first
    ).toMutableMap()
    if (!existentIdValueMap.containsKey(APK_SIGNATURE_SCHEME_V2_BLOCK_ID)) {
        throw SignatureNotFoundException(
            "No APK V2 Signature Scheme block in APK Signing Block"
        )
    }
    println("addIdValueByteBufferMap , existed IdValueMap = $existentIdValueMap")
    existentIdValueMap.putAll(idValueMap)
    println("addIdValueByteBufferMap , final IdValueMap = $existentIdValueMap")
    val newApkSigningBlock = V2SchemeUtils.generateApkSigningBlock(existentIdValueMap)
    println(
        "addIdValueByteBufferMap , oldApkSigningBlock size = ${apkSectionInfo.schemeV2Block!!.first.remaining()}, newApkSigningBlock size = ${newApkSigningBlock.remaining()}"
    )
    val centralDir = apkSectionInfo.centralDir!!.first
    val eocd = apkSectionInfo.eocd!!.first
    val centralDirOffset = apkSectionInfo.centralDir!!.second
    val apkChangeSize: Int =
        newApkSigningBlock.remaining() - apkSectionInfo.schemeV2Block!!.first.remaining()
    //update the offset of centralDir
    setZipEocdCentralDirectoryOffset(eocd, centralDirOffset + apkChangeSize) //修改了EOCD中保存的中央目录偏移量
    val apkLength = apkSectionInfo.apkSize + apkChangeSize
    var raf: RandomAccessFile? = null
    try {
        raf = RandomAccessFile(destApk, "rw")
        if (apkSectionInfo.lowMemory) {
            raf.seek(apkSectionInfo.schemeV2Block!!.second)
        } else {
            val contentEntry = apkSectionInfo.contentEntry!!.first
            raf.seek(apkSectionInfo.contentEntry!!.second)
            //1. write real content Entry block
            raf.write(
                contentEntry.array(),
                contentEntry.arrayOffset() + contentEntry.position(),
                contentEntry.remaining()
            )
        }

        //2. write new apk v2 scheme block
        raf.write(
            newApkSigningBlock.array(),
            newApkSigningBlock.arrayOffset() + newApkSigningBlock.position(),
            newApkSigningBlock.remaining()
        )
        //3. write central dir block
        raf.write(
            centralDir.array(),
            centralDir.arrayOffset() + centralDir.position(),
            centralDir.remaining()
        )
        //4. write eocd block
        raf.write(eocd.array(), eocd.arrayOffset() + eocd.position(), eocd.remaining())
        //5. modify the length of apk file
        if (raf.getFilePointer() != apkLength) {
            throw RuntimeException("after addIdValueByteBufferMap , file size wrong , FilePointer : ${raf.getFilePointer()}, apkLength : $apkLength")
        }
        raf.setLength(apkLength)
        println("addIdValueByteBufferMap , after add channel , new apk is ${destApk.getAbsolutePath()} , length = ${destApk.length()}")
    } finally {
        //恢复EOCD中保存的中央目录偏移量，满足基础包的APK结构
        setZipEocdCentralDirectoryOffset(eocd, centralDirOffset)
        raf?.close()
    }
}

/**
 * add id-value(byte[]) to apk
 *
 * @param destApk
 * @param id
 * @param buffer  please ensure utf-8 charset
 */
@Throws(IOException::class, SignatureNotFoundException::class)
fun addIdValue(srcApk: File, destApk: File, id: Int, buffer: ByteArray, lowMemory: Boolean) {
    val apkSectionInfo = getApkSectionInfo(srcApk, lowMemory)
    val channelByteBuffer = ByteBuffer.wrap(buffer)
    //apk中所有字节都是小端模式
    channelByteBuffer.order(ByteOrder.LITTLE_ENDIAN)
    addIdValue(apkSectionInfo, destApk, id, channelByteBuffer)
}

/**
 * add id-value(byte[]) pairs to apk
 *
 * @param srcApk
 * @param destApk
 * @param idValueByteMap
 * @throws IOException
 * @throws SignatureNotFoundException
 */
@Throws(IOException::class, SignatureNotFoundException::class)
fun addIdValueByteMap(
    srcApk: File,
    destApk: File,
    idValueByteMap: Map<Int, ByteArray>?,
    lowMemory: Boolean
) {
    if (idValueByteMap == null || idValueByteMap.isEmpty()) {
        throw RuntimeException("addIdValueByteMap , idValueByteMap is empty")
    }
    val apkSectionInfo = getApkSectionInfo(srcApk, lowMemory)
    val idValues = LinkedHashMap<Int, ByteBuffer>() // keep order
    for (integer in idValueByteMap.keys) {
        val channelByteBuffer = ByteBuffer.wrap(idValueByteMap[integer])
        //apk中所有字节都是小端模式
        channelByteBuffer.order(ByteOrder.LITTLE_ENDIAN)
        idValues[integer] = channelByteBuffer
    }
    addIdValueByteBufferMap(apkSectionInfo!!, destApk, idValues)
}

/**
 * add id-value(byte[]) pairs to apk
 *
 * @param apkFile
 * @param idValueByteMap
 * @throws IOException
 * @throws SignatureNotFoundException
 */
@Throws(IOException::class, SignatureNotFoundException::class)
fun addIdValueByteMap(apkFile: File, idValueByteMap: Map<Int, ByteArray>?, lowMemory: Boolean) {
    addIdValueByteMap(apkFile, apkFile, idValueByteMap, lowMemory)
}


/**
 * add id-value(byte[]) to apk
 *
 * @param apkFile
 * @param id
 * @param buffer
 * @throws IOException
 * @throws SignatureNotFoundException
 */
@Throws(IOException::class, SignatureNotFoundException::class)
fun addIdValue(apkFile: File, id: Int, buffer: ByteArray, lowMemory: Boolean) {
    addIdValue(apkFile, apkFile, id, buffer, lowMemory)
}


@Throws(IOException::class, SignatureNotFoundException::class)
fun getApkSectionInfo(baseApk: File?, lowMemory: Boolean): ApkSectionInfo? =
    if (baseApk == null || !baseApk.exists() || !baseApk.isFile()) null
    else V2SchemeUtils.getApkSectionInfo(baseApk, lowMemory)