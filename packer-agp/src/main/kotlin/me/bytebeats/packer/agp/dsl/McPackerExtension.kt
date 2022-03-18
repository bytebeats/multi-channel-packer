package me.bytebeats.packer.agp.dsl

import com.android.build.gradle.internal.dsl.decorator.SupportedPropertyType
import me.bytebeats.packer.agp.util.orFalse
import java.io.File
import org.gradle.api.GradleException

/**
 * Created by bytebeats on 2022/3/18 : 20:45
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */
/**
 * config extension class for plugin extension
 */
open class McPackerExtension {
    /**
     * only fit v2 signature
     * 低内存模式（仅针对V2签名，默认为false
     * 只把签名块、中央目录和EOCD读取到内存，不把最大头的内容块读取到内存
     * 在手机上合成APK时，可以使用该模式
     */
    var lowMemory: Boolean = false

    /**
     * 是否为快速模式，即不验证渠道名
     */
    var fastMode: Boolean = false

    /**
     * 渠道列表文件
     */
    var channelFile: SupportedPropertyType.Var.File? = null

    /**
     * 渠道包生成目录
     */
    var apkOutputDir: SupportedPropertyType.Var.File? = null

    /**
     * 渠道包的命名格式
     */
    var channelApkNameFormat = DEFAULT_CHANNEL_APK_NAME

    /**
     * buildTime的时间格式
     */
    var buildDateTimeFormat = DEFAULT_BUILD_TIME_FORMAT

    fun channels(): List<String> {
        val channels = mutableListOf<String>()
        if (channelFile?.isFile.orFalse() && channelFile?.exists().orFalse()) {
            channelFile?.forEachLine { channel ->
                if (channel.isNotEmpty()) {
                    channels.add(channel)
                }
            }
            println("channels from `channelFile`: $channels")
        }
        return channels
    }

    fun assetDslConfiguration() {
        if (!apkOutputDir?.exists().orFalse()) {
            apkOutputDir?.mkdirs()
        }
        if (!apkOutputDir?.isDirectory.orFalse()) {
            throw GradleException("dsl configuration apkOutputDir:${apkOutputDir.absolutePath} is not directory")
        }
        apkOutputDir?.listFiles()?.forEach { oldApk ->
            if (oldApk.name.endsWith(".apk")) {
                oldApk.delete()
            }
        }
    }

    companion object {
        private const val DEFAULT_CHANNEL_APK_NAME =
            "${'$'}{appName}-${'S'}{versionName}-${'$'}{versionCode}-${'$'}{flavorName}-${'$'}{buildType}-${'$'}{buildTime}"
        private const val DEFAULT_BUILD_TIME_FORMAT = "yyyyMMdd-HH:mm:ss"
    }
}