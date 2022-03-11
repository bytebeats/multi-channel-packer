package me.bytebeats.packer.base

/**
 * Created by bytebeats on 2022/3/8 : 19:22
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */
class SignatureNotFoundException @JvmOverloads constructor(
    message: String?,
    cause: Throwable? = null
) : Exception(message, cause)