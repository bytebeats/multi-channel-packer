package me.bytebeats.packer.base

/**
 * Created by bytebeats on 2022/3/8 : 17:52
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */

const val CHANNEL_BLOCK_ID = 0x881155ff
const val CONTENT_CHAR_SET = "UTF-8"
internal const val SHORT_LENGTH = 2
internal val V1_MAGIC = byteArrayOf(0x6c, 0x74, 0x6c, 0x6f, 0x76, 0x65, 0x7a, 0x68)//it's "ltlovezh"