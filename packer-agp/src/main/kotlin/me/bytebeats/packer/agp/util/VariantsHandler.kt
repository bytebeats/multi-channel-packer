package me.bytebeats.packer.agp.util

import com.android.build.api.variant.Variant

/**
 * Created by bytebeats on 2022/3/18 : 20:13
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */
sealed interface VariantsHandler {
    fun onAllVariants(block: (Variant) -> Unit)

    class Agp7Impl : VariantsHandler {
        override fun onAllVariants(block: (Variant) -> Unit) {

        }
    }

    class Agp4Dot2Impl : VariantsHandler {
        override fun onAllVariants(block: (Variant) -> Unit) {

        }
    }
}