package me.bytebeats.packer.base

/**
 * Created by bytebeats on 2022/3/8 : 19:42
 * E-mail: happychinapc@gmail.com
 * Quote: Peasant. Educated. Worker
 */
data class Pair<F, S>(val first: F, val second: S) {

    override fun hashCode(): Int {
        val prime = 31
        var hash = 1
        hash = hash * prime + (first?.hashCode() ?: 0)
        return hash
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null) return false
        if (javaClass != other.javaClass) return false

        other as Pair<*, *>

        if (first != other.first) return false
        if (second != other.second) return false

        return true
    }

    override fun toString(): String = "Pair{$first $second}"

    companion object {
        @JvmStatic
        @JvmName("create")
        operator fun <F, S> invoke(first: F, second: S): Pair<F, S> = Pair(first, second)
    }
}