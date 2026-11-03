package com.lody.virtual.server.accounts

import android.accounts.Account
import android.os.Parcel
import android.os.Parcelable
import kotlinx.collections.immutable.PersistentMap
import kotlinx.collections.immutable.persistentMapOf
import kotlinx.collections.immutable.toPersistentMap

/**
 * @author Lody
 */
data class VAccount(
    val userId: Int,
    val name: String,
    val previousName: String? = null,
    val type: String,
    val password: String? = null,
    val lastAuthenticatedTime: Long = 0,
    val authTokens: PersistentMap<String?, String?> = persistentMapOf(),
    val userDatas: PersistentMap<String?, String?> = persistentMapOf(),
) : Parcelable {
    constructor(userId: Int, account: Account) : this(
        userId = userId,
        name = account.name,
        type = account.type,
    )

    constructor(p: Parcel) : this(
        userId = p.readInt(),
        name = p.readString()!!,
        previousName = p.readString(),
        type = p.readString()!!,
        password = p.readString(),
        lastAuthenticatedTime = p.readLong(),
        authTokens = p.readInt().let { authTokensSize ->
            val map = HashMap<String?, String?>(authTokensSize)
            repeat(authTokensSize) {
                val key = p.readString()
                val value = p.readString()
                map[key] = value
            }
            map.toPersistentMap()
        },
        userDatas = p.readInt().let { userDatasSize ->
            val map = HashMap<String?, String?>(userDatasSize)
            repeat(userDatasSize) {
                val key = p.readString()
                val value = p.readString()
                map[key] = value
            }
            map.toPersistentMap()
        }
    )

    override fun describeContents(): Int {
        return 0
    }

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeInt(userId)
        dest.writeString(name)
        dest.writeString(previousName)
        dest.writeString(type)
        dest.writeString(password)
        dest.writeLong(lastAuthenticatedTime)
        dest.writeInt(authTokens.size)
        for ((key, value) in authTokens) {
            dest.writeString(key)
            dest.writeString(value)
        }
        dest.writeInt(userDatas.size)
        for ((key, value) in userDatas) {
            dest.writeString(key)
            dest.writeString(value)
        }
    }

    companion object {
        @JvmField
        val CREATOR: Parcelable.Creator<VAccount?> = object : Parcelable.Creator<VAccount?> {
            override fun createFromParcel(source: Parcel): VAccount {
                return VAccount(source)
            }

            override fun newArray(size: Int): Array<VAccount?> {
                return arrayOfNulls(size)
            }
        }
    }
}

