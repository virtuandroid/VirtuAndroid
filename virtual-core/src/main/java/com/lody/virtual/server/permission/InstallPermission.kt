package com.lody.virtual.server.permission

import android.os.Parcel
import android.os.Parcelable

/**
 * @author Alberto Lazari
 * Install-time permissions are granted by default on application install, with the exception
 * of signature and system permissions and permissions that cannot be found on the system.
 * Their status can be either GRANTED or DENIED.
 */
class InstallPermission : Permission {
    constructor(name: String?, status: Status) : super(name, status)

    constructor(name: String?, permission: InstallPermission) : super(name, permission)

    internal constructor(name: String?, statusString: String?) : super(name, statusString)

    override fun isValidStatus(status: Status?): Boolean {
        return status == Status.GRANTED || status == Status.DENIED || status == Status.DECLARED
    }

    override fun describeContents(): Int = 0

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeString(name)
        dest.writeString(statusToString())
    }

    companion object {
        @JvmField
        val CREATOR: Parcelable.Creator<InstallPermission> =
            object : Parcelable.Creator<InstallPermission> {
                override fun createFromParcel(source: Parcel): InstallPermission {
                    val name = source.readString()
                    val statusString = source.readString()
                    return InstallPermission(name, statusString)
                }

                override fun newArray(size: Int): Array<InstallPermission?> =
                    arrayOfNulls(size)
            }
    }
}
