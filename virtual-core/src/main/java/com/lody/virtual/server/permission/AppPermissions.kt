package com.lody.virtual.server.permission

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
class AppPermissions(
    /**
     * @return Reference of all permissions
     */
    val all: MutableMap<String?, Permission>
) : Parcelable {

    /**
     * @return A copy of all type T permissions
     */
    fun <T : Permission> getAllPermissions(type: Class<T>): MutableMap<String?, T?> {
        return all.entries
            .filter { entry -> type.isInstance(entry.value) }
            .associate { it.key to it.value as? T }.toMutableMap()
    }

    fun getPermission(permissionName: String?): Permission? {
        return all[permissionName]
    }

    @JvmName("getPermissionInline")
    inline fun <reified T : Permission?> getPermission(
        permissionName: String?,
    ): T? {
        val permission = all[permissionName]
        return permission as? T
    }

    fun updatePermission(newPermission: Permission) {
        val permissionName = newPermission.name
        val oldPermission = getPermission(permissionName)
        // Set only if permission is declared
        if (oldPermission != null) {
            all[permissionName] = newPermission
        }
    }
}
