package com.lody.virtual.client.ipc

import com.lody.virtual.client.core.VirtualCore
import com.lody.virtual.server.IVPermissionManager
import com.lody.virtual.server.permission.AppPermissions
import com.lody.virtual.server.permission.Permission
import com.lody.virtual.server.pm.parser.VPackage

object VPermissionManager {
    @JvmStatic
    fun get() = this

    private var mRemote: IVPermissionManager? = null
    private fun getRemoteInterface(): IVPermissionManager? {
        val logBinder = ServiceManagerNative.getService(ServiceManagerNative.VIRTUAL_PERMISSIONS)
        return IVPermissionManager.Stub.asInterface(logBinder)
    }

    fun getInterface(): IVPermissionManager? {
        if (mRemote == null || (!mRemote!!.asBinder()
                .pingBinder() && !VirtualCore.get().isVAppProcess)
        ) {
            synchronized(VPackageManager::class.java) {
                val remote = this.getRemoteInterface()
                mRemote = LocalProxyUtils.genProxy(
                    IVPermissionManager::class.java,
                    remote
                )
            }
        }
        return mRemote
    }

    fun checkPermission(permission: String?, uid: Int): Int {
        return getInterface()!!.checkPermission(permission, uid)
    }

    fun initPermissionsForUid(uid: Int, pkg: VPackage) {
        return getInterface()!!.initPermissionsForUid(uid, pkg)
    }

    fun removePermissionsForUid(uid: Int) {
        return getInterface()!!.removePermissionsForUid(uid)
    }

    fun shouldShowRequestPermissionRationale(
        permissionName: String?,
        uid: Int
    ): Boolean {
        return getInterface()!!.shouldShowRequestPermissionRationale(permissionName, uid)
    }


    fun getAppPermissions(
        uid: Int
    ): AppPermissions? {
        return getInterface()!!.getAppPermissions(uid)
    }

    /**
     * @return @permission for @uid, or `null` if not declared.
     */
    fun getPermission(permission: String?, uid: Int): Permission? {
        return getAppPermissions(uid)?.getPermission(permission)
    }

    fun allowPermission(permissionName: String?, uid: Int): Boolean {
        return getInterface()?.allowPermission(permissionName, uid) == true
    }

    fun doNotAllowPermission(permissionName: String?, uid: Int): Boolean {
        return getInterface()?.doNotAllowPermission(permissionName, uid) == true
    }

    fun alwaysAskPermission(permissionName: String?, uid: Int): Boolean {
        return getInterface()?.alwaysAskPermission(permissionName, uid) == true
    }

    fun followGroupPermission(permissionName: String?, uid: Int): Boolean {
        return getInterface()?.followGroupPermission(permissionName, uid) == true
    }
}
