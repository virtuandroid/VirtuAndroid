// IVPermissionManager.aidl
package com.lody.virtual.server;

import com.lody.virtual.server.pm.parser.VPackage;
import com.lody.virtual.server.permission.AppPermissions;

interface IVPermissionManager {
    int checkPermission(String permission, int uid);
    void initPermissionsForUid(int uid, in VPackage pkg);
    void removePermissionsForUid(int uid);

    boolean shouldShowRequestPermissionRationale(String permissionName, int uid);

    AppPermissions getAppPermissions(int uid);

    boolean allowPermission(String permissionName, int uid);
    boolean doNotAllowPermission(String permissionName, int uid);
    boolean followGroupPermission(String permissionName, int uid);
    boolean alwaysAskPermission(String permissionName, int uid);
}