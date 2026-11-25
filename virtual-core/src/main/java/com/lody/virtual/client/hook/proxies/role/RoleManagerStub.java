package com.lody.virtual.client.hook.proxies.role;

import android.content.Context;
import android.os.Build;

import androidx.annotation.RequiresApi;

import com.lody.virtual.client.hook.base.BinderInvocationProxy;
import com.lody.virtual.client.hook.base.ReplaceLastPkgMethodProxy;

import mirror.android.app.role.IRoleManager;

/**
 * @author Lody
 */
@RequiresApi(api = Build.VERSION_CODES.Q)
public class RoleManagerStub extends BinderInvocationProxy {

    public RoleManagerStub() {
        super(IRoleManager.Stub.asInterface, Context.ROLE_SERVICE);
    }

    @Override
    protected void onBindMethods() {
        super.onBindMethods();
        addMethodProxy(new ReplaceLastPkgMethodProxy("isRoleHeldAsUser"));
        addMethodProxy(new ReplaceLastPkgMethodProxy("addRoleHolderAsUser"));
        addMethodProxy(new ReplaceLastPkgMethodProxy("removeRoleHolderAsUser"));
        addMethodProxy(new ReplaceLastPkgMethodProxy("setDefaultApplicationAsUser"));
        addMethodProxy(new ReplaceLastPkgMethodProxy("addRoleHolderFromControllerAsUser"));
        addMethodProxy(new ReplaceLastPkgMethodProxy("removeRoleHolderFromControllerAsUser"));
        addMethodProxy(new ReplaceLastPkgMethodProxy("getHeldRolesFromControllerAsUser"));
        addMethodProxy(new ReplaceLastPkgMethodProxy("isApplicationVisibleForRoleAsUser"));
    }
}
