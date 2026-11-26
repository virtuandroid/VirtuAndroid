package io.virtualapp.settings

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.MenuItem
import android.widget.ImageView
import android.widget.PopupMenu
import androidx.preference.Preference
import androidx.preference.PreferenceCategory
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.PreferenceViewHolder
import com.lody.virtual.client.ipc.VPermissionManager
import com.lody.virtual.server.permission.InstallPermission
import com.lody.virtual.server.permission.Permission
import com.lody.virtual.server.permission.PermissionGroup
import com.lody.virtual.server.permission.PermissionGroup.Companion.getGroupIconRes
import com.lody.virtual.server.permission.RuntimePermission
import com.virtualxposed.utils.Utils.getSerializableSafe
import io.virtualapp.abs.ui.VActivity
import java.util.TreeMap
import java.util.function.Consumer

/**
 * @author Alberto Lazari
 * @date 14/8/24
 */
class PermissionManageActivity : VActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val extras = intent.extras
        val appName = extras!!.getString(EXTRA_APP_NAME)
        val uid = extras.getInt(EXTRA_APP_UID)
        val type = extras.getSerializableSafe<Class<out Permission?>>(EXTRA_PERMISSIONS_TYPE)!!
        setTitle(appName)

        supportFragmentManager
            .beginTransaction()
            .replace(
                android.R.id.content,
                PermissionsFragment(type, appName, uid)
            )
            .commit()
    }

    class PermissionsFragment(
        private val type: Class<out Permission?>, private val appName: String?,
        private val uid: Int
    ) : PreferenceFragmentCompat() {
        private val permissionManager = VPermissionManager.get()

        private var ctx: Activity? = null

        private var categories: Set<PreferenceCategory> = emptySet()
        private lateinit var allowedCategory: PreferenceCategory
        private lateinit var askCategory: PreferenceCategory
        private lateinit var deniedCategory: PreferenceCategory
        private lateinit var groupCategory: PreferenceCategory

        override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
            setPreferencesFromResource(io.virtualapp.R.xml.permissions_manage_preferences, rootKey)

            allowedCategory = findPreference(ALLOWED_CATEGORY_KEY)!!
            askCategory = findPreference(ASK_CATEGORY_KEY)!!
            deniedCategory = findPreference(DENIED_CATEGORY_KEY)!!
            groupCategory = findPreference(FOLLOW_GROUP_CATEGORY_KEY)!!

            categories = setOf(
                allowedCategory,
                askCategory,
                deniedCategory,
                groupCategory
            )

            ctx = activity

            val appPermissions = permissionManager.getAppPermissions(uid)
            val allPermissions = appPermissions?.getAllPermissions(type) ?: emptyMap()

            // Sort permissions
            TreeMap(allPermissions)
                .forEach { (name: String?, permission: Permission?) ->
                    val preference = createPermissionPreference(permission!!)
                    getCategoryFor(permission).addPreference(preference)
                }

            updateNoneTexts()

            val overrideCategory =
                findPreference<Preference?>("override_permissions") as PreferenceCategory?
            if (type != PermissionGroup::class.java) {
                ctx!!.setTitle("Override " + TYPE_TO_NAME_MAP[type] + " permissions")
                overrideCategory!!.isVisible = false
                return
            }

            // Set listener on permissions override settings
            TYPE_TO_NAME_MAP.keys.forEach(Consumer { overrideType: Class<out Permission?>? ->
                findPreference<Preference?>(
                    "override_" + TYPE_TO_NAME_MAP[overrideType]
                )!!.onPreferenceClickListener =
                    Preference.OnPreferenceClickListener {
                        val intent = Intent(ctx, PermissionManageActivity::class.java)
                        intent.putExtra(EXTRA_APP_NAME, appName)
                        intent.putExtra(EXTRA_APP_UID, uid)
                        intent.putExtra(EXTRA_PERMISSIONS_TYPE, overrideType)
                        startActivity(intent)
                        true
                    }
            })
            // Create an invisible preference to show the divider under last element
            val phantomPreference: Preference = object : Preference(ctx!!) {
                override fun onBindViewHolder(holder: PreferenceViewHolder) {
                    super.onBindViewHolder(holder)
                    holder.isDividerAllowedAbove = true
                    val itemView = holder.itemView
                    val params = itemView.layoutParams
                    params.height = 0
                    itemView.setLayoutParams(params)
                }
            }
            overrideCategory!!.addPreference(phantomPreference)
        }

        private fun getCategoryFor(permission: Permission): PreferenceCategory {
            if (permission is RuntimePermission
                && !permission.isOverridden
            ) {
                return groupCategory
            }
            return when (permission.getStatus()) {
                Permission.Status.DECLARED -> allowedCategory
                Permission.Status.GRANTED -> allowedCategory
                Permission.Status.ALWAYS_ASK -> askCategory
                Permission.Status.UNREQUESTED -> deniedCategory
                Permission.Status.DENIED -> deniedCategory
            }
        }

        private fun updateCategories() {
            categories.forEach { category ->
                // Update permissions positions
                var i = 0
                while (i < category.preferenceCount) {
                    val preference = category.getPreference(i)
                    if (preference is PermissionPreference) {
                        val permission = permissionManager.getPermission(
                            preference.permission.name, uid
                        )
                        val newCategory = getCategoryFor(permission!!)
                        if (category !== newCategory) {
                            category.removePreference(preference)
                            // Iterating on category and the current item was removed.
                            // Keep index at the same position.
                            --i
                            newCategory.addPreference(preference)
                        }
                    }
                    ++i
                }
            }
            updateNoneTexts()
        }

        private fun updateNoneTexts() {
            categories.forEach { category ->
                val noneTextKey = "none_" + category.key + "_text"
                when (category.key) {
                    ALLOWED_CATEGORY_KEY, DENIED_CATEGORY_KEY -> {
                        val count = category.preferenceCount
                        val noneText = findPreference<Preference?>(noneTextKey)
                        if (count == 1 && noneText != null) {
                            // The only preference is the none text, leave it that way
                            return@forEach
                        }
                        if (count == 0) {
                            hideCategory(category, true)
                        } else {
                            category.isVisible = true
                            if (noneText != null) {
                                category.removePreference(noneText)
                            }
                        }
                    }

                    else -> {
                        if (category.preferenceCount == 0) {
                            hideCategory(category, false)
                        } else {
                            category.isVisible = true
                        }
                    }
                }
            }
        }

        private fun hideCategory(category: PreferenceCategory, showNoneText: Boolean) {
            // Do not show "No permissions allowed/denied" for runtime permissions, because they
            // could all be following their group
            if (!showNoneText || type == RuntimePermission::class.java) {
                category.isVisible = false
                return
            }
            val categoryKey = category.key
            val noneTextKey = "none_" + categoryKey + "_text"
            val titleRes: Int = if (categoryKey == "not_allowed") {
                io.virtualapp.R.string.permission_manage_none_not_allowed
            } else {
                io.virtualapp.R.string.permission_manage_none_allowed
            }
            val noneText: Preference = object : Preference(ctx!!) {
                override fun onBindViewHolder(holder: PreferenceViewHolder) {
                    super.onBindViewHolder(holder)
                    holder.isDividerAllowedBelow = false
                }
            }
            noneText.setKey(noneTextKey)
            noneText.setTitle(titleRes)
            noneText.isSelectable = false
            noneText.layoutResource = io.virtualapp.R.layout.none_permissions

            category.addPreference(noneText)
        }

        private fun createPermissionPreference(permission: Permission): PermissionPreference {
            val name = permission.name
            val readableName = permission.readableName
            val groupIconRes = if (permission is RuntimePermission)
                permission.groupIconRes
            else
                getGroupIconRes(name)
            val preference = PermissionPreference(ctx!!, permission)
            preference.setKey("permission_manage_preference_$name")
            preference.title = readableName
            preference.setSummary(name)
            preference.layoutResource = io.virtualapp.R.layout.item_permission_manage
            preference.setIcon(groupIconRes)
            return preference
        }

        private inner class PermissionPreference(ctx: Context, val permission: Permission) :
            Preference(ctx) {
            private var holder: PreferenceViewHolder? = null
            private var iconView: ImageView? = null

            override fun onBindViewHolder(holder: PreferenceViewHolder) {
                super.onBindViewHolder(holder)
                this.holder = holder

                holder.isDividerAllowedAbove = true
                holder.isDividerAllowedBelow = true

                if (iconView == null) {
                    iconView = holder.findViewById(android.R.id.icon) as ImageView?
                }
            }

            override fun onClick() {
                super.onClick()
                showContextMenu()
            }


            fun showContextMenu() {
                val popupMenu = PopupMenu(ctx, holder!!.itemView)
                if (permission is InstallPermission) {
                    // Cannot change declared permissions, it would break assumptions
                    if (permission.getStatus() != Permission.Status.DECLARED) {
                        popupMenu.inflate(io.virtualapp.R.menu.install_permission_manage_menu)
                    }
                } else if (permission is RuntimePermission) {
                    popupMenu.inflate(io.virtualapp.R.menu.runtime_permission_manage_menu)
                    if (permission.hasPermissionGroup()) {
                        // Show "Follow group" menu action
                        popupMenu.menu
                            .findItem(io.virtualapp.R.id.action_group).isVisible = true
                    }
                } else if (permission is PermissionGroup) {
                    popupMenu.inflate(io.virtualapp.R.menu.permission_group_manage_menu)
                }

                popupMenu.setOnMenuItemClickListener { item: MenuItem? ->
                    handleMenuChoice(item!!.itemId)
                }
                try {
                    popupMenu.show()
                } catch (e: Throwable) {
                    e.printStackTrace()
                }
            }

            fun handleMenuChoice(choice: Int): Boolean {
                if (choice == io.virtualapp.R.id.action_group) {
                    val result = permissionManager.followGroupPermission(permission.name, uid)
                    updateCategories()
                    return result
                }

                if (permission is RuntimePermission) {
                    permission.override()
                }
                val result = when (choice) {
                    io.virtualapp.R.id.action_allow -> {
                        permissionManager.allowPermission(permission.name, uid)
                    }

                    io.virtualapp.R.id.action_ask -> {
                        permissionManager.alwaysAskPermission(permission.name, uid)
                    }

                    io.virtualapp.R.id.action_do_not_allow -> {
                        permissionManager.doNotAllowPermission(permission.name, uid)
                    }

                    else -> false
                }
                updateCategories()
                return result
            }
        }

        companion object {
            private const val ALLOWED_CATEGORY_KEY = "allowed"
            private const val ASK_CATEGORY_KEY = "ask"
            private const val DENIED_CATEGORY_KEY = "not_allowed"
            private const val FOLLOW_GROUP_CATEGORY_KEY = "follow_group"
            private val TYPE_TO_NAME_MAP = mapOf(
                InstallPermission::class.java to "install",
                RuntimePermission::class.java to "runtime"
            )
        }
    }

    companion object {
        const val EXTRA_APP_NAME: String = "io.virtualapp.settings.extra.PERMISSION_MANAGE_APP_NAME"
        const val EXTRA_APP_UID: String = "io.virtualapp.settings.extra.PERMISSION_MANAGE_APP_UID"
        const val EXTRA_PERMISSIONS_TYPE: String =
            "io.virtualapp.settings.extra.PERMISSION_MANAGE_PERMISSIONS_TYPE"
    }
}
