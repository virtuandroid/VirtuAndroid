package io.virtualapp.settings

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreference
import com.android.launcher3.LauncherFiles
import com.lody.virtual.client.ipc.VirtualSettingsManager
import com.lody.virtual.server.IVirtualSettingsManager.ACTION_KILL_APP
import com.lody.virtual.server.IVirtualSettingsManager.ACTION_LOG_ONLY
import com.lody.virtual.server.IVirtualSettingsManager.ACTION_TOAST
import com.lody.virtual.server.IVirtualSettingsManager.POLICY_NONE
import com.lody.virtual.server.IVirtualSettingsManager.POLICY_STRICT_HARDENING
import com.lody.virtual.server.IVirtualSettingsManager.POLICY_TRANSPARENT_HARDENING
import io.virtualapp.R
import io.virtualapp.VCommends
import io.virtualapp.abs.ui.VActivity
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class SecuritySettingsActivity : VActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (savedInstanceState == null) {
            supportFragmentManager
                .beginTransaction()
                .replace(android.R.id.content, AdvancedSettingsFragment())
                .commit()
        }
    }

    class AdvancedSettingsFragment : PreferenceFragmentCompat() {
        private data class SecurityPolicy(
            val seccompEnabled: Boolean,
            val fingerprintAction: Int,
            val dangerousAction: Int,
            val permissionBypassAction: Int,
            val servicePolicy: Int,
        ) {
            fun save(): Boolean = with(VirtualSettingsManager.get()) {
                listOf(
                    setSeccompEnabled(seccompEnabled),
                    setFingerprintLogAction(fingerprintAction),
                    setDangerousGuestAction(dangerousAction),
                    setServicePolicy(servicePolicy),
                    setPermissionBypassPolicy(permissionBypassAction),
                ).all { it }
            }

            companion object {
                fun load() = with(VirtualSettingsManager.get()) {
                    SecurityPolicy(
                        seccompEnabled = getSeccompEnabled(),
                        fingerprintAction = getFingerprintLogAction(),
                        dangerousAction = getDangerousGuestAction(),
                        servicePolicy = getServicePolicy(),
                        permissionBypassAction = getPermissionBypassPolicy()
                    )
                }
            }
        }

        // Values must match R.array.general_hardening_policy_values
        private enum class GeneralPolicy(val value: Int, val preset: SecurityPolicy?) {
            Custom(-1, null),
            None(
                0,
                SecurityPolicy(
                    false,
                    ACTION_LOG_ONLY,
                    ACTION_LOG_ONLY,
                    ACTION_LOG_ONLY,
                    POLICY_NONE
                )
            ),
            TransparentHardening(
                1,
                SecurityPolicy(
                    true,
                    ACTION_KILL_APP,
                    ACTION_LOG_ONLY,
                    ACTION_TOAST,
                    POLICY_TRANSPARENT_HARDENING
                )
            ),
            StrictHardening(
                2,
                SecurityPolicy(
                    true,
                    ACTION_KILL_APP,
                    ACTION_KILL_APP,
                    ACTION_KILL_APP,
                    POLICY_STRICT_HARDENING
                )
            );

            companion object {
                fun fromValue(value: Any?): GeneralPolicy? {
                    val int = (value as? Int) ?: (value as? String)?.toIntOrNull()
                    return entries.firstOrNull { it.value == int }
                }

                /** The preset equal to [policy], or Custom if none match. */
                fun matching(policy: SecurityPolicy) =
                    entries.firstOrNull { it.preset == policy } ?: Custom
            }
        }

        /** What the screen shows. `mode` is stored explicitly so Custom stays Custom
         *  even if the user's edits happen to equal a preset. */
        private data class UiState(val mode: GeneralPolicy, val policy: SecurityPolicy)

        private val state: MutableStateFlow<UiState> = MutableStateFlow(loadState())
        private lateinit var generalPolicy: ListPreference
        private lateinit var seccomp: SwitchPreference
        private lateinit var fingerprintAction: ListPreference
        private lateinit var dangerousAction: ListPreference
        private lateinit var servicePolicy: ListPreference
        private lateinit var permissionBypassAction: ListPreference

        private fun loadState(): UiState {
            val policy = SecurityPolicy.load()
            return UiState(GeneralPolicy.matching(policy), policy)
        }


        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            preferenceManager.setSharedPreferencesName(LauncherFiles.SHARED_PREFERENCES_KEY)
            addPreferencesFromResource(R.xml.security_settings_preferences)

            generalPolicy = findPreference(GENERAL_POLICY)!!
            seccomp = findPreference(ENABLE_SECCOMP)!!
            fingerprintAction = findPreference(FINGERPRINT_INCONSISTENT)!!
            dangerousAction = findPreference(DANGEROUS_ACTION)!!
            servicePolicy = findPreference(SERVICE_POLICY)!!
            permissionBypassAction = findPreference(PERMISSION_ACTION)!!

            generalPolicy.onUserChange { value ->
                GeneralPolicy.fromValue(value)?.let(::selectMode)
            }
            seccomp.onUserChange { value -> (value as? Boolean)?.let { edit { copy(seccompEnabled = it) } } }
            fingerprintAction.onUserChange { value ->
                value.convertToInt()?.let { edit { copy(fingerprintAction = it) } }
            }
            dangerousAction.onUserChange { value ->
                value.convertToInt()?.let { edit { copy(dangerousAction = it) } }
            }
            servicePolicy.onUserChange { value ->
                value.convertToInt()?.let { edit { copy(servicePolicy = it) } }
            }
            permissionBypassAction.onUserChange { value ->
                value.convertToInt()?.let { edit { copy(permissionBypassAction = it) } }
            }

            lifecycleScope.launch {
                repeatOnLifecycle(Lifecycle.State.STARTED) {
                    state.collect(::render)
                }
            }
        }

        private fun selectMode(mode: GeneralPolicy) {
            mode.preset?.save()  // Custom keeps the current values and just unlocks editing
            // Re-read from the manager so the UI always shows what was really stored.
            state.value = UiState(mode, SecurityPolicy.load())
        }

        private fun edit(change: SecurityPolicy.() -> SecurityPolicy) {
            val currentPolicy = state.value
            currentPolicy.policy.change().save()

            // a failed write reverts visibly
            state.update {
                val newPolicy = SecurityPolicy.load()
                //  If something fails then change to a custom mode to indicate that it is custom
                if (currentPolicy.mode != GeneralPolicy.Custom && GeneralPolicy.matching(newPolicy) == GeneralPolicy.Custom) {
                    it.copy(policy = newPolicy, mode = GeneralPolicy.Custom)
                } else {
                    it.copy(policy = newPolicy)
                }
            }
        }

        private fun render(ui: UiState) {
            val custom = ui.mode == GeneralPolicy.Custom

            generalPolicy.value = ui.mode.value.toString()

            seccomp.isChecked = ui.policy.seccompEnabled
            // Seccomp implementation isn't supported on Android 10 and below
            seccomp.isEnabled = custom && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

            fingerprintAction.value = ui.policy.fingerprintAction.toString()
            permissionBypassAction.value = ui.policy.permissionBypassAction.toString()

            dangerousAction.value = ui.policy.dangerousAction.toString()
            dangerousAction.isEnabled = custom

            // Dangerous logs include fingerprint inconsistencies
            val dangerousLogKills = ui.policy.dangerousAction == ACTION_KILL_APP
            fingerprintAction.isEnabled = !dangerousLogKills && custom
            permissionBypassAction.isEnabled = !dangerousLogKills && custom

            servicePolicy.value = ui.policy.servicePolicy.toString()
            servicePolicy.isEnabled = custom

        }

        private fun Preference.onUserChange(handler: (Any?) -> Unit) {
            setOnPreferenceChangeListener { _, newValue ->
                handler(newValue)
                false  // don't let the preference update itself, render() does it from state
            }
        }

        private fun Any?.convertToInt(): Int? = (this as? Int) ?: (this as? String)?.toIntOrNull()

        override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {}

        override fun startActivity(intent: Intent?) {
            try {
                super.startActivity(intent)
            } catch (ignored: Throwable) {
                Toast.makeText(activity, "startActivity failed.", Toast.LENGTH_SHORT).show()
                ignored.printStackTrace()
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VCommends.REQUEST_SELECT_APP && resultCode == RESULT_OK) {
            finish()
        }
    }

    companion object {
        private const val GENERAL_POLICY = "advance_settings_general_policy"

        private const val ENABLE_SECCOMP = "security_settings_enable_seccomp"
        private const val FINGERPRINT_INCONSISTENT = "advance_settings_fingerprint_action"
        private const val DANGEROUS_ACTION = "advance_settings_dangerous_action"
        private const val PERMISSION_ACTION = "advance_settings_permission_action"

        private const val SERVICE_POLICY = "advance_settings_service_policy"
    }
}