package io.virtualapp.settings

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreference
import com.android.launcher3.LauncherFiles
import com.lody.virtual.client.ipc.VirtualSettingsManager
import io.virtualapp.VCommends
import io.virtualapp.abs.ui.VActivity
import java.io.IOException

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

        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            preferenceManager.setSharedPreferencesName(LauncherFiles.SHARED_PREFERENCES_KEY)
            addPreferencesFromResource(io.virtualapp.R.xml.security_settings_preferences)

            val seccomp = findPreference<SwitchPreference>(ENABLE_SECCOMP)

            // Make it clearly visible to the user that Android 10 and below
            // does not support the current seccomp implementation
            seccomp?.isEnabled = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

            seccomp?.isChecked = VirtualSettingsManager.get().getSeccompEnabled()
            seccomp?.onPreferenceChangeListener =
                Preference.OnPreferenceChangeListener { _, k ->
                    val change = k as? Boolean ?: return@OnPreferenceChangeListener false
                    val success = VirtualSettingsManager.get().setSeccompEnabled(change)
                    return@OnPreferenceChangeListener success
                }

            val fingerprint = findPreference<ListPreference>(FINGERPRINT_INCONSISTENT)
            fingerprint?.value = VirtualSettingsManager.get().getFingerprintLogAction().toString()
            fingerprint?.onPreferenceChangeListener =
                Preference.OnPreferenceChangeListener { _, k ->
                    val key = (k as? Int) ?: (k as? String)?.toIntOrNull()
                    ?: return@OnPreferenceChangeListener false
                    val success = VirtualSettingsManager.get().setFingerprintLogAction(key)
                    return@OnPreferenceChangeListener success
                }


            val dangerousAction = findPreference<ListPreference>(DANGEROUS_ACTION)
            dangerousAction?.value = VirtualSettingsManager.get().getDangerousGuestAction().toString()
            dangerousAction?.onPreferenceChangeListener =
                Preference.OnPreferenceChangeListener { _, k ->
                    val key = (k as? Int) ?: (k as? String)?.toIntOrNull()
                    ?: return@OnPreferenceChangeListener false
                    val success = VirtualSettingsManager.get().setDangerousGuestAction(key)
                    return@OnPreferenceChangeListener success
                }

            val servicePolicy = findPreference<ListPreference>(SERVICE_POLICY)
            servicePolicy?.value = VirtualSettingsManager.get().getServicePolicy().toString()
            servicePolicy?.onPreferenceChangeListener =
                Preference.OnPreferenceChangeListener { _, k ->
                    val key = (k as? Int) ?: (k as? String)?.toIntOrNull()
                    ?: return@OnPreferenceChangeListener false
                    val success = VirtualSettingsManager.get().setServicePolicy(key)
                    return@OnPreferenceChangeListener success
                }
        }

        override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {}

        override fun startActivity(intent: Intent?) {
            try {
                super.startActivity(intent)
            } catch (ignored: Throwable) {
                Toast.makeText(activity, "startActivity failed.", Toast.LENGTH_SHORT).show()
                ignored.printStackTrace()
            }
        }

        private fun setupFileFlagPreference(preferenceKey: String, fileName: String) {
            findPreference<SwitchPreference>(preferenceKey)?.onPreferenceChangeListener =
                Preference.OnPreferenceChangeListener { _, newValue ->
                    if (newValue !is Boolean) return@OnPreferenceChangeListener false

                    val flag = activity?.getFileStreamPath(fileName)
                        ?: return@OnPreferenceChangeListener false
                    if (newValue) {
                        try {
                            flag.createNewFile()
                        } catch (_: IOException) {
                            false
                        }
                    } else {
                        !flag.exists() || flag.delete()
                    }
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
        private const val ENABLE_SECCOMP = "security_settings_enable_seccomp"
        private const val FINGERPRINT_INCONSISTENT = "advance_settings_fingerprint_action"
        private const val DANGEROUS_ACTION = "advance_settings_dangerous_action"
        private const val SERVICE_POLICY = "advance_settings_service_policy"
    }
}