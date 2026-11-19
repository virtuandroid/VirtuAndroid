package io.virtualapp.settings

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreference
import com.android.launcher3.LauncherFiles
import com.virtualxposed.log.client.VLoggingClient
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

            setupFileFlagPreference(DISABLE_SECCOMP, ".disable_seccomp")


            val fingerprint = findPreference<ListPreference>(FINGERPRINT_INCONSISTENT)
            fingerprint?.value = VLoggingClient.get().getFingerprintAction()?.toString()
            fingerprint?.onPreferenceChangeListener =
                Preference.OnPreferenceChangeListener { _, k ->
                    val key = (k as? Int) ?: (k as? String)?.toIntOrNull()
                    ?: return@OnPreferenceChangeListener false
                    val success = VLoggingClient.get().setFingerprintAction(key)
                    return@OnPreferenceChangeListener success
                }


            val dangerousAction = findPreference<ListPreference>(DANGEROUS_ACTION)
            dangerousAction?.value = VLoggingClient.get().getDangerousGuestAction()?.toString()
            dangerousAction?.onPreferenceChangeListener =
                Preference.OnPreferenceChangeListener { _, k ->
                    val key = (k as? Int) ?: (k as? String)?.toIntOrNull()
                    ?: return@OnPreferenceChangeListener false
                    val success = VLoggingClient.get().setDangerousGuestAction(key)
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
        private const val DISABLE_SECCOMP = "security_settings_disable_seccomp"
        private const val FINGERPRINT_INCONSISTENT = "advance_settings_fingerprint_action"
        private const val DANGEROUS_ACTION = "advance_settings_dangerous_action"
    }
}