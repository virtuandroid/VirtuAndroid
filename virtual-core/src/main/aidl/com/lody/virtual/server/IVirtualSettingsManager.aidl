package com.lody.virtual.server;

interface IVirtualSettingsManager {
    const int ACTION_LOG_ONLY = 0;
    const int ACTION_TOAST = 1;
    const int ACTION_KILL_APP = 2;

    const int POLICY_NONE = 0;
    const int POLICY_TRANSPARENT_HARDENING = 1;
    const int POLICY_STRICT_HARDENING = 2;

    int getFingerprintLogAction();
    boolean setFingerprintLogAction(int action);

    int getDangerousGuestAction();
    boolean setDangerousGuestAction(int action);

    boolean getSeccompEnabled();
    boolean setSeccompEnabled(boolean enabled);

    int getServicePolicy();
    boolean setServicePolicy(int policy);
}