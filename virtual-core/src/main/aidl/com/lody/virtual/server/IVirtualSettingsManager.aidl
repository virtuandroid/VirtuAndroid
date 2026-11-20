package com.lody.virtual.server;

interface IVirtualSettingsManager {
    int getFingerprintLogAction();
    boolean setFingerprintLogAction(int action);

    int getDangerousGuestAction();
    boolean setDangerousGuestAction(int action);

    boolean getSeccompEnabled();
    boolean setSeccompEnabled(boolean Boolean);

    const int LOG_ONLY = 0;
    const int TOAST = 1;
    const int KILL_APP = 2;
}