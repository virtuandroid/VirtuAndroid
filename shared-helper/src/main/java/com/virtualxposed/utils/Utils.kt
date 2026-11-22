package com.virtualxposed.utils

import android.os.Build
import android.os.Parcel
import android.os.Parcelable
import kotlin.jvm.java

object Utils {
    inline fun <reified T : Parcelable> Parcel.readParcelableSafe(): T? {
        val classLoader = Utils.javaClass.classLoader
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            this.readParcelable(classLoader, T::class.java)
        } else {
            @Suppress("DEPRECATION")
            this.readParcelable<T>(classLoader)
        }
    }
}