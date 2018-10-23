package com.uam.wmi.fmt.keepassbsm;

import android.content.Context;
import android.content.SharedPreferences;

public class SPutils {

    public SPutils() {
    }

    private static SharedPreferences getSharedPreferences(Context context) {
        return context.getSharedPreferences("keePassAndroidPrefs", Context.MODE_PRIVATE);
    }

    static void keyStoreInit(Context context) {
        SharedPreferences.Editor editor = getSharedPreferences(context).edit();
        editor.putBoolean("keyStore", true);
        editor.apply();
    }

    static boolean keyStoreSaved(Context context) {
        SharedPreferences preferences = getSharedPreferences(context);

        return preferences.getBoolean("keyStore", true);
    }

    static void purgeUserLocalStorage(Context context) {
        SharedPreferences preferences = getSharedPreferences(context);
        SharedPreferences.Editor editor = preferences.edit();
        editor.clear().apply();
    }
}
