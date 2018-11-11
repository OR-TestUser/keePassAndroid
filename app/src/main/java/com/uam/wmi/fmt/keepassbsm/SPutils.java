package com.uam.wmi.fmt.keepassbsm;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashMap;
import java.util.Map;

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

    static void putKeyValue(Context context, String key, String value) {
        SharedPreferences.Editor editor = getSharedPreferences(context).edit();
        editor.putString(key, value);
        editor.apply();
    }


    static boolean keyStoreSaved(Context context) {
        SharedPreferences preferences = getSharedPreferences(context);

        return preferences.getBoolean("keyStore", false);
    }

    static void purgeUserLocalStorage(Context context) {
        SharedPreferences preferences = getSharedPreferences(context);
        SharedPreferences.Editor editor = preferences.edit();
        editor.clear().apply();
    }


    public static String getString(Context context, String key) {

        return getSharedPreferences(context).getString(key, "");
    }
}
