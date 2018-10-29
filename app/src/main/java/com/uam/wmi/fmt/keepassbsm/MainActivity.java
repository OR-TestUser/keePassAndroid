package com.uam.wmi.fmt.keepassbsm;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;


public class MainActivity extends AppCompatActivity {

    String tag = getClass().getName();


    TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
                finish();
            }
        });




        textView = findViewById(R.id.MSGeditText);
        Button saveButton =  findViewById(R.id.saveButton);


        saveButton.setOnClickListener(view -> encryptMsg());
    }


    private void encryptMsg() {

        String txt = textView.getText().toString();
        Log.e(tag, txt);
    }
}
