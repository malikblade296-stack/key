package com.xyz.app;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * INRI Proxy authorization gate.
 *
 * Normal launch: shows "Waiting for authorization from INRI".
 * Dashboard "Connect INRI Proxy": opens inri://auth?ticket=... (or onNewIntent while
 * this screen is already open), the ticket is redeemed with the device HWID, then
 * MainActivity opens.
 */
public class LoginActivity extends Activity {

    // Change this if the site moves.
    private static final String BASE_URL = "https://fuck-production-6e8d4c9c.up.railway.app";
    private static final String PREFS = "inri_auth";

    private static final int BG = Color.rgb(6, 10, 17);
    private static final int TEXT = Color.rgb(232, 238, 251);
    private static final int MUTED = Color.rgb(148, 163, 184);
    private static final int ACCENT = Color.rgb(94, 234, 212);
    private static final int BAD = Color.rgb(251, 113, 133);
    private static final int OK = Color.rgb(52, 211, 153);

    private final Handler handler = new Handler(Looper.getMainLooper());
    private TextView statusView;
    private TextView hintView;
    private ProgressBar progress;
    private Button actionButton;
    private String activeTicket;
    private boolean finished;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildUi());
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    @Override
    public void onBackPressed() {
        moveTaskToBack(true);
    }

    private void handleIntent(Intent intent) {
        String ticket = null;
        if (intent != null) {
            Uri data = intent.getData();
            if (data != null && "inri".equals(data.getScheme())) {
                ticket = data.getQueryParameter("ticket");
            }
            if (TextUtils.isEmpty(ticket)) {
                ticket = intent.getStringExtra("ticket");
            }
        }
        if (!TextUtils.isEmpty(ticket)) {
            activeTicket = ticket;
            authorize(ticket);
        } else {
            showWaiting();
        }
    }

    private void showWaiting() {
        progress.setVisibility(View.VISIBLE);
        statusView.setTextColor(TEXT);
        statusView.setText("Waiting for authorization from INRI");
        hintView.setText(
            "Open the INRI Proxy dashboard in your browser, enter your key and tap "
                + "\"Connect INRI Proxy\". This screen will authorize automatically.");
        actionButton.setText("Open INRI dashboard");
        actionButton.setEnabled(true);
    }

    private void showWorking() {
        progress.setVisibility(View.VISIBLE);
        statusView.setTextColor(TEXT);
        statusView.setText("Authorizing…");
        hintView.setText("Checking this key with INRI. Keep the app open.");
        actionButton.setEnabled(false);
    }

    private void showError(String message) {
        progress.setVisibility(View.GONE);
        statusView.setTextColor(BAD);
        statusView.setText("Authorization failed");
        hintView.setText(message);
        actionButton.setText("Try again");
        actionButton.setEnabled(true);
    }

    private void showSuccess() {
        progress.setVisibility(View.GONE);
        statusView.setTextColor(OK);
        statusView.setText("Authorization success");
        hintView.setText("Opening INRI Proxy…");
        actionButton.setEnabled(false);
    }

    private void authorize(final String ticket) {
        showWorking();
        new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        String error = null;
                        JSONObject result = null;
                        HttpURLConnection connection = null;
                        try {
                            URL url = new URL(BASE_URL + "/api/app/authorize");
                            connection = (HttpURLConnection) url.openConnection();
                            connection.setRequestMethod("POST");
                            connection.setConnectTimeout(12000);
                            connection.setReadTimeout(15000);
                            connection.setDoOutput(true);
                            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                            connection.setRequestProperty("Accept", "application/json");

                            JSONObject body = new JSONObject();
                            body.put("ticket", ticket);
                            body.put("hwid", deviceId());
                            byte[] payload = body.toString().getBytes(StandardCharsets.UTF_8);
                            connection.setFixedLengthStreamingMode(payload.length);
                            OutputStream out = connection.getOutputStream();
                            try {
                                out.write(payload);
                            } finally {
                                out.close();
                            }

                            int code = connection.getResponseCode();
                            InputStream stream =
                                    code >= 200 && code < 300
                                            ? connection.getInputStream()
                                            : connection.getErrorStream();
                            String text = readAll(stream);
                            result = new JSONObject(TextUtils.isEmpty(text) ? "{}" : text);
                            if (code < 200 || code >= 300 || !result.optBoolean("ok", false)) {
                                error = result.optString("error", "Authorization failed.");
                            }
                        } catch (Exception e) {
                            error = "Cannot reach INRI. Check your internet connection and try again.";
                        } finally {
                            if (connection != null) connection.disconnect();
                        }

                        final String failure = error;
                        final JSONObject payload = result;
                        handler.post(
                                new Runnable() {
                                    @Override
                                    public void run() {
                                        if (failure == null) {
                                            saveAuthorization(payload);
                                            showSuccess();
                                            handler.postDelayed(
                                                    new Runnable() {
                                                        @Override
                                                        public void run() {
                                                            openMain();
                                                        }
                                                    },
                                                    1200);
                                        } else {
                                            showError(failure);
                                        }
                                    }
                                });
                    }
                },
                "inri-authorize")
                .start();
    }

    private void saveAuthorization(JSONObject payload) {
        if (payload == null) return;
        SharedPreferences.Editor editor =
                getSharedPreferences(PREFS, MODE_PRIVATE)
                        .edit()
                        .putBoolean("authorized", true)
                        .putString("key", payload.optString("key", ""))
                        .putLong("expires_at", payload.optLong("expires_at", 0))
                        .putString("hwid", deviceId());
        editor.apply();
    }

    private void openMain() {
        if (finished) return;
        finished = true;
        Intent intent = new Intent(this, MainActivity.class);
        intent.putExtra("inri_authorized", true);
        startActivity(intent);
        finish();
    }

    private String deviceId() {
        String androidId =
                Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
        if (androidId == null) androidId = Build.FINGERPRINT;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash =
                    digest.digest((androidId + "|com.xyz.app").getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder();
            for (byte value : hash) {
                builder.append(String.format("%02x", value & 0xff));
            }
            return builder.toString();
        } catch (Exception e) {
            return androidId;
        }
    }

    private String readAll(InputStream stream) throws Exception {
        if (stream == null) return "";
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int read;
        try {
            while ((read = stream.read(chunk)) != -1) {
                buffer.write(chunk, 0, read);
            }
        } finally {
            stream.close();
        }
        return buffer.toString("UTF-8");
    }

    private int dp(int value) {
        return Math.round(
                TypedValue.applyDimension(
                        TypedValue.COMPLEX_UNIT_DIP, value, getResources().getDisplayMetrics()));
    }

    private LinearLayout buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setBackgroundColor(BG);
        root.setPadding(dp(28), dp(32), dp(28), dp(32));

        TextView eyebrow = new TextView(this);
        eyebrow.setText("INRI PROXY");
        eyebrow.setTextColor(ACCENT);
        eyebrow.setTextSize(12);
        eyebrow.setTypeface(Typeface.DEFAULT_BOLD);
        if (Build.VERSION.SDK_INT >= 21) {
            eyebrow.setLetterSpacing(0.18f);
        }
        root.addView(eyebrow, wrap());

        TextView title = new TextView(this);
        title.setText("App authorization");
        title.setTextColor(TEXT);
        title.setTextSize(28);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setPadding(0, dp(8), 0, dp(10));
        root.addView(title, wrap());

        statusView = new TextView(this);
        statusView.setText("Waiting for authorization from INRI");
        statusView.setTextColor(TEXT);
        statusView.setTextSize(18);
        statusView.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(statusView, wrap());

        hintView = new TextView(this);
        hintView.setTextColor(MUTED);
        hintView.setTextSize(14);
        hintView.setLineSpacing(dp(3), 1f);
        hintView.setPadding(0, dp(10), 0, dp(20));
        root.addView(hintView, wrap());

        progress = new ProgressBar(this);
        progress.setIndeterminate(true);
        if (Build.VERSION.SDK_INT >= 21) {
            progress.setIndeterminateTintList(ColorStateList.valueOf(ACCENT));
        }
        root.addView(progress, wrap());

        actionButton = new Button(this);
        actionButton.setText("Open INRI dashboard");
        actionButton.setAllCaps(false);
        actionButton.setTextColor(Color.rgb(5, 46, 43));
        actionButton.setTextSize(15);
        actionButton.setTypeface(Typeface.DEFAULT_BOLD);
        actionButton.setBackgroundColor(ACCENT);
        actionButton.setPadding(dp(20), dp(12), dp(20), dp(12));
        actionButton.setOnClickListener(
                new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        if (activeTicket != null) {
                            authorize(activeTicket);
                        } else {
                            openDashboard();
                        }
                    }
                });
        LinearLayout.LayoutParams buttonParams =
                new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        buttonParams.topMargin = dp(18);
        root.addView(actionButton, buttonParams);

        TextView footer = new TextView(this);
        footer.setText("Your key is checked on the INRI server. This device is locked on first authorization.");
        footer.setTextColor(MUTED);
        footer.setTextSize(11);
        footer.setGravity(Gravity.CENTER);
        footer.setPadding(0, dp(22), 0, 0);
        root.addView(footer, wrap());

        return root;
    }

    private LinearLayout.LayoutParams wrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private void openDashboard() {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(BASE_URL + "/")));
        } catch (Exception ignored) {
        }
    }
}
