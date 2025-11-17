package com.bobof.shheissee;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private TextView statusText;
    private TextView totalAttacksText;
    private RecyclerView attacksRecycler;
    private AttackAdapter attackAdapter;
    private OkHttpClient client;
    private Handler handler;
    private Runnable updateRunnable;

    private String serverUrl = "http://192.168.1.100:8080"; // Change this to your server IP

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusText = findViewById(R.id.status_text);
        totalAttacksText = findViewById(R.id.total_attacks_text);
        attacksRecycler = findViewById(R.id.attacks_recycler);

        attackAdapter = new AttackAdapter();
        attacksRecycler.setLayoutManager(new LinearLayoutManager(this));
        attacksRecycler.setAdapter(attackAdapter);

        client = new OkHttpClient();
        handler = new Handler(Looper.getMainLooper());

        // Update every 5 seconds
        updateRunnable = new Runnable() {
            @Override
            public void run() {
                updateStatus();
                updateAttacks();
                handler.postDelayed(this, 5000);
            }
        };
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(updateRunnable);
    }

    @Override
    protected void onPause() {
        super.onPause();
        handler.removeCallbacks(updateRunnable);
    }

    private void updateStatus() {
        Request request = new Request.Builder()
                .url(serverUrl + "/api/status")
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                runOnUiThread(() -> {
                    statusText.setText("Status: Offline");
                    totalAttacksText.setText("Total Attacks: --");
                });
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try {
                    if (response.isSuccessful() && response.body() != null) {
                        JSONObject json = new JSONObject(response.body().string());
                        String status = json.optString("status", "Unknown");
                        int totalAttacks = json.optInt("total_attacks", 0);
                        runOnUiThread(() -> {
                            statusText.setText("Status: " + status);
                            totalAttacksText.setText(String.format("Total Attacks: %d", totalAttacks));
                        });
                    } else {
                        runOnUiThread(() -> {
                            statusText.setText("Status: Server Error");
                            totalAttacksText.setText("Total Attacks: --");
                        });
                    }
                } catch (JSONException e) {
                    runOnUiThread(() -> {
                        statusText.setText("Status: Parse Error");
                        totalAttacksText.setText("Total Attacks: --");
                    });
                } finally {
                    if (response != null && response.body() != null) {
                        response.body().close();
                    }
                }
            }
        });
    }

    private void updateAttacks() {
        Request request = new Request.Builder()
                .url(serverUrl + "/api/attacks?limit=20")
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                // Network failure - keep existing data
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try {
                    if (response.isSuccessful() && response.body() != null) {
                        JSONObject json = new JSONObject(response.body().string());
                        JSONArray attacksArray = json.optJSONArray("attacks");
                        if (attacksArray != null) {
                            List<Attack> attacks = new ArrayList<>();
                            for (int i = 0; i < attacksArray.length(); i++) {
                                JSONObject attackJson = attacksArray.optJSONObject(i);
                                if (attackJson != null) {
                                    Attack attack = new Attack();
                                    attack.setType(attackJson.optString("type", "Unknown"));
                                    attack.setDescription(attackJson.optString("description", "No description"));
                                    attack.setTimestamp(attackJson.optString("timestamp", ""));
                                    attacks.add(attack);
                                }
                            }
                            runOnUiThread(() -> attackAdapter.setAttacks(attacks));
                        }
                    }
                } catch (JSONException e) {
                    // JSON parsing error - keep existing data
                } finally {
                    if (response != null && response.body() != null) {
                        response.body().close();
                    }
                }
            }
        });
    }
}
