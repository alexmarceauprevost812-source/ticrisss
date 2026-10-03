package com.tilex.audit;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.Toast;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Lecteur de rapports locaux, à intégrer dans un projet Android Java. */
public class AuditReportActivity extends Activity {
    private WebView viewer;
    private static final int OPEN_REPORT = 42;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        Button open = new Button(this);
        open.setText("Ouvrir un rapport JSON TI-LEX");
        viewer = new WebView(this);
        viewer.getSettings().setJavaScriptEnabled(false);
        viewer.getSettings().setAllowFileAccess(false);
        viewer.getSettings().setAllowContentAccess(false);
        viewer.getSettings().setBlockNetworkLoads(true);
        layout.addView(open);
        layout.addView(viewer, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(layout);
        open.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*");
            startActivityForResult(intent, OPEN_REPORT);
        });
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != OPEN_REPORT || result != RESULT_OK || data == null || data.getData() == null) return;
        // Lecture bornée hors du thread de l'interface.
        new Thread(() -> {
            try (InputStream input = getContentResolver().openInputStream(data.getData());
                 ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
                if (input == null) throw new Exception("Fichier inaccessible");
                byte[] chunk = new byte[8192];
                int count;
                while ((count = input.read(chunk)) != -1) {
                    if (buffer.size() + count > 2_000_000) throw new Exception("Rapport trop volumineux");
                    buffer.write(chunk, 0, count);
                }
                JSONObject report = new JSONObject(new String(buffer.toByteArray(), StandardCharsets.UTF_8));
                if (!"ticrisss-Audit".equals(report.optString("tool"))) throw new Exception("Rapport TI-LEX attendu");
                String page = "<!doctype html><html lang='fr'><meta charset='utf-8'>"
                        + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                        + "<style>body{background:#101827;color:#edf2f7;font:16px sans-serif;padding:20px}"
                        + "pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>"
                        + "<h1>ticrisss</h1><p>Les observations nécessitent une vérification."
                        + " Un port ouvert ne prouve pas une faille.</p><pre>"
                        + escape(report.toString(2)) + "</pre></html>";
                runOnUiThread(() -> { if (!isFinishing() && !isDestroyed()) viewer.loadDataWithBaseURL(null, page, "text/html", "UTF-8", null); });
            } catch (Exception exception) {
                runOnUiThread(() -> { if (!isFinishing() && !isDestroyed()) Toast.makeText(this, "Impossible de lire ce rapport JSON TI-LEX (maximum 2 Mo).", Toast.LENGTH_LONG).show(); });
            }
        }).start();
    }

    @Override public void onDestroy() {
        viewer.destroy();
        super.onDestroy();
    }
}
