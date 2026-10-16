package ed.vault;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.text.TextUtils;
import android.util.Base64;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.Consumer;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Single-screen notes app. Each note can be locked with its own PIN.
 * Locked notes: body is AES-256-GCM encrypted with a key derived from the PIN
 * (PBKDF2-HMAC-SHA256). Titles stay readable so the list can show them.
 * Everything lives in the app's private storage; no network permission.
 */
public class MainActivity extends Activity {
    static final int ITER = 150_000;
    static final int MIN_PIN = 4;
    static final SecureRandom RNG = new SecureRandom();

    static class Note {
        String id, title = "", body = "";
        long updated;
        byte[] salt, iv, ct;
        boolean locked() { return salt != null; }
    }

    final Handler ui = new Handler(Looper.getMainLooper());
    File dir;
    FrameLayout root;
    int pad;

    // Editor state. Invariant while editing: cur.locked() == (key != null)
    Note cur;
    SecretKey key;
    EditText titleEt, bodyEt;
    Button lockBtn;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        // Keep note contents out of screenshots and the recents preview
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        pad = dp(16);
        dir = new File(getFilesDir(), "notes");
        dir.mkdirs();
        root = new FrameLayout(this);
        root.setOnApplyWindowInsetsListener((v, in) -> {
            Insets i = in.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.ime());
            v.setPadding(i.left, i.top, i.right, i.bottom);
            return WindowInsets.CONSUMED;
        });
        setContentView(root);
        showList();
    }

    @Override
    protected void onPause() {
        super.onPause();
        save();
    }

    @Override
    protected void onStop() {
        super.onStop();
        // Re-lock a PIN note whenever the app leaves the screen
        if (cur != null && key != null) showList();
    }

    @Override
    public void onBackPressed() {
        if (cur != null) {
            save();
            hideKeyboard();
            showList();
        } else {
            super.onBackPressed();
        }
    }

    // ---------- List screen ----------

    void showList() {
        cur = null;
        key = null;
        titleEt = bodyEt = null;
        lockBtn = null;

        LinearLayout col = vbox();
        LinearLayout bar = hbox();
        bar.setPadding(pad, dp(8), dp(8), dp(8));
        TextView h = text("Notes", 26);
        h.setTypeface(Typeface.DEFAULT_BOLD);
        bar.addView(h, new LinearLayout.LayoutParams(0, -2, 1));
        Button add = button("+ New");
        add.setOnClickListener(v -> openEditor(new Note()));
        bar.addView(add);
        col.addView(bar);

        LinearLayout list = vbox();
        List<Note> notes = loadAll();
        if (notes.isEmpty()) {
            TextView empty = text("No notes yet. Tap + New.", 16);
            empty.setAlpha(0.6f);
            empty.setPadding(pad, dp(24), pad, 0);
            list.addView(empty);
        }
        DateFormat df = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT);
        for (Note n : notes) {
            LinearLayout row = vbox();
            row.setPadding(pad, dp(12), pad, dp(12));
            row.setBackgroundResource(attrRes(android.R.attr.selectableItemBackground));
            TextView t = text((n.locked() ? "🔒 " : "") + (n.title.isEmpty() ? "Untitled" : n.title), 18);
            t.setSingleLine(true);
            t.setEllipsize(TextUtils.TruncateAt.END);
            row.addView(t);
            TextView d = text(df.format(new Date(n.updated)), 13);
            d.setAlpha(0.6f);
            row.addView(d);
            row.setOnClickListener(v -> open(n));
            row.setOnLongClickListener(v -> { confirmDelete(n); return true; });
            list.addView(row);
        }
        ScrollView sv = new ScrollView(this);
        sv.addView(list);
        col.addView(sv, new LinearLayout.LayoutParams(-1, 0, 1));
        swap(col);
    }

    void open(Note n) {
        if (!n.locked()) { openEditor(n); return; }
        askPin("Enter PIN", false, pin -> work("Unlocking…", () -> {
            SecretKey k = derive(pin, n.salt);
            String body = dec(k, n.iv, n.ct);
            return () -> { n.body = body; key = k; openEditor(n); };
        }));
    }

    void confirmDelete(Note n) {
        Runnable del = () -> {
            new File(dir, n.id + ".json").delete();
            showList();
        };
        new AlertDialog.Builder(this)
                .setTitle("Delete note?")
                .setMessage(n.title.isEmpty() ? "Untitled" : n.title)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Delete", (d, w) -> {
                    if (!n.locked()) { del.run(); return; }
                    askPin("PIN to delete", false, pin -> work("Checking…", () -> {
                        dec(derive(pin, n.salt), n.iv, n.ct); // throws if wrong
                        return del;
                    }));
                })
                .show();
    }

    // ---------- Editor screen ----------

    void openEditor(Note n) {
        cur = n;
        LinearLayout col = vbox();

        LinearLayout bar = hbox();
        bar.setPadding(dp(4), dp(4), dp(8), dp(4));
        Button back = button("‹ Notes");
        back.setOnClickListener(v -> onBackPressed());
        bar.addView(back);
        bar.addView(new View(this), new LinearLayout.LayoutParams(0, 1, 1));
        lockBtn = button("");
        lockBtn.setOnClickListener(v -> lockMenu());
        bar.addView(lockBtn);
        col.addView(bar);
        updateLockBtn();

        titleEt = new EditText(this);
        titleEt.setHint("Title");
        titleEt.setSingleLine(true);
        titleEt.setTextSize(22);
        titleEt.setTypeface(Typeface.DEFAULT_BOLD);
        titleEt.setBackground(null);
        titleEt.setPadding(pad, dp(8), pad, dp(8));
        titleEt.setImeOptions(EditorInfo.IME_ACTION_NEXT);
        titleEt.setText(n.title);
        col.addView(titleEt);

        bodyEt = new EditText(this);
        bodyEt.setHint("Write something…");
        bodyEt.setGravity(Gravity.TOP | Gravity.START);
        bodyEt.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);
        bodyEt.setTextSize(17);
        bodyEt.setBackground(null);
        bodyEt.setPadding(pad, dp(4), pad, pad);
        bodyEt.setText(n.body);
        col.addView(bodyEt, new LinearLayout.LayoutParams(-1, 0, 1));

        swap(col);
        if (n.id == null) {
            bodyEt.requestFocus();
            bodyEt.post(() -> getSystemService(InputMethodManager.class)
                    .showSoftInput(bodyEt, InputMethodManager.SHOW_IMPLICIT));
        }
    }

    void updateLockBtn() {
        if (lockBtn != null) lockBtn.setText(cur.locked() ? "🔒 PIN" : "Lock");
    }

    void lockMenu() {
        if (!cur.locked()) { setNewPin("Set a PIN"); return; }
        new AlertDialog.Builder(this)
                .setItems(new String[]{"Change PIN", "Remove PIN"}, (d, w) -> {
                    if (w == 0) {
                        setNewPin("New PIN");
                    } else {
                        key = null;
                        cur.salt = cur.iv = cur.ct = null;
                        persist(true);
                        updateLockBtn();
                        toast("PIN removed");
                    }
                })
                .show();
    }

    void setNewPin(String title) {
        askPin(title, true, pin -> work("Locking…", () -> {
            byte[] salt = rand(16);
            SecretKey k = derive(pin, salt);
            return () -> {
                key = k;
                cur.salt = salt;
                persist(true);
                updateLockBtn();
                toast("Locked");
            };
        }));
    }

    void save() { persist(false); }

    /** Writes the open note to disk if it changed (or always, if force). */
    void persist(boolean force) {
        if (cur == null || titleEt == null) return;
        String t = titleEt.getText().toString();
        String b = bodyEt.getText().toString();
        if (cur.id == null && t.isEmpty() && b.isEmpty() && !cur.locked()) return;
        if (!force && cur.id != null && t.equals(cur.title) && b.equals(cur.body)) return;
        cur.title = t;
        cur.body = b;
        cur.updated = System.currentTimeMillis();
        if (cur.id == null) cur.id = Long.toString(cur.updated, 36) + Integer.toString(RNG.nextInt(1 << 20), 36);
        try {
            JSONObject o = new JSONObject();
            o.put("t", t);
            o.put("u", cur.updated);
            if (key != null) {
                cur.iv = rand(12);
                cur.ct = enc(key, cur.iv, b);
                o.put("s", b64(cur.salt));
                o.put("i", b64(cur.iv));
                o.put("c", b64(cur.ct));
            } else {
                o.put("b", b);
            }
            File tmp = new File(dir, cur.id + ".tmp");
            try (FileOutputStream fo = new FileOutputStream(tmp)) {
                fo.write(o.toString().getBytes(StandardCharsets.UTF_8));
                fo.getFD().sync();
            }
            tmp.renameTo(new File(dir, cur.id + ".json"));
        } catch (Exception e) {
            toast("Save failed: " + e.getMessage());
        }
    }

    // ---------- Storage ----------

    List<Note> loadAll() {
        List<Note> out = new ArrayList<>();
        File[] files = dir.listFiles((d, name) -> name.endsWith(".json"));
        if (files == null) return out;
        for (File f : files) {
            try {
                byte[] raw = new byte[(int) f.length()];
                try (FileInputStream in = new FileInputStream(f)) {
                    int off = 0;
                    while (off < raw.length) {
                        int r = in.read(raw, off, raw.length - off);
                        if (r < 0) break;
                        off += r;
                    }
                }
                JSONObject o = new JSONObject(new String(raw, StandardCharsets.UTF_8));
                Note n = new Note();
                n.id = f.getName().substring(0, f.getName().length() - 5);
                n.title = o.optString("t");
                n.updated = o.optLong("u");
                if (o.has("s")) {
                    n.salt = unb64(o.getString("s"));
                    n.iv = unb64(o.getString("i"));
                    n.ct = unb64(o.getString("c"));
                } else {
                    n.body = o.optString("b");
                }
                out.add(n);
            } catch (Exception ignored) {
            }
        }
        out.sort((a, b) -> Long.compare(b.updated, a.updated));
        return out;
    }

    // ---------- Crypto ----------

    static SecretKey derive(String pin, byte[] salt) throws Exception {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] k = f.generateSecret(new PBEKeySpec(pin.toCharArray(), salt, ITER, 256)).getEncoded();
        return new SecretKeySpec(k, "AES");
    }

    static byte[] enc(SecretKey k, byte[] iv, String s) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(128, iv));
        return c.doFinal(s.getBytes(StandardCharsets.UTF_8));
    }

    static String dec(SecretKey k, byte[] iv, byte[] ct) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, iv));
        return new String(c.doFinal(ct), StandardCharsets.UTF_8);
    }

    static byte[] rand(int n) { byte[] b = new byte[n]; RNG.nextBytes(b); return b; }
    static String b64(byte[] b) { return Base64.encodeToString(b, Base64.NO_WRAP); }
    static byte[] unb64(String s) { return Base64.decode(s, Base64.NO_WRAP); }

    // ---------- Dialog + background helpers ----------

    interface Job { Runnable run() throws Exception; }

    /** Runs slow key derivation off the main thread; posts the result back. */
    void work(String msg, Job job) {
        Toast t = Toast.makeText(this, msg, Toast.LENGTH_SHORT);
        t.show();
        new Thread(() -> {
            try {
                Runnable then = job.run();
                ui.post(() -> { t.cancel(); then.run(); });
            } catch (Exception e) {
                ui.post(() -> { t.cancel(); toast("Wrong PIN"); });
            }
        }).start();
    }

    void askPin(String title, boolean confirm, Consumer<String> cb) {
        LinearLayout box = vbox();
        box.setPadding(dp(24), dp(8), dp(24), 0);
        EditText p1 = pinField("PIN");
        EditText p2 = confirm ? pinField("Confirm PIN") : null;
        box.addView(p1);
        if (p2 != null) box.addView(p2);

        AlertDialog d = new AlertDialog.Builder(this)
                .setTitle(title)
                .setView(box)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("OK", null)
                .create();
        d.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE);
        d.setOnShowListener(x -> {
            Button ok = d.getButton(AlertDialog.BUTTON_POSITIVE);
            ok.setOnClickListener(v -> {
                String a = p1.getText().toString();
                if (a.length() < MIN_PIN) { p1.setError("At least " + MIN_PIN + " digits"); return; }
                if (p2 != null && !a.equals(p2.getText().toString())) { p2.setError("PINs don't match"); return; }
                d.dismiss();
                cb.accept(a);
            });
            EditText last = p2 != null ? p2 : p1;
            last.setOnEditorActionListener((v, id, e) -> { ok.performClick(); return true; });
            p1.requestFocus();
        });
        d.show();
    }

    EditText pinField(String hint) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        e.setImeOptions(EditorInfo.IME_ACTION_DONE);
        e.setSingleLine(true);
        return e;
    }

    // ---------- Tiny view helpers ----------

    void swap(View v) {
        root.removeAllViews();
        root.addView(v, new FrameLayout.LayoutParams(-1, -1));
    }

    LinearLayout vbox() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.VERTICAL); return l; }

    LinearLayout hbox() {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.HORIZONTAL);
        l.setGravity(Gravity.CENTER_VERTICAL);
        return l;
    }

    TextView text(String s, float sp) { TextView t = new TextView(this); t.setText(s); t.setTextSize(sp); return t; }

    Button button(String s) {
        Button b = new Button(this, null, android.R.attr.borderlessButtonStyle);
        b.setText(s);
        b.setAllCaps(false);
        b.setTextSize(16);
        return b;
    }

    int attrRes(int attr) {
        TypedArray a = obtainStyledAttributes(new int[]{attr});
        int r = a.getResourceId(0, 0);
        a.recycle();
        return r;
    }

    int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    void toast(String s) { Toast.makeText(this, s, Toast.LENGTH_SHORT).show(); }

    void hideKeyboard() {
        View f = getCurrentFocus();
        if (f != null) getSystemService(InputMethodManager.class).hideSoftInputFromWindow(f.getWindowToken(), 0);
    }
}
