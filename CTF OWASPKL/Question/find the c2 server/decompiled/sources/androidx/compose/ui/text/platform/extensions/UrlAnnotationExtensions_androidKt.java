package androidx.compose.ui.text.platform.extensions;

import android.text.style.URLSpan;
import androidx.compose.ui.text.UrlAnnotation;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: UrlAnnotationExtensions.android.kt */
@Metadata(d1 = {"\u0000\f\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u001a\f\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0007¨\u0006\u0003"}, d2 = {"toSpan", "Landroid/text/style/URLSpan;", "Landroidx/compose/ui/text/UrlAnnotation;", "ui-text_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class UrlAnnotationExtensions_androidKt {
    public static final URLSpan toSpan(UrlAnnotation $this$toSpan) {
        Intrinsics.checkNotNullParameter($this$toSpan, "<this>");
        return new URLSpan($this$toSpan.getUrl());
    }
}
