package androidx.compose.ui.draw;

import androidx.compose.ui.Modifier;
import androidx.compose.ui.graphics.GraphicsLayerModifierKt;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: Alpha.kt */
@Metadata(d1 = {"\u0000\f\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0000\u001a\u0014\u0010\u0000\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0000\u001a\u00020\u0002H\u0007¨\u0006\u0003"}, d2 = {"alpha", "Landroidx/compose/ui/Modifier;", "", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class AlphaKt {
    public static final Modifier alpha(Modifier $this$alpha, float alpha) {
        Intrinsics.checkNotNullParameter($this$alpha, "<this>");
        return !((alpha > 1.0f ? 1 : (alpha == 1.0f ? 0 : -1)) == 0) ? GraphicsLayerModifierKt.m2752graphicsLayerAp8cVGQ$default($this$alpha, 0.0f, 0.0f, alpha, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0L, null, true, null, 0L, 0L, 0, 126971, null) : $this$alpha;
    }
}
