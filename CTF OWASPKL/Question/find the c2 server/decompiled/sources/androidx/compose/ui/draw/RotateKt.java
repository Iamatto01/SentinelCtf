package androidx.compose.ui.draw;

import androidx.compose.ui.Modifier;
import androidx.compose.ui.graphics.GraphicsLayerModifierKt;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: Rotate.kt */
@Metadata(d1 = {"\u0000\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0000\u001a\u0014\u0010\u0000\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\u0007¨\u0006\u0004"}, d2 = {"rotate", "Landroidx/compose/ui/Modifier;", "degrees", "", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class RotateKt {
    public static final Modifier rotate(Modifier $this$rotate, float degrees) {
        Intrinsics.checkNotNullParameter($this$rotate, "<this>");
        return !((degrees > 0.0f ? 1 : (degrees == 0.0f ? 0 : -1)) == 0) ? GraphicsLayerModifierKt.m2752graphicsLayerAp8cVGQ$default($this$rotate, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, degrees, 0.0f, 0L, null, false, null, 0L, 0L, 0, 130815, null) : $this$rotate;
    }
}
