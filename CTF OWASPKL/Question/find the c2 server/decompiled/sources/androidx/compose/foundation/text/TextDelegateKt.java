package androidx.compose.foundation.text;

import kotlin.Metadata;
import kotlin.math.MathKt;
/* compiled from: TextDelegate.kt */
@Metadata(d1 = {"\u0000\f\n\u0000\n\u0002\u0010\b\n\u0002\u0010\u0007\n\u0000\u001a\f\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0000¨\u0006\u0003"}, d2 = {"ceilToIntPx", "", "", "foundation_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class TextDelegateKt {
    public static final int ceilToIntPx(float $this$ceilToIntPx) {
        return MathKt.roundToInt((float) Math.ceil($this$ceilToIntPx));
    }
}
