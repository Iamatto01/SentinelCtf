package androidx.compose.material;

import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.ui.graphics.Color;
import androidx.compose.ui.graphics.ColorKt;
import kotlin.Metadata;
/* compiled from: Snackbar.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\bÇ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082T¢\u0006\u0002\n\u0000R\u001a\u0010\u0005\u001a\u00020\u00068Gø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0006\u001a\u0004\b\u0007\u0010\bR\u001a\u0010\t\u001a\u00020\u00068Gø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0006\u001a\u0004\b\n\u0010\b\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u0006\u000b"}, d2 = {"Landroidx/compose/material/SnackbarDefaults;", "", "()V", "SnackbarOverlayAlpha", "", "backgroundColor", "Landroidx/compose/ui/graphics/Color;", "getBackgroundColor", "(Landroidx/compose/runtime/Composer;I)J", "primaryActionColor", "getPrimaryActionColor", "material_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class SnackbarDefaults {
    public static final int $stable = 0;
    public static final SnackbarDefaults INSTANCE = new SnackbarDefaults();
    private static final float SnackbarOverlayAlpha = 0.8f;

    private SnackbarDefaults() {
    }

    public final long getBackgroundColor(Composer $composer, int $changed) {
        long m2604copywmQWz5c;
        $composer.startReplaceableGroup(1630911716);
        ComposerKt.sourceInformation($composer, "C201@8484L6,203@8598L6:Snackbar.kt#jmzs0o");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(1630911716, $changed, -1, "androidx.compose.material.SnackbarDefaults.<get-backgroundColor> (Snackbar.kt:200)");
        }
        m2604copywmQWz5c = Color.m2604copywmQWz5c(r2, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r2) : SnackbarOverlayAlpha, (r12 & 2) != 0 ? Color.m2612getRedimpl(r2) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r2) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(MaterialTheme.INSTANCE.getColors($composer, 6).m961getOnSurface0d7_KjU()) : 0.0f);
        long m2651compositeOverOWjLjI = ColorKt.m2651compositeOverOWjLjI(m2604copywmQWz5c, MaterialTheme.INSTANCE.getColors($composer, 6).m966getSurface0d7_KjU());
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return m2651compositeOverOWjLjI;
    }

    public final long getPrimaryActionColor(Composer $composer, int $changed) {
        long primary;
        long overlayColor;
        $composer.startReplaceableGroup(-810329402);
        ComposerKt.sourceInformation($composer, "C222@9546L6:Snackbar.kt#jmzs0o");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-810329402, $changed, -1, "androidx.compose.material.SnackbarDefaults.<get-primaryActionColor> (Snackbar.kt:221)");
        }
        Colors colors = MaterialTheme.INSTANCE.getColors($composer, 6);
        if (colors.isLight()) {
            long primary2 = colors.m962getPrimary0d7_KjU();
            overlayColor = Color.m2604copywmQWz5c(r3, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r3) : 0.6f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r3) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r3) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(colors.m966getSurface0d7_KjU()) : 0.0f);
            primary = ColorKt.m2651compositeOverOWjLjI(overlayColor, primary2);
        } else {
            primary = colors.m963getPrimaryVariant0d7_KjU();
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return primary;
    }
}
