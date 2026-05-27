package androidx.compose.material3;

import androidx.compose.foundation.BorderStroke;
import androidx.compose.foundation.BorderStrokeKt;
import androidx.compose.material3.tokens.FilledIconButtonTokens;
import androidx.compose.material3.tokens.FilledTonalIconButtonTokens;
import androidx.compose.material3.tokens.IconButtonTokens;
import androidx.compose.material3.tokens.OutlinedIconButtonTokens;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.ui.graphics.Color;
import androidx.compose.ui.graphics.Shape;
import kotlin.Metadata;
/* compiled from: IconButton.kt */
@Metadata(d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\t\bÇ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J=\u0010\t\u001a\u00020\n2\b\b\u0002\u0010\u000b\u001a\u00020\f2\b\b\u0002\u0010\r\u001a\u00020\f2\b\b\u0002\u0010\u000e\u001a\u00020\f2\b\b\u0002\u0010\u000f\u001a\u00020\fH\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0010\u0010\u0011JQ\u0010\u0012\u001a\u00020\u00132\b\b\u0002\u0010\u000b\u001a\u00020\f2\b\b\u0002\u0010\r\u001a\u00020\f2\b\b\u0002\u0010\u000e\u001a\u00020\f2\b\b\u0002\u0010\u000f\u001a\u00020\f2\b\b\u0002\u0010\u0014\u001a\u00020\f2\b\b\u0002\u0010\u0015\u001a\u00020\fH\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0016\u0010\u0017J=\u0010\u0018\u001a\u00020\n2\b\b\u0002\u0010\u000b\u001a\u00020\f2\b\b\u0002\u0010\r\u001a\u00020\f2\b\b\u0002\u0010\u000e\u001a\u00020\f2\b\b\u0002\u0010\u000f\u001a\u00020\fH\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0019\u0010\u0011JQ\u0010\u001a\u001a\u00020\u00132\b\b\u0002\u0010\u000b\u001a\u00020\f2\b\b\u0002\u0010\r\u001a\u00020\f2\b\b\u0002\u0010\u000e\u001a\u00020\f2\b\b\u0002\u0010\u000f\u001a\u00020\f2\b\b\u0002\u0010\u0014\u001a\u00020\f2\b\b\u0002\u0010\u0015\u001a\u00020\fH\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001b\u0010\u0017J=\u0010\u001c\u001a\u00020\n2\b\b\u0002\u0010\u000b\u001a\u00020\f2\b\b\u0002\u0010\r\u001a\u00020\f2\b\b\u0002\u0010\u000e\u001a\u00020\f2\b\b\u0002\u0010\u000f\u001a\u00020\fH\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001d\u0010\u0011JQ\u0010\u001e\u001a\u00020\u00132\b\b\u0002\u0010\u000b\u001a\u00020\f2\b\b\u0002\u0010\r\u001a\u00020\f2\b\b\u0002\u0010\u000e\u001a\u00020\f2\b\b\u0002\u0010\u000f\u001a\u00020\f2\b\b\u0002\u0010\u0014\u001a\u00020\f2\b\b\u0002\u0010\u0015\u001a\u00020\fH\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001f\u0010\u0017J\u0015\u0010 \u001a\u00020!2\u0006\u0010\"\u001a\u00020#H\u0007¢\u0006\u0002\u0010$J=\u0010%\u001a\u00020\n2\b\b\u0002\u0010\u000b\u001a\u00020\f2\b\b\u0002\u0010\r\u001a\u00020\f2\b\b\u0002\u0010\u000e\u001a\u00020\f2\b\b\u0002\u0010\u000f\u001a\u00020\fH\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b&\u0010\u0011J\u001f\u0010'\u001a\u0004\u0018\u00010!2\u0006\u0010\"\u001a\u00020#2\u0006\u0010(\u001a\u00020#H\u0007¢\u0006\u0002\u0010)JQ\u0010*\u001a\u00020\u00132\b\b\u0002\u0010\u000b\u001a\u00020\f2\b\b\u0002\u0010\r\u001a\u00020\f2\b\b\u0002\u0010\u000e\u001a\u00020\f2\b\b\u0002\u0010\u000f\u001a\u00020\f2\b\b\u0002\u0010\u0014\u001a\u00020\f2\b\b\u0002\u0010\u0015\u001a\u00020\fH\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b+\u0010\u0017R\u0011\u0010\u0003\u001a\u00020\u00048G¢\u0006\u0006\u001a\u0004\b\u0005\u0010\u0006R\u0011\u0010\u0007\u001a\u00020\u00048G¢\u0006\u0006\u001a\u0004\b\b\u0010\u0006\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006,"}, d2 = {"Landroidx/compose/material3/IconButtonDefaults;", "", "()V", "filledShape", "Landroidx/compose/ui/graphics/Shape;", "getFilledShape", "(Landroidx/compose/runtime/Composer;I)Landroidx/compose/ui/graphics/Shape;", "outlinedShape", "getOutlinedShape", "filledIconButtonColors", "Landroidx/compose/material3/IconButtonColors;", "containerColor", "Landroidx/compose/ui/graphics/Color;", "contentColor", "disabledContainerColor", "disabledContentColor", "filledIconButtonColors-ro_MJ88", "(JJJJLandroidx/compose/runtime/Composer;II)Landroidx/compose/material3/IconButtonColors;", "filledIconToggleButtonColors", "Landroidx/compose/material3/IconToggleButtonColors;", "checkedContainerColor", "checkedContentColor", "filledIconToggleButtonColors-5tl4gsc", "(JJJJJJLandroidx/compose/runtime/Composer;II)Landroidx/compose/material3/IconToggleButtonColors;", "filledTonalIconButtonColors", "filledTonalIconButtonColors-ro_MJ88", "filledTonalIconToggleButtonColors", "filledTonalIconToggleButtonColors-5tl4gsc", "iconButtonColors", "iconButtonColors-ro_MJ88", "iconToggleButtonColors", "iconToggleButtonColors-5tl4gsc", "outlinedIconButtonBorder", "Landroidx/compose/foundation/BorderStroke;", "enabled", "", "(ZLandroidx/compose/runtime/Composer;I)Landroidx/compose/foundation/BorderStroke;", "outlinedIconButtonColors", "outlinedIconButtonColors-ro_MJ88", "outlinedIconToggleButtonBorder", "checked", "(ZZLandroidx/compose/runtime/Composer;I)Landroidx/compose/foundation/BorderStroke;", "outlinedIconToggleButtonColors", "outlinedIconToggleButtonColors-5tl4gsc", "material3_release"}, k = 1, mv = {1, 7, 1}, xi = 48)
/* loaded from: classes.dex */
public final class IconButtonDefaults {
    public static final int $stable = 0;
    public static final IconButtonDefaults INSTANCE = new IconButtonDefaults();

    private IconButtonDefaults() {
    }

    public final Shape getFilledShape(Composer $composer, int $changed) {
        $composer.startReplaceableGroup(1265841879);
        ComposerKt.sourceInformation($composer, "C539@26106L9:IconButton.kt#uh7d8r");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(1265841879, $changed, -1, "androidx.compose.material3.IconButtonDefaults.<get-filledShape> (IconButton.kt:539)");
        }
        Shape shape = ShapesKt.toShape(FilledIconButtonTokens.INSTANCE.getContainerShape(), $composer, 6);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return shape;
    }

    public final Shape getOutlinedShape(Composer $composer, int $changed) {
        $composer.startReplaceableGroup(1327125527);
        ComposerKt.sourceInformation($composer, "C544@26280L9:IconButton.kt#uh7d8r");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(1327125527, $changed, -1, "androidx.compose.material3.IconButtonDefaults.<get-outlinedShape> (IconButton.kt:543)");
        }
        Shape shape = ShapesKt.toShape(OutlinedIconButtonTokens.INSTANCE.getContainerShape(), $composer, 6);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return shape;
    }

    /* renamed from: iconButtonColors-ro_MJ88  reason: not valid java name */
    public final IconButtonColors m1432iconButtonColorsro_MJ88(long containerColor, long contentColor, long disabledContainerColor, long disabledContentColor, Composer $composer, int $changed, int i) {
        long contentColor2;
        long disabledContainerColor2;
        long disabledContentColor2;
        long m2604copywmQWz5c;
        $composer.startReplaceableGroup(999008085);
        ComposerKt.sourceInformation($composer, "C(iconButtonColors)P(0:c#ui.graphics.Color,1:c#ui.graphics.Color,2:c#ui.graphics.Color,3:c#ui.graphics.Color)557@26898L7:IconButton.kt#uh7d8r");
        long containerColor2 = (i & 1) != 0 ? Color.Companion.m2641getTransparent0d7_KjU() : containerColor;
        if ((i & 2) == 0) {
            contentColor2 = contentColor;
        } else {
            ComposerKt.sourceInformationMarkerStart($composer, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume = $composer.consume(ContentColorKt.getLocalContentColor());
            ComposerKt.sourceInformationMarkerEnd($composer);
            contentColor2 = ((Color) consume).m2616unboximpl();
        }
        if ((i & 4) != 0) {
            disabledContainerColor2 = Color.Companion.m2641getTransparent0d7_KjU();
        } else {
            disabledContainerColor2 = disabledContainerColor;
        }
        if ((i & 8) != 0) {
            m2604copywmQWz5c = Color.m2604copywmQWz5c(r6, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r6) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r6) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r6) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(contentColor2) : 0.0f);
            disabledContentColor2 = m2604copywmQWz5c;
        } else {
            disabledContentColor2 = disabledContentColor;
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(999008085, $changed, -1, "androidx.compose.material3.IconButtonDefaults.iconButtonColors (IconButton.kt:555)");
        }
        IconButtonColors iconButtonColors = new IconButtonColors(containerColor2, contentColor2, disabledContainerColor2, disabledContentColor2, null);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return iconButtonColors;
    }

    /* renamed from: iconToggleButtonColors-5tl4gsc  reason: not valid java name */
    public final IconToggleButtonColors m1433iconToggleButtonColors5tl4gsc(long containerColor, long contentColor, long disabledContainerColor, long disabledContentColor, long checkedContainerColor, long checkedContentColor, Composer $composer, int $changed, int i) {
        long contentColor2;
        long disabledContainerColor2;
        long disabledContentColor2;
        long checkedContainerColor2;
        long checkedContentColor2;
        long m2604copywmQWz5c;
        $composer.startReplaceableGroup(-2020719549);
        ComposerKt.sourceInformation($composer, "C(iconToggleButtonColors)P(2:c#ui.graphics.Color,3:c#ui.graphics.Color,4:c#ui.graphics.Color,5:c#ui.graphics.Color,0:c#ui.graphics.Color,1:c#ui.graphics.Color)583@28155L7,588@28468L9:IconButton.kt#uh7d8r");
        long containerColor2 = (i & 1) != 0 ? Color.Companion.m2641getTransparent0d7_KjU() : containerColor;
        if ((i & 2) == 0) {
            contentColor2 = contentColor;
        } else {
            ComposerKt.sourceInformationMarkerStart($composer, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume = $composer.consume(ContentColorKt.getLocalContentColor());
            ComposerKt.sourceInformationMarkerEnd($composer);
            contentColor2 = ((Color) consume).m2616unboximpl();
        }
        if ((i & 4) != 0) {
            disabledContainerColor2 = Color.Companion.m2641getTransparent0d7_KjU();
        } else {
            disabledContainerColor2 = disabledContainerColor;
        }
        if ((i & 8) != 0) {
            m2604copywmQWz5c = Color.m2604copywmQWz5c(r6, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r6) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r6) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r6) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(contentColor2) : 0.0f);
            disabledContentColor2 = m2604copywmQWz5c;
        } else {
            disabledContentColor2 = disabledContentColor;
        }
        if ((i & 16) == 0) {
            checkedContainerColor2 = checkedContainerColor;
        } else {
            checkedContainerColor2 = Color.Companion.m2641getTransparent0d7_KjU();
        }
        if ((i & 32) == 0) {
            checkedContentColor2 = checkedContentColor;
        } else {
            checkedContentColor2 = ColorSchemeKt.toColor(IconButtonTokens.INSTANCE.getSelectedIconColor(), $composer, 6);
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-2020719549, $changed, -1, "androidx.compose.material3.IconButtonDefaults.iconToggleButtonColors (IconButton.kt:581)");
        }
        IconToggleButtonColors iconToggleButtonColors = new IconToggleButtonColors(containerColor2, contentColor2, disabledContainerColor2, disabledContentColor2, checkedContainerColor2, checkedContentColor2, null);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return iconToggleButtonColors;
    }

    /* renamed from: filledIconButtonColors-ro_MJ88  reason: not valid java name */
    public final IconButtonColors m1428filledIconButtonColorsro_MJ88(long containerColor, long contentColor, long disabledContainerColor, long disabledContentColor, Composer $composer, int $changed, int i) {
        long contentColor2;
        long disabledContainerColor2;
        long disabledContentColor2;
        long m2604copywmQWz5c;
        $composer.startReplaceableGroup(-669858473);
        ComposerKt.sourceInformation($composer, "C(filledIconButtonColors)P(0:c#ui.graphics.Color,1:c#ui.graphics.Color,2:c#ui.graphics.Color,3:c#ui.graphics.Color)609@29461L9,610@29502L31,611@29621L9,613@29782L9:IconButton.kt#uh7d8r");
        long containerColor2 = (i & 1) != 0 ? ColorSchemeKt.toColor(FilledIconButtonTokens.INSTANCE.getContainerColor(), $composer, 6) : containerColor;
        if ((i & 2) == 0) {
            contentColor2 = contentColor;
        } else {
            contentColor2 = ColorSchemeKt.m1338contentColorForek8zF_U(containerColor2, $composer, $changed & 14);
        }
        if ((i & 4) != 0) {
            m2604copywmQWz5c = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.12f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledIconButtonTokens.INSTANCE.getDisabledContainerColor(), $composer, 6)) : 0.0f);
            disabledContainerColor2 = m2604copywmQWz5c;
        } else {
            disabledContainerColor2 = disabledContainerColor;
        }
        if ((i & 8) != 0) {
            disabledContentColor2 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledIconButtonTokens.INSTANCE.getDisabledColor(), $composer, 6)) : 0.0f);
        } else {
            disabledContentColor2 = disabledContentColor;
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-669858473, $changed, -1, "androidx.compose.material3.IconButtonDefaults.filledIconButtonColors (IconButton.kt:608)");
        }
        IconButtonColors iconButtonColors = new IconButtonColors(containerColor2, contentColor2, disabledContainerColor2, disabledContentColor2, null);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return iconButtonColors;
    }

    /* renamed from: filledIconToggleButtonColors-5tl4gsc  reason: not valid java name */
    public final IconToggleButtonColors m1429filledIconToggleButtonColors5tl4gsc(long containerColor, long contentColor, long disabledContainerColor, long disabledContentColor, long checkedContainerColor, long checkedContentColor, Composer $composer, int $changed, int i) {
        long contentColor2;
        long disabledContainerColor2;
        long disabledContentColor2;
        long checkedContainerColor2;
        long checkedContentColor2;
        long m2604copywmQWz5c;
        long m2604copywmQWz5c2;
        $composer.startReplaceableGroup(1887173701);
        ComposerKt.sourceInformation($composer, "C(filledIconToggleButtonColors)P(2:c#ui.graphics.Color,3:c#ui.graphics.Color,4:c#ui.graphics.Color,5:c#ui.graphics.Color,0:c#ui.graphics.Color,1:c#ui.graphics.Color)636@30926L9,639@31145L9,640@31242L9,642@31403L9,644@31565L9,645@31613L38:IconButton.kt#uh7d8r");
        long containerColor2 = (i & 1) != 0 ? ColorSchemeKt.toColor(FilledIconButtonTokens.INSTANCE.getUnselectedContainerColor(), $composer, 6) : containerColor;
        if ((i & 2) == 0) {
            contentColor2 = contentColor;
        } else {
            contentColor2 = ColorSchemeKt.toColor(FilledIconButtonTokens.INSTANCE.getToggleUnselectedColor(), $composer, 6);
        }
        if ((i & 4) != 0) {
            m2604copywmQWz5c2 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.12f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledIconButtonTokens.INSTANCE.getDisabledContainerColor(), $composer, 6)) : 0.0f);
            disabledContainerColor2 = m2604copywmQWz5c2;
        } else {
            disabledContainerColor2 = disabledContainerColor;
        }
        if ((i & 8) != 0) {
            m2604copywmQWz5c = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledIconButtonTokens.INSTANCE.getDisabledColor(), $composer, 6)) : 0.0f);
            disabledContentColor2 = m2604copywmQWz5c;
        } else {
            disabledContentColor2 = disabledContentColor;
        }
        if ((i & 16) == 0) {
            checkedContainerColor2 = checkedContainerColor;
        } else {
            checkedContainerColor2 = ColorSchemeKt.toColor(FilledIconButtonTokens.INSTANCE.getSelectedContainerColor(), $composer, 6);
        }
        if ((i & 32) == 0) {
            checkedContentColor2 = checkedContentColor;
        } else {
            checkedContentColor2 = ColorSchemeKt.m1338contentColorForek8zF_U(checkedContainerColor2, $composer, ($changed >> 12) & 14);
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(1887173701, $changed, -1, "androidx.compose.material3.IconButtonDefaults.filledIconToggleButtonColors (IconButton.kt:635)");
        }
        IconToggleButtonColors iconToggleButtonColors = new IconToggleButtonColors(containerColor2, contentColor2, disabledContainerColor2, disabledContentColor2, checkedContainerColor2, checkedContentColor2, null);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return iconToggleButtonColors;
    }

    /* renamed from: filledTonalIconButtonColors-ro_MJ88  reason: not valid java name */
    public final IconButtonColors m1430filledTonalIconButtonColorsro_MJ88(long containerColor, long contentColor, long disabledContainerColor, long disabledContentColor, Composer $composer, int $changed, int i) {
        long contentColor2;
        long disabledContainerColor2;
        long disabledContentColor2;
        long m2604copywmQWz5c;
        $composer.startReplaceableGroup(-18532843);
        ComposerKt.sourceInformation($composer, "C(filledTonalIconButtonColors)P(0:c#ui.graphics.Color,1:c#ui.graphics.Color,2:c#ui.graphics.Color,3:c#ui.graphics.Color)667@32657L9,668@32698L31,669@32822L9,671@32993L9:IconButton.kt#uh7d8r");
        long containerColor2 = (i & 1) != 0 ? ColorSchemeKt.toColor(FilledTonalIconButtonTokens.INSTANCE.getContainerColor(), $composer, 6) : containerColor;
        if ((i & 2) == 0) {
            contentColor2 = contentColor;
        } else {
            contentColor2 = ColorSchemeKt.m1338contentColorForek8zF_U(containerColor2, $composer, $changed & 14);
        }
        if ((i & 4) != 0) {
            m2604copywmQWz5c = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.12f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledTonalIconButtonTokens.INSTANCE.getDisabledContainerColor(), $composer, 6)) : 0.0f);
            disabledContainerColor2 = m2604copywmQWz5c;
        } else {
            disabledContainerColor2 = disabledContainerColor;
        }
        if ((i & 8) != 0) {
            disabledContentColor2 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledTonalIconButtonTokens.INSTANCE.getDisabledColor(), $composer, 6)) : 0.0f);
        } else {
            disabledContentColor2 = disabledContentColor;
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-18532843, $changed, -1, "androidx.compose.material3.IconButtonDefaults.filledTonalIconButtonColors (IconButton.kt:666)");
        }
        IconButtonColors iconButtonColors = new IconButtonColors(containerColor2, contentColor2, disabledContainerColor2, disabledContentColor2, null);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return iconButtonColors;
    }

    /* renamed from: filledTonalIconToggleButtonColors-5tl4gsc  reason: not valid java name */
    public final IconToggleButtonColors m1431filledTonalIconToggleButtonColors5tl4gsc(long containerColor, long contentColor, long disabledContainerColor, long disabledContentColor, long checkedContainerColor, long checkedContentColor, Composer $composer, int $changed, int i) {
        long contentColor2;
        long disabledContainerColor2;
        long disabledContentColor2;
        long checkedContainerColor2;
        long checkedContentColor2;
        long m2604copywmQWz5c;
        long m2604copywmQWz5c2;
        $composer.startReplaceableGroup(-19426557);
        ComposerKt.sourceInformation($composer, "C(filledTonalIconToggleButtonColors)P(2:c#ui.graphics.Color,3:c#ui.graphics.Color,4:c#ui.graphics.Color,5:c#ui.graphics.Color,0:c#ui.graphics.Color,1:c#ui.graphics.Color)694@34157L9,695@34198L31,696@34322L9,698@34493L9,701@34677L9,702@34773L9:IconButton.kt#uh7d8r");
        long containerColor2 = (i & 1) != 0 ? ColorSchemeKt.toColor(FilledTonalIconButtonTokens.INSTANCE.getUnselectedContainerColor(), $composer, 6) : containerColor;
        if ((i & 2) == 0) {
            contentColor2 = contentColor;
        } else {
            contentColor2 = ColorSchemeKt.m1338contentColorForek8zF_U(containerColor2, $composer, $changed & 14);
        }
        if ((i & 4) != 0) {
            m2604copywmQWz5c2 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.12f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledTonalIconButtonTokens.INSTANCE.getDisabledContainerColor(), $composer, 6)) : 0.0f);
            disabledContainerColor2 = m2604copywmQWz5c2;
        } else {
            disabledContainerColor2 = disabledContainerColor;
        }
        if ((i & 8) != 0) {
            m2604copywmQWz5c = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledTonalIconButtonTokens.INSTANCE.getDisabledColor(), $composer, 6)) : 0.0f);
            disabledContentColor2 = m2604copywmQWz5c;
        } else {
            disabledContentColor2 = disabledContentColor;
        }
        if ((i & 16) == 0) {
            checkedContainerColor2 = checkedContainerColor;
        } else {
            checkedContainerColor2 = ColorSchemeKt.toColor(FilledTonalIconButtonTokens.INSTANCE.getSelectedContainerColor(), $composer, 6);
        }
        if ((i & 32) == 0) {
            checkedContentColor2 = checkedContentColor;
        } else {
            checkedContentColor2 = ColorSchemeKt.toColor(FilledTonalIconButtonTokens.INSTANCE.getToggleSelectedColor(), $composer, 6);
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-19426557, $changed, -1, "androidx.compose.material3.IconButtonDefaults.filledTonalIconToggleButtonColors (IconButton.kt:693)");
        }
        IconToggleButtonColors iconToggleButtonColors = new IconToggleButtonColors(containerColor2, contentColor2, disabledContainerColor2, disabledContentColor2, checkedContainerColor2, checkedContentColor2, null);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return iconToggleButtonColors;
    }

    /* renamed from: outlinedIconButtonColors-ro_MJ88  reason: not valid java name */
    public final IconButtonColors m1434outlinedIconButtonColorsro_MJ88(long containerColor, long contentColor, long disabledContainerColor, long disabledContentColor, Composer $composer, int $changed, int i) {
        long contentColor2;
        long disabledContainerColor2;
        long disabledContentColor2;
        long m2604copywmQWz5c;
        $composer.startReplaceableGroup(-1030517545);
        ComposerKt.sourceInformation($composer, "C(outlinedIconButtonColors)P(0:c#ui.graphics.Color,1:c#ui.graphics.Color,2:c#ui.graphics.Color,3:c#ui.graphics.Color)725@35806L7:IconButton.kt#uh7d8r");
        long containerColor2 = (i & 1) != 0 ? Color.Companion.m2641getTransparent0d7_KjU() : containerColor;
        if ((i & 2) == 0) {
            contentColor2 = contentColor;
        } else {
            ComposerKt.sourceInformationMarkerStart($composer, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume = $composer.consume(ContentColorKt.getLocalContentColor());
            ComposerKt.sourceInformationMarkerEnd($composer);
            contentColor2 = ((Color) consume).m2616unboximpl();
        }
        if ((i & 4) != 0) {
            disabledContainerColor2 = Color.Companion.m2641getTransparent0d7_KjU();
        } else {
            disabledContainerColor2 = disabledContainerColor;
        }
        if ((i & 8) != 0) {
            m2604copywmQWz5c = Color.m2604copywmQWz5c(r6, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r6) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r6) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r6) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(contentColor2) : 0.0f);
            disabledContentColor2 = m2604copywmQWz5c;
        } else {
            disabledContentColor2 = disabledContentColor;
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-1030517545, $changed, -1, "androidx.compose.material3.IconButtonDefaults.outlinedIconButtonColors (IconButton.kt:723)");
        }
        IconButtonColors iconButtonColors = new IconButtonColors(containerColor2, contentColor2, disabledContainerColor2, disabledContentColor2, null);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return iconButtonColors;
    }

    /* renamed from: outlinedIconToggleButtonColors-5tl4gsc  reason: not valid java name */
    public final IconToggleButtonColors m1435outlinedIconToggleButtonColors5tl4gsc(long containerColor, long contentColor, long disabledContainerColor, long disabledContentColor, long checkedContainerColor, long checkedContentColor, Composer $composer, int $changed, int i) {
        long contentColor2;
        long disabledContainerColor2;
        long disabledContentColor2;
        long checkedContainerColor2;
        long checkedContentColor2;
        long m2604copywmQWz5c;
        $composer.startReplaceableGroup(2130592709);
        ComposerKt.sourceInformation($composer, "C(outlinedIconToggleButtonColors)P(2:c#ui.graphics.Color,3:c#ui.graphics.Color,4:c#ui.graphics.Color,5:c#ui.graphics.Color,0:c#ui.graphics.Color,1:c#ui.graphics.Color)751@37083L7,756@37369L9,757@37417L38:IconButton.kt#uh7d8r");
        long containerColor2 = (i & 1) != 0 ? Color.Companion.m2641getTransparent0d7_KjU() : containerColor;
        if ((i & 2) == 0) {
            contentColor2 = contentColor;
        } else {
            ComposerKt.sourceInformationMarkerStart($composer, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume = $composer.consume(ContentColorKt.getLocalContentColor());
            ComposerKt.sourceInformationMarkerEnd($composer);
            contentColor2 = ((Color) consume).m2616unboximpl();
        }
        if ((i & 4) != 0) {
            disabledContainerColor2 = Color.Companion.m2641getTransparent0d7_KjU();
        } else {
            disabledContainerColor2 = disabledContainerColor;
        }
        if ((i & 8) != 0) {
            m2604copywmQWz5c = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(contentColor2) : 0.0f);
            disabledContentColor2 = m2604copywmQWz5c;
        } else {
            disabledContentColor2 = disabledContentColor;
        }
        if ((i & 16) == 0) {
            checkedContainerColor2 = checkedContainerColor;
        } else {
            checkedContainerColor2 = ColorSchemeKt.toColor(OutlinedIconButtonTokens.INSTANCE.getSelectedContainerColor(), $composer, 6);
        }
        if ((i & 32) == 0) {
            checkedContentColor2 = checkedContentColor;
        } else {
            checkedContentColor2 = ColorSchemeKt.m1338contentColorForek8zF_U(checkedContainerColor2, $composer, ($changed >> 12) & 14);
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(2130592709, $changed, -1, "androidx.compose.material3.IconButtonDefaults.outlinedIconToggleButtonColors (IconButton.kt:749)");
        }
        IconToggleButtonColors iconToggleButtonColors = new IconToggleButtonColors(containerColor2, contentColor2, disabledContainerColor2, disabledContentColor2, checkedContainerColor2, checkedContentColor2, null);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return iconToggleButtonColors;
    }

    public final BorderStroke outlinedIconToggleButtonBorder(boolean enabled, boolean checked, Composer $composer, int $changed) {
        $composer.startReplaceableGroup(1244729690);
        ComposerKt.sourceInformation($composer, "C(outlinedIconToggleButtonBorder)P(1)780@38287L33:IconButton.kt#uh7d8r");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(1244729690, $changed, -1, "androidx.compose.material3.IconButtonDefaults.outlinedIconToggleButtonBorder (IconButton.kt:776)");
        }
        if (checked) {
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            $composer.endReplaceableGroup();
            return null;
        }
        BorderStroke outlinedIconButtonBorder = outlinedIconButtonBorder(enabled, $composer, ($changed & 14) | (($changed >> 3) & 112));
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return outlinedIconButtonBorder;
    }

    public final BorderStroke outlinedIconButtonBorder(boolean enabled, Composer $composer, int $changed) {
        long color;
        Object value$iv$iv;
        $composer.startReplaceableGroup(-511461558);
        ComposerKt.sourceInformation($composer, "C(outlinedIconButtonBorder)796@38840L108:IconButton.kt#uh7d8r");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-511461558, $changed, -1, "androidx.compose.material3.IconButtonDefaults.outlinedIconButtonBorder (IconButton.kt:789)");
        }
        if (!enabled) {
            $composer.startReplaceableGroup(1252615127);
            ComposerKt.sourceInformation($composer, "793@38718L7");
            ComposerKt.sourceInformationMarkerStart($composer, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume = $composer.consume(ContentColorKt.getLocalContentColor());
            ComposerKt.sourceInformationMarkerEnd($composer);
            color = Color.m2604copywmQWz5c(r1, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r1) : 0.12f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r1) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r1) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(((Color) consume).m2616unboximpl()) : 0.0f);
            $composer.endReplaceableGroup();
        } else {
            $composer.startReplaceableGroup(1252615072);
            ComposerKt.sourceInformation($composer, "791@38663L7");
            ComposerKt.sourceInformationMarkerStart($composer, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume2 = $composer.consume(ContentColorKt.getLocalContentColor());
            ComposerKt.sourceInformationMarkerEnd($composer);
            color = ((Color) consume2).m2616unboximpl();
            $composer.endReplaceableGroup();
        }
        Object key1$iv = Color.m2596boximpl(color);
        $composer.startReplaceableGroup(1157296644);
        ComposerKt.sourceInformation($composer, "C(remember)P(1):Composables.kt#9igjgp");
        boolean invalid$iv$iv = $composer.changed(key1$iv);
        Object it$iv$iv = $composer.rememberedValue();
        if (invalid$iv$iv || it$iv$iv == Composer.Companion.getEmpty()) {
            value$iv$iv = BorderStrokeKt.m170BorderStrokecXLIe8U(OutlinedIconButtonTokens.INSTANCE.m2019getUnselectedOutlineWidthD9Ej5fM(), color);
            $composer.updateRememberedValue(value$iv$iv);
        } else {
            value$iv$iv = it$iv$iv;
        }
        $composer.endReplaceableGroup();
        BorderStroke borderStroke = (BorderStroke) value$iv$iv;
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return borderStroke;
    }
}
