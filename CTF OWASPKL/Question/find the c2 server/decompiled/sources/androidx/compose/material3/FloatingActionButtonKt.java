package androidx.compose.material3;

import androidx.compose.animation.AnimatedVisibilityKt;
import androidx.compose.animation.AnimatedVisibilityScope;
import androidx.compose.animation.EnterExitTransitionKt;
import androidx.compose.animation.EnterTransition;
import androidx.compose.animation.ExitTransition;
import androidx.compose.animation.core.AnimationSpecKt;
import androidx.compose.foundation.interaction.InteractionSourceKt;
import androidx.compose.foundation.interaction.MutableInteractionSource;
import androidx.compose.foundation.layout.Arrangement;
import androidx.compose.foundation.layout.PaddingKt;
import androidx.compose.foundation.layout.RowKt;
import androidx.compose.foundation.layout.RowScope;
import androidx.compose.foundation.layout.RowScopeInstance;
import androidx.compose.foundation.layout.SizeKt;
import androidx.compose.foundation.layout.SpacerKt;
import androidx.compose.material3.tokens.FabPrimaryTokens;
import androidx.compose.material3.tokens.MotionTokens;
import androidx.compose.runtime.Applier;
import androidx.compose.runtime.ComposablesKt;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.ScopeUpdateScope;
import androidx.compose.runtime.SkippableUpdater;
import androidx.compose.runtime.Updater;
import androidx.compose.runtime.internal.ComposableLambdaKt;
import androidx.compose.ui.Alignment;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.graphics.Shape;
import androidx.compose.ui.layout.LayoutKt;
import androidx.compose.ui.layout.MeasurePolicy;
import androidx.compose.ui.node.ComposeUiNode;
import androidx.compose.ui.platform.CompositionLocalsKt;
import androidx.compose.ui.platform.ViewConfiguration;
import androidx.compose.ui.semantics.SemanticsModifierKt;
import androidx.compose.ui.semantics.SemanticsPropertyReceiver;
import androidx.compose.ui.unit.Density;
import androidx.compose.ui.unit.Dp;
import androidx.compose.ui.unit.LayoutDirection;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: FloatingActionButton.kt */
@Metadata(d1 = {"\u0000`\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\n\u001a}\u0010\n\u001a\u00020\u000b2\f\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000b0\r2\b\b\u0002\u0010\u000e\u001a\u00020\u000f2\b\b\u0002\u0010\u0010\u001a\u00020\u00112\b\b\u0002\u0010\u0012\u001a\u00020\u00132\b\b\u0002\u0010\u0014\u001a\u00020\u00132\b\b\u0002\u0010\u0015\u001a\u00020\u00162\b\b\u0002\u0010\u0017\u001a\u00020\u00182\u001c\u0010\u0019\u001a\u0018\u0012\u0004\u0012\u00020\u001b\u0012\u0004\u0012\u00020\u000b0\u001a¢\u0006\u0002\b\u001c¢\u0006\u0002\b\u001dH\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\u001e\u0010\u001f\u001a\u008f\u0001\u0010\n\u001a\u00020\u000b2\u0011\u0010 \u001a\r\u0012\u0004\u0012\u00020\u000b0\r¢\u0006\u0002\b\u001c2\u0011\u0010!\u001a\r\u0012\u0004\u0012\u00020\u000b0\r¢\u0006\u0002\b\u001c2\f\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000b0\r2\b\b\u0002\u0010\u000e\u001a\u00020\u000f2\b\b\u0002\u0010\"\u001a\u00020#2\b\b\u0002\u0010\u0010\u001a\u00020\u00112\b\b\u0002\u0010\u0012\u001a\u00020\u00132\b\b\u0002\u0010\u0014\u001a\u00020\u00132\b\b\u0002\u0010\u0015\u001a\u00020\u00162\b\b\u0002\u0010\u0017\u001a\u00020\u0018H\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b$\u0010%\u001ar\u0010&\u001a\u00020\u000b2\f\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000b0\r2\b\b\u0002\u0010\u000e\u001a\u00020\u000f2\b\b\u0002\u0010\u0010\u001a\u00020\u00112\b\b\u0002\u0010\u0012\u001a\u00020\u00132\b\b\u0002\u0010\u0014\u001a\u00020\u00132\b\b\u0002\u0010\u0015\u001a\u00020\u00162\b\b\u0002\u0010\u0017\u001a\u00020\u00182\u0011\u0010\u0019\u001a\r\u0012\u0004\u0012\u00020\u000b0\r¢\u0006\u0002\b\u001cH\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b'\u0010(\u001ar\u0010)\u001a\u00020\u000b2\f\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000b0\r2\b\b\u0002\u0010\u000e\u001a\u00020\u000f2\b\b\u0002\u0010\u0010\u001a\u00020\u00112\b\b\u0002\u0010\u0012\u001a\u00020\u00132\b\b\u0002\u0010\u0014\u001a\u00020\u00132\b\b\u0002\u0010\u0015\u001a\u00020\u00162\b\b\u0002\u0010\u0017\u001a\u00020\u00182\u0011\u0010\u0019\u001a\r\u0012\u0004\u0012\u00020\u000b0\r¢\u0006\u0002\b\u001cH\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b*\u0010(\u001ar\u0010+\u001a\u00020\u000b2\f\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000b0\r2\b\b\u0002\u0010\u000e\u001a\u00020\u000f2\b\b\u0002\u0010\u0010\u001a\u00020\u00112\b\b\u0002\u0010\u0012\u001a\u00020\u00132\b\b\u0002\u0010\u0014\u001a\u00020\u00132\b\b\u0002\u0010\u0015\u001a\u00020\u00162\b\b\u0002\u0010\u0017\u001a\u00020\u00182\u0011\u0010\u0019\u001a\r\u0012\u0004\u0012\u00020\u000b0\r¢\u0006\u0002\b\u001cH\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b,\u0010(\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082\u0004¢\u0006\u0002\n\u0000\"\u0013\u0010\u0002\u001a\u00020\u0003X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0004\"\u000e\u0010\u0005\u001a\u00020\u0006X\u0082\u0004¢\u0006\u0002\n\u0000\"\u0013\u0010\u0007\u001a\u00020\u0003X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0004\"\u0013\u0010\b\u001a\u00020\u0003X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0004\"\u0013\u0010\t\u001a\u00020\u0003X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0004\u0082\u0002\u000b\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001¨\u0006-"}, d2 = {"ExtendedFabCollapseAnimation", "Landroidx/compose/animation/ExitTransition;", "ExtendedFabEndIconPadding", "Landroidx/compose/ui/unit/Dp;", "F", "ExtendedFabExpandAnimation", "Landroidx/compose/animation/EnterTransition;", "ExtendedFabMinimumWidth", "ExtendedFabStartIconPadding", "ExtendedFabTextPadding", "ExtendedFloatingActionButton", "", "onClick", "Lkotlin/Function0;", "modifier", "Landroidx/compose/ui/Modifier;", "shape", "Landroidx/compose/ui/graphics/Shape;", "containerColor", "Landroidx/compose/ui/graphics/Color;", "contentColor", "elevation", "Landroidx/compose/material3/FloatingActionButtonElevation;", "interactionSource", "Landroidx/compose/foundation/interaction/MutableInteractionSource;", "content", "Lkotlin/Function1;", "Landroidx/compose/foundation/layout/RowScope;", "Landroidx/compose/runtime/Composable;", "Lkotlin/ExtensionFunctionType;", "ExtendedFloatingActionButton-X-z6DiA", "(Lkotlin/jvm/functions/Function0;Landroidx/compose/ui/Modifier;Landroidx/compose/ui/graphics/Shape;JJLandroidx/compose/material3/FloatingActionButtonElevation;Landroidx/compose/foundation/interaction/MutableInteractionSource;Lkotlin/jvm/functions/Function3;Landroidx/compose/runtime/Composer;II)V", "text", "icon", "expanded", "", "ExtendedFloatingActionButton-ElI5-7k", "(Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function0;Landroidx/compose/ui/Modifier;ZLandroidx/compose/ui/graphics/Shape;JJLandroidx/compose/material3/FloatingActionButtonElevation;Landroidx/compose/foundation/interaction/MutableInteractionSource;Landroidx/compose/runtime/Composer;II)V", "FloatingActionButton", "FloatingActionButton-X-z6DiA", "(Lkotlin/jvm/functions/Function0;Landroidx/compose/ui/Modifier;Landroidx/compose/ui/graphics/Shape;JJLandroidx/compose/material3/FloatingActionButtonElevation;Landroidx/compose/foundation/interaction/MutableInteractionSource;Lkotlin/jvm/functions/Function2;Landroidx/compose/runtime/Composer;II)V", "LargeFloatingActionButton", "LargeFloatingActionButton-X-z6DiA", "SmallFloatingActionButton", "SmallFloatingActionButton-X-z6DiA", "material3_release"}, k = 2, mv = {1, 7, 1}, xi = 48)
/* loaded from: classes.dex */
public final class FloatingActionButtonKt {
    private static final float ExtendedFabStartIconPadding = Dp.m5122constructorimpl(16);
    private static final float ExtendedFabEndIconPadding = Dp.m5122constructorimpl(12);
    private static final float ExtendedFabTextPadding = Dp.m5122constructorimpl(20);
    private static final float ExtendedFabMinimumWidth = Dp.m5122constructorimpl(80);
    private static final ExitTransition ExtendedFabCollapseAnimation = EnterExitTransitionKt.fadeOut$default(AnimationSpecKt.tween$default(100, 0, MotionTokens.INSTANCE.getEasingLinearCubicBezier(), 2, null), 0.0f, 2, null).plus(EnterExitTransitionKt.shrinkHorizontally$default(AnimationSpecKt.tween$default(500, 0, MotionTokens.INSTANCE.getEasingEmphasizedCubicBezier(), 2, null), Alignment.Companion.getStart(), false, null, 12, null));
    private static final EnterTransition ExtendedFabExpandAnimation = EnterExitTransitionKt.fadeIn$default(AnimationSpecKt.tween(ComposerKt.invocationKey, 100, MotionTokens.INSTANCE.getEasingLinearCubicBezier()), 0.0f, 2, null).plus(EnterExitTransitionKt.expandHorizontally$default(AnimationSpecKt.tween$default(500, 0, MotionTokens.INSTANCE.getEasingEmphasizedCubicBezier(), 2, null), Alignment.Companion.getStart(), false, null, 12, null));

    /* JADX WARN: Removed duplicated region for block: B:113:0x0173  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x0178  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x017f  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x018c  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x0199  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x01a4  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x01a9  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x01c2  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x020f  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x0228  */
    /* JADX WARN: Removed duplicated region for block: B:140:0x02ba  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x02c4  */
    /* JADX WARN: Removed duplicated region for block: B:146:? A[RETURN, SYNTHETIC] */
    /* renamed from: FloatingActionButton-X-z6DiA  reason: not valid java name */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void m1425FloatingActionButtonXz6DiA(final kotlin.jvm.functions.Function0<kotlin.Unit> r27, androidx.compose.ui.Modifier r28, androidx.compose.ui.graphics.Shape r29, long r30, long r32, androidx.compose.material3.FloatingActionButtonElevation r34, androidx.compose.foundation.interaction.MutableInteractionSource r35, final kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r36, androidx.compose.runtime.Composer r37, final int r38, final int r39) {
        /*
            Method dump skipped, instructions count: 740
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.FloatingActionButtonKt.m1425FloatingActionButtonXz6DiA(kotlin.jvm.functions.Function0, androidx.compose.ui.Modifier, androidx.compose.ui.graphics.Shape, long, long, androidx.compose.material3.FloatingActionButtonElevation, androidx.compose.foundation.interaction.MutableInteractionSource, kotlin.jvm.functions.Function2, androidx.compose.runtime.Composer, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:113:0x0178  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x017d  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0184  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x018f  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x0195  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x01a2  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x01b3  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x01bb  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x01d4  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x01d8  */
    /* JADX WARN: Removed duplicated region for block: B:136:0x0211  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x0222  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x028f  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x0299  */
    /* JADX WARN: Removed duplicated region for block: B:148:? A[RETURN, SYNTHETIC] */
    /* renamed from: SmallFloatingActionButton-X-z6DiA  reason: not valid java name */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void m1427SmallFloatingActionButtonXz6DiA(final kotlin.jvm.functions.Function0<kotlin.Unit> r29, androidx.compose.ui.Modifier r30, androidx.compose.ui.graphics.Shape r31, long r32, long r34, androidx.compose.material3.FloatingActionButtonElevation r36, androidx.compose.foundation.interaction.MutableInteractionSource r37, final kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r38, androidx.compose.runtime.Composer r39, final int r40, final int r41) {
        /*
            Method dump skipped, instructions count: 701
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.FloatingActionButtonKt.m1427SmallFloatingActionButtonXz6DiA(kotlin.jvm.functions.Function0, androidx.compose.ui.Modifier, androidx.compose.ui.graphics.Shape, long, long, androidx.compose.material3.FloatingActionButtonElevation, androidx.compose.foundation.interaction.MutableInteractionSource, kotlin.jvm.functions.Function2, androidx.compose.runtime.Composer, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:113:0x0178  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x017d  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0184  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x018f  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x0195  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x01a2  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x01b3  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x01bb  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x01d4  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x01d8  */
    /* JADX WARN: Removed duplicated region for block: B:136:0x0211  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x0222  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x028f  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x0299  */
    /* JADX WARN: Removed duplicated region for block: B:148:? A[RETURN, SYNTHETIC] */
    /* renamed from: LargeFloatingActionButton-X-z6DiA  reason: not valid java name */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void m1426LargeFloatingActionButtonXz6DiA(final kotlin.jvm.functions.Function0<kotlin.Unit> r29, androidx.compose.ui.Modifier r30, androidx.compose.ui.graphics.Shape r31, long r32, long r34, androidx.compose.material3.FloatingActionButtonElevation r36, androidx.compose.foundation.interaction.MutableInteractionSource r37, final kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r38, androidx.compose.runtime.Composer r39, final int r40, final int r41) {
        /*
            Method dump skipped, instructions count: 701
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.FloatingActionButtonKt.m1426LargeFloatingActionButtonXz6DiA(kotlin.jvm.functions.Function0, androidx.compose.ui.Modifier, androidx.compose.ui.graphics.Shape, long, long, androidx.compose.material3.FloatingActionButtonElevation, androidx.compose.foundation.interaction.MutableInteractionSource, kotlin.jvm.functions.Function2, androidx.compose.runtime.Composer, int, int):void");
    }

    /* renamed from: ExtendedFloatingActionButton-X-z6DiA  reason: not valid java name */
    public static final void m1424ExtendedFloatingActionButtonXz6DiA(final Function0<Unit> onClick, Modifier modifier, Shape shape, long containerColor, long contentColor, FloatingActionButtonElevation elevation, MutableInteractionSource interactionSource, final Function3<? super RowScope, ? super Composer, ? super Integer, Unit> content, Composer $composer, final int $changed, final int i) {
        Object obj;
        long containerColor2;
        long j;
        Object elevation2;
        Object obj2;
        Shape shape2;
        int $dirty;
        long contentColor2;
        long containerColor3;
        Modifier modifier2;
        FloatingActionButtonElevation elevation3;
        final int $dirty2;
        MutableInteractionSource interactionSource2;
        Object value$iv$iv;
        Composer $composer2;
        int i2;
        int i3;
        int i4;
        int i5;
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        Intrinsics.checkNotNullParameter(content, "content");
        Composer $composer3 = $composer.startRestartGroup(-326283107);
        ComposerKt.sourceInformation($composer3, "C(ExtendedFloatingActionButton)P(6,5,7,0:c#ui.graphics.Color,2:c#ui.graphics.Color,3,4)271@13789L16,272@13864L14,273@13906L31,274@14015L11,275@14078L39,278@14173L595:FloatingActionButton.kt#uh7d8r");
        int $dirty3 = $changed;
        if ((i & 1) != 0) {
            $dirty3 |= 6;
        } else if (($changed & 14) == 0) {
            $dirty3 |= $composer3.changed(onClick) ? 4 : 2;
        }
        int i6 = i & 2;
        if (i6 != 0) {
            $dirty3 |= 48;
        } else if (($changed & 112) == 0) {
            $dirty3 |= $composer3.changed(modifier) ? 32 : 16;
        }
        if (($changed & 896) == 0) {
            if ((i & 4) == 0) {
                obj = shape;
                if ($composer3.changed(obj)) {
                    i5 = 256;
                    $dirty3 |= i5;
                }
            } else {
                obj = shape;
            }
            i5 = 128;
            $dirty3 |= i5;
        } else {
            obj = shape;
        }
        if (($changed & 7168) == 0) {
            if ((i & 8) == 0) {
                containerColor2 = containerColor;
                if ($composer3.changed(containerColor2)) {
                    i4 = 2048;
                    $dirty3 |= i4;
                }
            } else {
                containerColor2 = containerColor;
            }
            i4 = 1024;
            $dirty3 |= i4;
        } else {
            containerColor2 = containerColor;
        }
        if (($changed & 57344) == 0) {
            if ((i & 16) == 0) {
                j = contentColor;
                if ($composer3.changed(j)) {
                    i3 = 16384;
                    $dirty3 |= i3;
                }
            } else {
                j = contentColor;
            }
            i3 = 8192;
            $dirty3 |= i3;
        } else {
            j = contentColor;
        }
        if (($changed & 458752) == 0) {
            if ((i & 32) == 0) {
                elevation2 = elevation;
                if ($composer3.changed(elevation2)) {
                    i2 = 131072;
                    $dirty3 |= i2;
                }
            } else {
                elevation2 = elevation;
            }
            i2 = 65536;
            $dirty3 |= i2;
        } else {
            elevation2 = elevation;
        }
        int i7 = i & 64;
        if (i7 != 0) {
            $dirty3 |= 1572864;
            obj2 = interactionSource;
        } else if (($changed & 3670016) == 0) {
            obj2 = interactionSource;
            $dirty3 |= $composer3.changed(obj2) ? 1048576 : 524288;
        } else {
            obj2 = interactionSource;
        }
        if ((i & 128) != 0) {
            $dirty3 |= 12582912;
        } else if ((29360128 & $changed) == 0) {
            $dirty3 |= $composer3.changed(content) ? 8388608 : 4194304;
        }
        if ((23967451 & $dirty3) == 4793490 && $composer3.getSkipping()) {
            $composer3.skipToGroupEnd();
            modifier2 = modifier;
            shape2 = obj;
            containerColor3 = containerColor2;
            contentColor2 = j;
            interactionSource2 = obj2;
            elevation3 = elevation2;
            $composer2 = $composer3;
        } else {
            $composer3.startDefaults();
            if (($changed & 1) == 0 || $composer3.getDefaultsInvalid()) {
                Modifier.Companion modifier3 = i6 != 0 ? Modifier.Companion : modifier;
                if ((i & 4) != 0) {
                    $dirty3 &= -897;
                    shape2 = FloatingActionButtonDefaults.INSTANCE.getExtendedFabShape($composer3, 6);
                } else {
                    shape2 = obj;
                }
                if ((i & 8) != 0) {
                    $dirty3 &= -7169;
                    containerColor2 = FloatingActionButtonDefaults.INSTANCE.getContainerColor($composer3, 6);
                }
                if ((i & 16) != 0) {
                    $dirty = $dirty3 & (-57345);
                    contentColor2 = ColorSchemeKt.m1338contentColorForek8zF_U(containerColor2, $composer3, ($dirty3 >> 9) & 14);
                } else {
                    $dirty = $dirty3;
                    contentColor2 = j;
                }
                if ((i & 32) != 0) {
                    containerColor3 = containerColor2;
                    $dirty &= -458753;
                    elevation2 = FloatingActionButtonDefaults.INSTANCE.m1420elevationxZ9QkE(0.0f, 0.0f, 0.0f, 0.0f, $composer3, 24576, 15);
                } else {
                    containerColor3 = containerColor2;
                }
                if (i7 != 0) {
                    $composer3.startReplaceableGroup(-492369756);
                    ComposerKt.sourceInformation($composer3, "C(remember):Composables.kt#9igjgp");
                    Object it$iv$iv = $composer3.rememberedValue();
                    if (it$iv$iv == Composer.Companion.getEmpty()) {
                        value$iv$iv = InteractionSourceKt.MutableInteractionSource();
                        $composer3.updateRememberedValue(value$iv$iv);
                    } else {
                        value$iv$iv = it$iv$iv;
                    }
                    $composer3.endReplaceableGroup();
                    modifier2 = modifier3;
                    elevation3 = elevation2;
                    $dirty2 = $dirty;
                    interactionSource2 = (MutableInteractionSource) value$iv$iv;
                } else {
                    modifier2 = modifier3;
                    elevation3 = elevation2;
                    $dirty2 = $dirty;
                    interactionSource2 = obj2;
                }
            } else {
                $composer3.skipToGroupEnd();
                if ((i & 4) != 0) {
                    $dirty3 &= -897;
                }
                if ((i & 8) != 0) {
                    $dirty3 &= -7169;
                }
                if ((i & 16) != 0) {
                    $dirty3 &= -57345;
                }
                if ((i & 32) != 0) {
                    modifier2 = modifier;
                    shape2 = obj;
                    containerColor3 = containerColor2;
                    contentColor2 = j;
                    interactionSource2 = obj2;
                    elevation3 = elevation2;
                    $dirty2 = $dirty3 & (-458753);
                } else {
                    modifier2 = modifier;
                    shape2 = obj;
                    containerColor3 = containerColor2;
                    contentColor2 = j;
                    interactionSource2 = obj2;
                    elevation3 = elevation2;
                    $dirty2 = $dirty3;
                }
            }
            $composer3.endDefaults();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(-326283107, $dirty2, -1, "androidx.compose.material3.ExtendedFloatingActionButton (FloatingActionButton.kt:268)");
            }
            $composer2 = $composer3;
            m1425FloatingActionButtonXz6DiA(onClick, modifier2, shape2, containerColor3, contentColor2, elevation3, interactionSource2, ComposableLambdaKt.composableLambda($composer3, 398457247, true, new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material3.FloatingActionButtonKt$ExtendedFloatingActionButton$2
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                /* JADX WARN: Multi-variable type inference failed */
                {
                    super(2);
                }

                @Override // kotlin.jvm.functions.Function2
                public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
                    invoke(composer, num.intValue());
                    return Unit.INSTANCE;
                }

                public final void invoke(Composer $composer4, int $changed2) {
                    float f;
                    float f2;
                    ComposerKt.sourceInformation($composer4, "C287@14446L316:FloatingActionButton.kt#uh7d8r");
                    if (($changed2 & 11) != 2 || !$composer4.getSkipping()) {
                        if (ComposerKt.isTraceInProgress()) {
                            ComposerKt.traceEventStart(398457247, $changed2, -1, "androidx.compose.material3.ExtendedFloatingActionButton.<anonymous> (FloatingActionButton.kt:286)");
                        }
                        f = FloatingActionButtonKt.ExtendedFabMinimumWidth;
                        Modifier m461sizeInqDBjuR0$default = SizeKt.m461sizeInqDBjuR0$default(Modifier.Companion, f, 0.0f, 0.0f, 0.0f, 14, null);
                        f2 = FloatingActionButtonKt.ExtendedFabTextPadding;
                        Modifier modifier$iv = PaddingKt.m416paddingVpY3zN4$default(m461sizeInqDBjuR0$default, f2, 0.0f, 2, null);
                        Arrangement.Horizontal horizontalArrangement$iv = Arrangement.INSTANCE.getCenter();
                        Alignment.Vertical verticalAlignment$iv = Alignment.Companion.getCenterVertically();
                        Function3 content$iv = content;
                        int $changed$iv = (($dirty2 >> 12) & 7168) | 438;
                        $composer4.startReplaceableGroup(693286680);
                        ComposerKt.sourceInformation($composer4, "C(Row)P(2,1,3)78@3880L58,79@3943L130:Row.kt#2w3rfo");
                        MeasurePolicy measurePolicy$iv = RowKt.rowMeasurePolicy(horizontalArrangement$iv, verticalAlignment$iv, $composer4, (($changed$iv >> 3) & 14) | (($changed$iv >> 3) & 112));
                        int $changed$iv$iv = ($changed$iv << 3) & 112;
                        $composer4.startReplaceableGroup(-1323940314);
                        ComposerKt.sourceInformation($composer4, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                        ComposerKt.sourceInformationMarkerStart($composer4, 2023513938, "C:CompositionLocal.kt#9igjgp");
                        Object consume = $composer4.consume(CompositionLocalsKt.getLocalDensity());
                        ComposerKt.sourceInformationMarkerEnd($composer4);
                        Density density$iv$iv = (Density) consume;
                        ComposerKt.sourceInformationMarkerStart($composer4, 2023513938, "C:CompositionLocal.kt#9igjgp");
                        Object consume2 = $composer4.consume(CompositionLocalsKt.getLocalLayoutDirection());
                        ComposerKt.sourceInformationMarkerEnd($composer4);
                        LayoutDirection layoutDirection$iv$iv = (LayoutDirection) consume2;
                        ComposerKt.sourceInformationMarkerStart($composer4, 2023513938, "C:CompositionLocal.kt#9igjgp");
                        Object consume3 = $composer4.consume(CompositionLocalsKt.getLocalViewConfiguration());
                        ComposerKt.sourceInformationMarkerEnd($composer4);
                        ViewConfiguration viewConfiguration$iv$iv = (ViewConfiguration) consume3;
                        Function0 factory$iv$iv$iv = ComposeUiNode.Companion.getConstructor();
                        Function3 skippableUpdate$iv$iv$iv = LayoutKt.materializerOf(modifier$iv);
                        int $changed$iv$iv$iv = (($changed$iv$iv << 9) & 7168) | 6;
                        if (!($composer4.getApplier() instanceof Applier)) {
                            ComposablesKt.invalidApplier();
                        }
                        $composer4.startReusableNode();
                        if ($composer4.getInserting()) {
                            $composer4.createNode(factory$iv$iv$iv);
                        } else {
                            $composer4.useNode();
                        }
                        $composer4.disableReusing();
                        Composer $this$Layout_u24lambda_u2d0$iv$iv = Updater.m2247constructorimpl($composer4);
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, measurePolicy$iv, ComposeUiNode.Companion.getSetMeasurePolicy());
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, density$iv$iv, ComposeUiNode.Companion.getSetDensity());
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, layoutDirection$iv$iv, ComposeUiNode.Companion.getSetLayoutDirection());
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, viewConfiguration$iv$iv, ComposeUiNode.Companion.getSetViewConfiguration());
                        $composer4.enableReusing();
                        skippableUpdate$iv$iv$iv.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer4)), $composer4, Integer.valueOf(($changed$iv$iv$iv >> 3) & 112));
                        $composer4.startReplaceableGroup(2058660585);
                        $composer4.startReplaceableGroup(-678309503);
                        ComposerKt.sourceInformation($composer4, "C80@3988L9:Row.kt#2w3rfo");
                        if ((($changed$iv$iv$iv >> 9) & 14 & 11) == 2 && $composer4.getSkipping()) {
                            $composer4.skipToGroupEnd();
                        } else {
                            content$iv.invoke(RowScopeInstance.INSTANCE, $composer4, Integer.valueOf((($changed$iv >> 6) & 112) | 6));
                        }
                        $composer4.endReplaceableGroup();
                        $composer4.endReplaceableGroup();
                        $composer4.endNode();
                        $composer4.endReplaceableGroup();
                        $composer4.endReplaceableGroup();
                        if (ComposerKt.isTraceInProgress()) {
                            ComposerKt.traceEventEnd();
                            return;
                        }
                        return;
                    }
                    $composer4.skipToGroupEnd();
                }
            }), $composer3, ($dirty2 & 14) | 12582912 | ($dirty2 & 112) | ($dirty2 & 896) | ($dirty2 & 7168) | (57344 & $dirty2) | (458752 & $dirty2) | ($dirty2 & 3670016), 0);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Modifier modifier4 = modifier2;
        final Shape shape3 = shape2;
        final long j2 = containerColor3;
        final long j3 = contentColor2;
        final FloatingActionButtonElevation floatingActionButtonElevation = elevation3;
        final MutableInteractionSource mutableInteractionSource = interactionSource2;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material3.FloatingActionButtonKt$ExtendedFloatingActionButton$3
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
                invoke(composer, num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(Composer composer, int i8) {
                FloatingActionButtonKt.m1424ExtendedFloatingActionButtonXz6DiA(onClick, modifier4, shape3, j2, j3, floatingActionButtonElevation, mutableInteractionSource, content, composer, $changed | 1, i);
            }
        });
    }

    /* renamed from: ExtendedFloatingActionButton-ElI5-7k  reason: not valid java name */
    public static final void m1423ExtendedFloatingActionButtonElI57k(final Function2<? super Composer, ? super Integer, Unit> text, final Function2<? super Composer, ? super Integer, Unit> icon, final Function0<Unit> onClick, Modifier modifier, boolean expanded, Shape shape, long containerColor, long contentColor, FloatingActionButtonElevation elevation, MutableInteractionSource interactionSource, Composer $composer, final int $changed, final int i) {
        Object obj;
        boolean z;
        Object obj2;
        int $dirty;
        Object obj3;
        Object obj4;
        int $dirty2;
        Shape shape2;
        long containerColor2;
        long contentColor2;
        int $dirty3;
        long containerColor3;
        int i2;
        FloatingActionButtonElevation elevation2;
        Shape shape3;
        final boolean expanded2;
        final int $dirty4;
        MutableInteractionSource interactionSource2;
        Object modifier2;
        FloatingActionButtonElevation elevation3;
        Object value$iv$iv;
        boolean expanded3;
        Composer $composer2;
        int i3;
        int $dirty5;
        int i4;
        int i5;
        int i6;
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(icon, "icon");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        Composer $composer3 = $composer.startRestartGroup(-1387401842);
        ComposerKt.sourceInformation($composer3, "C(ExtendedFloatingActionButton)P(9,4,7,6,3,8,0:c#ui.graphics.Color,1:c#ui.graphics.Color)341@17331L16,342@17406L14,343@17448L31,344@17557L11,345@17620L39,347@17669L1269:FloatingActionButton.kt#uh7d8r");
        int $dirty6 = $changed;
        if ((i & 1) != 0) {
            $dirty6 |= 6;
        } else if (($changed & 14) == 0) {
            $dirty6 |= $composer3.changed(text) ? 4 : 2;
        }
        if ((i & 2) != 0) {
            $dirty6 |= 48;
        } else if (($changed & 112) == 0) {
            $dirty6 |= $composer3.changed(icon) ? 32 : 16;
        }
        if ((i & 4) != 0) {
            $dirty6 |= 384;
        } else if (($changed & 896) == 0) {
            $dirty6 |= $composer3.changed(onClick) ? 256 : 128;
        }
        int i7 = i & 8;
        if (i7 != 0) {
            $dirty6 |= 3072;
            obj = modifier;
        } else if (($changed & 7168) == 0) {
            obj = modifier;
            $dirty6 |= $composer3.changed(obj) ? 2048 : 1024;
        } else {
            obj = modifier;
        }
        int i8 = i & 16;
        if (i8 != 0) {
            $dirty6 |= 24576;
            z = expanded;
        } else if (($changed & 57344) == 0) {
            z = expanded;
            $dirty6 |= $composer3.changed(z) ? 16384 : 8192;
        } else {
            z = expanded;
        }
        if (($changed & 458752) == 0) {
            if ((i & 32) == 0) {
                obj2 = shape;
                if ($composer3.changed(obj2)) {
                    i6 = 131072;
                    $dirty6 |= i6;
                }
            } else {
                obj2 = shape;
            }
            i6 = 65536;
            $dirty6 |= i6;
        } else {
            obj2 = shape;
        }
        if (($changed & 3670016) == 0) {
            if ((i & 64) == 0 && $composer3.changed(containerColor)) {
                i5 = 1048576;
                $dirty6 |= i5;
            }
            i5 = 524288;
            $dirty6 |= i5;
        }
        if (($changed & 29360128) == 0) {
            if ((i & 128) == 0) {
                $dirty5 = $dirty6;
                if ($composer3.changed(contentColor)) {
                    i4 = 8388608;
                    $dirty = $dirty5 | i4;
                }
            } else {
                $dirty5 = $dirty6;
            }
            i4 = 4194304;
            $dirty = $dirty5 | i4;
        } else {
            $dirty = $dirty6;
        }
        if (($changed & 234881024) == 0) {
            if ((i & 256) == 0) {
                obj3 = elevation;
                if ($composer3.changed(obj3)) {
                    i3 = 67108864;
                    $dirty |= i3;
                }
            } else {
                obj3 = elevation;
            }
            i3 = 33554432;
            $dirty |= i3;
        } else {
            obj3 = elevation;
        }
        int i9 = i & 512;
        if (i9 != 0) {
            $dirty |= 805306368;
            obj4 = interactionSource;
        } else if ((1879048192 & $changed) == 0) {
            obj4 = interactionSource;
            $dirty |= $composer3.changed(obj4) ? 536870912 : 268435456;
        } else {
            obj4 = interactionSource;
        }
        if (($dirty & 1533916891) == 306783378 && $composer3.getSkipping()) {
            $composer3.skipToGroupEnd();
            containerColor3 = containerColor;
            contentColor2 = contentColor;
            expanded3 = z;
            shape3 = obj2;
            interactionSource2 = obj4;
            elevation3 = obj3;
            $composer2 = $composer3;
            modifier2 = obj;
        } else {
            $composer3.startDefaults();
            if (($changed & 1) == 0 || $composer3.getDefaultsInvalid()) {
                Modifier modifier3 = i7 != 0 ? Modifier.Companion : obj;
                boolean expanded4 = i8 != 0 ? true : z;
                if ((i & 32) != 0) {
                    int $dirty7 = $dirty & (-458753);
                    shape2 = FloatingActionButtonDefaults.INSTANCE.getExtendedFabShape($composer3, 6);
                    $dirty2 = $dirty7;
                } else {
                    $dirty2 = $dirty;
                    shape2 = obj2;
                }
                if ((i & 64) != 0) {
                    $dirty2 &= -3670017;
                    containerColor2 = FloatingActionButtonDefaults.INSTANCE.getContainerColor($composer3, 6);
                } else {
                    containerColor2 = containerColor;
                }
                if ((i & 128) != 0) {
                    $dirty3 = $dirty2 & (-29360129);
                    contentColor2 = ColorSchemeKt.m1338contentColorForek8zF_U(containerColor2, $composer3, ($dirty2 >> 18) & 14);
                } else {
                    contentColor2 = contentColor;
                    $dirty3 = $dirty2;
                }
                if ((i & 256) != 0) {
                    containerColor3 = containerColor2;
                    i2 = i9;
                    elevation2 = FloatingActionButtonDefaults.INSTANCE.m1420elevationxZ9QkE(0.0f, 0.0f, 0.0f, 0.0f, $composer3, 24576, 15);
                    $dirty3 &= -234881025;
                } else {
                    containerColor3 = containerColor2;
                    i2 = i9;
                    elevation2 = obj3;
                }
                if (i2 != 0) {
                    $composer3.startReplaceableGroup(-492369756);
                    ComposerKt.sourceInformation($composer3, "C(remember):Composables.kt#9igjgp");
                    Object it$iv$iv = $composer3.rememberedValue();
                    if (it$iv$iv == Composer.Companion.getEmpty()) {
                        value$iv$iv = InteractionSourceKt.MutableInteractionSource();
                        $composer3.updateRememberedValue(value$iv$iv);
                    } else {
                        value$iv$iv = it$iv$iv;
                    }
                    $composer3.endReplaceableGroup();
                    shape3 = shape2;
                    expanded2 = expanded4;
                    $dirty4 = $dirty3;
                    modifier2 = modifier3;
                    elevation3 = elevation2;
                    interactionSource2 = (MutableInteractionSource) value$iv$iv;
                } else {
                    shape3 = shape2;
                    expanded2 = expanded4;
                    $dirty4 = $dirty3;
                    interactionSource2 = interactionSource;
                    modifier2 = modifier3;
                    elevation3 = elevation2;
                }
            } else {
                $composer3.skipToGroupEnd();
                if ((i & 32) != 0) {
                    $dirty &= -458753;
                }
                if ((i & 64) != 0) {
                    $dirty &= -3670017;
                }
                if ((i & 128) != 0) {
                    $dirty &= -29360129;
                }
                if ((i & 256) != 0) {
                    containerColor3 = containerColor;
                    contentColor2 = contentColor;
                    $dirty4 = $dirty & (-234881025);
                    modifier2 = obj;
                    shape3 = obj2;
                    interactionSource2 = obj4;
                    elevation3 = obj3;
                    expanded2 = z;
                } else {
                    containerColor3 = containerColor;
                    contentColor2 = contentColor;
                    shape3 = obj2;
                    interactionSource2 = obj4;
                    elevation3 = obj3;
                    $dirty4 = $dirty;
                    modifier2 = obj;
                    expanded2 = z;
                }
            }
            $composer3.endDefaults();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(-1387401842, $dirty4, -1, "androidx.compose.material3.ExtendedFloatingActionButton (FloatingActionButton.kt:335)");
            }
            expanded3 = expanded2;
            $composer2 = $composer3;
            m1425FloatingActionButtonXz6DiA(onClick, modifier2, shape3, containerColor3, contentColor2, elevation3, interactionSource2, ComposableLambdaKt.composableLambda($composer3, 1172118032, true, new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material3.FloatingActionButtonKt$ExtendedFloatingActionButton$5
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                /* JADX WARN: Multi-variable type inference failed */
                {
                    super(2);
                }

                @Override // kotlin.jvm.functions.Function2
                public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
                    invoke(composer, num.intValue());
                    return Unit.INSTANCE;
                }

                public final void invoke(Composer $composer4, int $changed2) {
                    float startPadding;
                    float endPadding;
                    float m1872getContainerWidthD9Ej5fM;
                    EnterTransition enterTransition;
                    ExitTransition exitTransition;
                    Composer $composer5;
                    Composer $composer$iv;
                    float f;
                    float f2;
                    float f3;
                    ComposerKt.sourceInformation($composer4, "C359@18094L838:FloatingActionButton.kt#uh7d8r");
                    if (($changed2 & 11) != 2 || !$composer4.getSkipping()) {
                        if (ComposerKt.isTraceInProgress()) {
                            ComposerKt.traceEventStart(1172118032, $changed2, -1, "androidx.compose.material3.ExtendedFloatingActionButton.<anonymous> (FloatingActionButton.kt:355)");
                        }
                        if (expanded2) {
                            f3 = FloatingActionButtonKt.ExtendedFabStartIconPadding;
                            startPadding = f3;
                        } else {
                            startPadding = Dp.m5122constructorimpl(0);
                        }
                        if (expanded2) {
                            f2 = FloatingActionButtonKt.ExtendedFabTextPadding;
                            endPadding = f2;
                        } else {
                            endPadding = Dp.m5122constructorimpl(0);
                        }
                        Modifier.Companion companion = Modifier.Companion;
                        if (expanded2) {
                            f = FloatingActionButtonKt.ExtendedFabMinimumWidth;
                            m1872getContainerWidthD9Ej5fM = f;
                        } else {
                            m1872getContainerWidthD9Ej5fM = FabPrimaryTokens.INSTANCE.m1872getContainerWidthD9Ej5fM();
                        }
                        Modifier m418paddingqDBjuR0$default = PaddingKt.m418paddingqDBjuR0$default(SizeKt.m461sizeInqDBjuR0$default(companion, m1872getContainerWidthD9Ej5fM, 0.0f, 0.0f, 0.0f, 14, null), startPadding, 0.0f, endPadding, 0.0f, 10, null);
                        Alignment.Vertical centerVertically = Alignment.Companion.getCenterVertically();
                        Arrangement.HorizontalOrVertical start = expanded2 ? Arrangement.INSTANCE.getStart() : Arrangement.INSTANCE.getCenter();
                        Function2<Composer, Integer, Unit> function2 = icon;
                        final int i10 = $dirty4;
                        boolean z2 = expanded2;
                        final Function2<Composer, Integer, Unit> function22 = text;
                        $composer4.startReplaceableGroup(693286680);
                        ComposerKt.sourceInformation($composer4, "C(Row)P(2,1,3)78@3880L58,79@3943L130:Row.kt#2w3rfo");
                        MeasurePolicy measurePolicy$iv = RowKt.rowMeasurePolicy(start, centerVertically, $composer4, ((384 >> 3) & 14) | ((384 >> 3) & 112));
                        int $changed$iv$iv = (384 << 3) & 112;
                        $composer4.startReplaceableGroup(-1323940314);
                        ComposerKt.sourceInformation($composer4, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                        ComposerKt.sourceInformationMarkerStart($composer4, 2023513938, "C:CompositionLocal.kt#9igjgp");
                        Object consume = $composer4.consume(CompositionLocalsKt.getLocalDensity());
                        ComposerKt.sourceInformationMarkerEnd($composer4);
                        Density density$iv$iv = (Density) consume;
                        ComposerKt.sourceInformationMarkerStart($composer4, 2023513938, "C:CompositionLocal.kt#9igjgp");
                        Object consume2 = $composer4.consume(CompositionLocalsKt.getLocalLayoutDirection());
                        ComposerKt.sourceInformationMarkerEnd($composer4);
                        LayoutDirection layoutDirection$iv$iv = (LayoutDirection) consume2;
                        ComposerKt.sourceInformationMarkerStart($composer4, 2023513938, "C:CompositionLocal.kt#9igjgp");
                        Object consume3 = $composer4.consume(CompositionLocalsKt.getLocalViewConfiguration());
                        ComposerKt.sourceInformationMarkerEnd($composer4);
                        ViewConfiguration viewConfiguration$iv$iv = (ViewConfiguration) consume3;
                        Function0 factory$iv$iv$iv = ComposeUiNode.Companion.getConstructor();
                        Function3 skippableUpdate$iv$iv$iv = LayoutKt.materializerOf(m418paddingqDBjuR0$default);
                        int $changed$iv$iv$iv = (($changed$iv$iv << 9) & 7168) | 6;
                        if (!($composer4.getApplier() instanceof Applier)) {
                            ComposablesKt.invalidApplier();
                        }
                        $composer4.startReusableNode();
                        if ($composer4.getInserting()) {
                            $composer4.createNode(factory$iv$iv$iv);
                        } else {
                            $composer4.useNode();
                        }
                        $composer4.disableReusing();
                        Composer $this$Layout_u24lambda_u2d0$iv$iv = Updater.m2247constructorimpl($composer4);
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, measurePolicy$iv, ComposeUiNode.Companion.getSetMeasurePolicy());
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, density$iv$iv, ComposeUiNode.Companion.getSetDensity());
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, layoutDirection$iv$iv, ComposeUiNode.Companion.getSetLayoutDirection());
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, viewConfiguration$iv$iv, ComposeUiNode.Companion.getSetViewConfiguration());
                        $composer4.enableReusing();
                        skippableUpdate$iv$iv$iv.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer4)), $composer4, Integer.valueOf(($changed$iv$iv$iv >> 3) & 112));
                        $composer4.startReplaceableGroup(2058660585);
                        int $changed$iv = ($changed$iv$iv$iv >> 9) & 14;
                        $composer4.startReplaceableGroup(-678309503);
                        ComposerKt.sourceInformation($composer4, "C80@3988L9:Row.kt#2w3rfo");
                        if (($changed$iv & 11) == 2 && $composer4.getSkipping()) {
                            $composer4.skipToGroupEnd();
                            $composer$iv = $composer4;
                        } else {
                            int $changed3 = ((384 >> 6) & 112) | 6;
                            RowScope $this$invoke_u24lambda_u2d0 = RowScopeInstance.INSTANCE;
                            $composer4.startReplaceableGroup(1368928116);
                            ComposerKt.sourceInformation($composer4, "C369@18542L6,370@18561L361:FloatingActionButton.kt#uh7d8r");
                            int $dirty8 = $changed3;
                            if (($changed3 & 14) == 0) {
                                $dirty8 |= $composer4.changed($this$invoke_u24lambda_u2d0) ? 4 : 2;
                            }
                            int $changed$iv2 = $dirty8 & 91;
                            if ($changed$iv2 != 18 || !$composer4.getSkipping()) {
                                function2.invoke($composer4, Integer.valueOf((i10 >> 3) & 14));
                                enterTransition = FloatingActionButtonKt.ExtendedFabExpandAnimation;
                                exitTransition = FloatingActionButtonKt.ExtendedFabCollapseAnimation;
                                int i11 = ($dirty8 & 14) | 1600512 | ((i10 >> 9) & 112);
                                $composer5 = $composer4;
                                $composer$iv = $composer4;
                                AnimatedVisibilityKt.AnimatedVisibility($this$invoke_u24lambda_u2d0, z2, (Modifier) null, enterTransition, exitTransition, (String) null, ComposableLambdaKt.composableLambda($composer4, 176242764, true, new Function3<AnimatedVisibilityScope, Composer, Integer, Unit>() { // from class: androidx.compose.material3.FloatingActionButtonKt$ExtendedFloatingActionButton$5$1$1
                                    /* JADX INFO: Access modifiers changed from: package-private */
                                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                    /* JADX WARN: Multi-variable type inference failed */
                                    {
                                        super(3);
                                    }

                                    @Override // kotlin.jvm.functions.Function3
                                    public /* bridge */ /* synthetic */ Unit invoke(AnimatedVisibilityScope animatedVisibilityScope, Composer composer, Integer num) {
                                        invoke(animatedVisibilityScope, composer, num.intValue());
                                        return Unit.INSTANCE;
                                    }

                                    public final void invoke(AnimatedVisibilityScope AnimatedVisibility, Composer $composer6, int $changed4) {
                                        float f4;
                                        Intrinsics.checkNotNullParameter(AnimatedVisibility, "$this$AnimatedVisibility");
                                        ComposerKt.sourceInformation($composer6, "C375@18754L154:FloatingActionButton.kt#uh7d8r");
                                        if (ComposerKt.isTraceInProgress()) {
                                            ComposerKt.traceEventStart(176242764, $changed4, -1, "androidx.compose.material3.ExtendedFloatingActionButton.<anonymous>.<anonymous>.<anonymous> (FloatingActionButton.kt:374)");
                                        }
                                        Modifier modifier$iv = SemanticsModifierKt.clearAndSetSemantics(Modifier.Companion, new Function1<SemanticsPropertyReceiver, Unit>() { // from class: androidx.compose.material3.FloatingActionButtonKt$ExtendedFloatingActionButton$5$1$1.1
                                            @Override // kotlin.jvm.functions.Function1
                                            public /* bridge */ /* synthetic */ Unit invoke(SemanticsPropertyReceiver semanticsPropertyReceiver) {
                                                invoke2(semanticsPropertyReceiver);
                                                return Unit.INSTANCE;
                                            }

                                            /* renamed from: invoke  reason: avoid collision after fix types in other method */
                                            public final void invoke2(SemanticsPropertyReceiver clearAndSetSemantics) {
                                                Intrinsics.checkNotNullParameter(clearAndSetSemantics, "$this$clearAndSetSemantics");
                                            }
                                        });
                                        Function2<Composer, Integer, Unit> function23 = function22;
                                        int i12 = i10;
                                        $composer6.startReplaceableGroup(693286680);
                                        ComposerKt.sourceInformation($composer6, "C(Row)P(2,1,3)78@3880L58,79@3943L130:Row.kt#2w3rfo");
                                        Arrangement.Horizontal horizontalArrangement$iv = Arrangement.INSTANCE.getStart();
                                        Alignment.Vertical verticalAlignment$iv = Alignment.Companion.getTop();
                                        MeasurePolicy measurePolicy$iv2 = RowKt.rowMeasurePolicy(horizontalArrangement$iv, verticalAlignment$iv, $composer6, ((0 >> 3) & 14) | ((0 >> 3) & 112));
                                        int $changed$iv$iv2 = (0 << 3) & 112;
                                        $composer6.startReplaceableGroup(-1323940314);
                                        ComposerKt.sourceInformation($composer6, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                                        ComposerKt.sourceInformationMarkerStart($composer6, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                        Object consume4 = $composer6.consume(CompositionLocalsKt.getLocalDensity());
                                        ComposerKt.sourceInformationMarkerEnd($composer6);
                                        Density density$iv$iv2 = (Density) consume4;
                                        ComposerKt.sourceInformationMarkerStart($composer6, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                        Object consume5 = $composer6.consume(CompositionLocalsKt.getLocalLayoutDirection());
                                        ComposerKt.sourceInformationMarkerEnd($composer6);
                                        LayoutDirection layoutDirection$iv$iv2 = (LayoutDirection) consume5;
                                        ComposerKt.sourceInformationMarkerStart($composer6, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                        Object consume6 = $composer6.consume(CompositionLocalsKt.getLocalViewConfiguration());
                                        ComposerKt.sourceInformationMarkerEnd($composer6);
                                        ViewConfiguration viewConfiguration$iv$iv2 = (ViewConfiguration) consume6;
                                        Function0 factory$iv$iv$iv2 = ComposeUiNode.Companion.getConstructor();
                                        Function3 skippableUpdate$iv$iv$iv2 = LayoutKt.materializerOf(modifier$iv);
                                        int $changed$iv$iv$iv2 = (($changed$iv$iv2 << 9) & 7168) | 6;
                                        if (!($composer6.getApplier() instanceof Applier)) {
                                            ComposablesKt.invalidApplier();
                                        }
                                        $composer6.startReusableNode();
                                        if ($composer6.getInserting()) {
                                            $composer6.createNode(factory$iv$iv$iv2);
                                        } else {
                                            $composer6.useNode();
                                        }
                                        $composer6.disableReusing();
                                        Composer $this$Layout_u24lambda_u2d0$iv$iv2 = Updater.m2247constructorimpl($composer6);
                                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, measurePolicy$iv2, ComposeUiNode.Companion.getSetMeasurePolicy());
                                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, density$iv$iv2, ComposeUiNode.Companion.getSetDensity());
                                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, layoutDirection$iv$iv2, ComposeUiNode.Companion.getSetLayoutDirection());
                                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, viewConfiguration$iv$iv2, ComposeUiNode.Companion.getSetViewConfiguration());
                                        $composer6.enableReusing();
                                        skippableUpdate$iv$iv$iv2.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer6)), $composer6, Integer.valueOf(($changed$iv$iv$iv2 >> 3) & 112));
                                        $composer6.startReplaceableGroup(2058660585);
                                        int $changed$iv3 = ($changed$iv$iv$iv2 >> 9) & 14;
                                        $composer6.startReplaceableGroup(-678309503);
                                        ComposerKt.sourceInformation($composer6, "C80@3988L9:Row.kt#2w3rfo");
                                        if (($changed$iv3 & 11) == 2 && $composer6.getSkipping()) {
                                            $composer6.skipToGroupEnd();
                                        } else {
                                            RowScopeInstance rowScopeInstance = RowScopeInstance.INSTANCE;
                                            int $changed5 = ((0 >> 6) & 112) | 6;
                                            $composer6.startReplaceableGroup(-141102928);
                                            ComposerKt.sourceInformation($composer6, "C376@18814L49,377@18884L6:FloatingActionButton.kt#uh7d8r");
                                            if (($changed5 & 81) != 16 || !$composer6.getSkipping()) {
                                                f4 = FloatingActionButtonKt.ExtendedFabEndIconPadding;
                                                SpacerKt.Spacer(SizeKt.m462width3ABfNKs(Modifier.Companion, f4), $composer6, 6);
                                                function23.invoke($composer6, Integer.valueOf(i12 & 14));
                                            } else {
                                                $composer6.skipToGroupEnd();
                                            }
                                            $composer6.endReplaceableGroup();
                                        }
                                        $composer6.endReplaceableGroup();
                                        $composer6.endReplaceableGroup();
                                        $composer6.endNode();
                                        $composer6.endReplaceableGroup();
                                        $composer6.endReplaceableGroup();
                                        if (ComposerKt.isTraceInProgress()) {
                                            ComposerKt.traceEventEnd();
                                        }
                                    }
                                }), $composer5, i11, 18);
                            } else {
                                $composer4.skipToGroupEnd();
                                $composer5 = $composer4;
                                $composer$iv = $composer4;
                            }
                            $composer5.endReplaceableGroup();
                        }
                        $composer$iv.endReplaceableGroup();
                        $composer4.endReplaceableGroup();
                        $composer4.endNode();
                        $composer4.endReplaceableGroup();
                        $composer4.endReplaceableGroup();
                        if (ComposerKt.isTraceInProgress()) {
                            ComposerKt.traceEventEnd();
                            return;
                        }
                        return;
                    }
                    $composer4.skipToGroupEnd();
                }
            }), $composer3, (($dirty4 >> 6) & 14) | 12582912 | (($dirty4 >> 6) & 112) | (($dirty4 >> 9) & 896) | (($dirty4 >> 9) & 7168) | (($dirty4 >> 9) & 57344) | (($dirty4 >> 9) & 458752) | (($dirty4 >> 9) & 3670016), 0);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Modifier modifier4 = modifier2;
        final boolean z2 = expanded3;
        final Shape shape4 = shape3;
        final long j = containerColor3;
        final long j2 = contentColor2;
        final FloatingActionButtonElevation floatingActionButtonElevation = elevation3;
        final MutableInteractionSource mutableInteractionSource = interactionSource2;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material3.FloatingActionButtonKt$ExtendedFloatingActionButton$6
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
                invoke(composer, num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(Composer composer, int i10) {
                FloatingActionButtonKt.m1423ExtendedFloatingActionButtonElI57k(text, icon, onClick, modifier4, z2, shape4, j, j2, floatingActionButtonElevation, mutableInteractionSource, composer, $changed | 1, i);
            }
        });
    }
}
