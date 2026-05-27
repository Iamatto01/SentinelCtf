package androidx.compose.material;

import androidx.compose.foundation.BackgroundKt;
import androidx.compose.foundation.BorderStroke;
import androidx.compose.foundation.interaction.InteractionSourceKt;
import androidx.compose.foundation.interaction.MutableInteractionSource;
import androidx.compose.foundation.layout.Arrangement;
import androidx.compose.foundation.layout.BoxKt;
import androidx.compose.foundation.layout.BoxScopeInstance;
import androidx.compose.foundation.layout.PaddingKt;
import androidx.compose.foundation.layout.RowKt;
import androidx.compose.foundation.layout.RowScope;
import androidx.compose.foundation.layout.RowScopeInstance;
import androidx.compose.foundation.layout.SizeKt;
import androidx.compose.foundation.layout.SpacerKt;
import androidx.compose.foundation.shape.CornerBasedShape;
import androidx.compose.foundation.shape.CornerSizeKt;
import androidx.compose.foundation.shape.RoundedCornerShapeKt;
import androidx.compose.runtime.Applier;
import androidx.compose.runtime.ComposablesKt;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.CompositionLocalKt;
import androidx.compose.runtime.ProvidedValue;
import androidx.compose.runtime.RecomposeScopeImplKt;
import androidx.compose.runtime.ScopeUpdateScope;
import androidx.compose.runtime.SkippableUpdater;
import androidx.compose.runtime.State;
import androidx.compose.runtime.Updater;
import androidx.compose.runtime.internal.ComposableLambdaKt;
import androidx.compose.ui.Alignment;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.draw.ClipKt;
import androidx.compose.ui.graphics.Color;
import androidx.compose.ui.graphics.Shape;
import androidx.compose.ui.layout.LayoutKt;
import androidx.compose.ui.layout.MeasurePolicy;
import androidx.compose.ui.node.ComposeUiNode;
import androidx.compose.ui.platform.CompositionLocalsKt;
import androidx.compose.ui.platform.ViewConfiguration;
import androidx.compose.ui.semantics.Role;
import androidx.compose.ui.semantics.SemanticsModifierKt;
import androidx.compose.ui.semantics.SemanticsPropertiesKt;
import androidx.compose.ui.semantics.SemanticsPropertyReceiver;
import androidx.compose.ui.text.TextStyle;
import androidx.compose.ui.unit.Density;
import androidx.compose.ui.unit.Dp;
import androidx.compose.ui.unit.LayoutDirection;
import androidx.core.app.FrameMetricsAggregator;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: Chip.kt */
@Metadata(d1 = {"\u0000`\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\u001a\u008e\u0001\u0010\n\u001a\u00020\u000b2\f\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000b0\r2\b\b\u0002\u0010\u000e\u001a\u00020\u000f2\b\b\u0002\u0010\u0010\u001a\u00020\u00112\b\b\u0002\u0010\u0012\u001a\u00020\u00132\b\b\u0002\u0010\u0014\u001a\u00020\u00152\n\b\u0002\u0010\u0016\u001a\u0004\u0018\u00010\u00172\b\b\u0002\u0010\u0018\u001a\u00020\u00192\u0015\b\u0002\u0010\u001a\u001a\u000f\u0012\u0004\u0012\u00020\u000b\u0018\u00010\r¢\u0006\u0002\b\u001b2\u001c\u0010\u001c\u001a\u0018\u0012\u0004\u0012\u00020\u001e\u0012\u0004\u0012\u00020\u000b0\u001d¢\u0006\u0002\b\u001b¢\u0006\u0002\b\u001fH\u0007¢\u0006\u0002\u0010 \u001aÄ\u0001\u0010!\u001a\u00020\u000b2\u0006\u0010\"\u001a\u00020\u00112\f\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000b0\r2\b\b\u0002\u0010\u000e\u001a\u00020\u000f2\b\b\u0002\u0010\u0010\u001a\u00020\u00112\b\b\u0002\u0010\u0012\u001a\u00020\u00132\b\b\u0002\u0010\u0014\u001a\u00020\u00152\n\b\u0002\u0010\u0016\u001a\u0004\u0018\u00010\u00172\b\b\u0002\u0010\u0018\u001a\u00020#2\u0015\b\u0002\u0010\u001a\u001a\u000f\u0012\u0004\u0012\u00020\u000b\u0018\u00010\r¢\u0006\u0002\b\u001b2\u0015\b\u0002\u0010$\u001a\u000f\u0012\u0004\u0012\u00020\u000b\u0018\u00010\r¢\u0006\u0002\b\u001b2\u0015\b\u0002\u0010%\u001a\u000f\u0012\u0004\u0012\u00020\u000b\u0018\u00010\r¢\u0006\u0002\b\u001b2\u001c\u0010\u001c\u001a\u0018\u0012\u0004\u0012\u00020\u001e\u0012\u0004\u0012\u00020\u000b0\u001d¢\u0006\u0002\b\u001b¢\u0006\u0002\b\u001fH\u0007¢\u0006\u0002\u0010&\"\u0013\u0010\u0000\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\"\u0013\u0010\u0003\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\"\u0013\u0010\u0004\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\"\u0013\u0010\u0005\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\"\u000e\u0010\u0006\u001a\u00020\u0007X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\b\u001a\u00020\u0007X\u0082T¢\u0006\u0002\n\u0000\"\u0013\u0010\t\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006'"}, d2 = {"HorizontalPadding", "Landroidx/compose/ui/unit/Dp;", "F", "LeadingIconEndSpacing", "LeadingIconStartSpacing", "SelectedIconContainerSize", "SelectedOverlayOpacity", "", "SurfaceOverlayOpacity", "TrailingIconSpacing", "Chip", "", "onClick", "Lkotlin/Function0;", "modifier", "Landroidx/compose/ui/Modifier;", "enabled", "", "interactionSource", "Landroidx/compose/foundation/interaction/MutableInteractionSource;", "shape", "Landroidx/compose/ui/graphics/Shape;", OutlinedTextFieldKt.BorderId, "Landroidx/compose/foundation/BorderStroke;", "colors", "Landroidx/compose/material/ChipColors;", "leadingIcon", "Landroidx/compose/runtime/Composable;", "content", "Lkotlin/Function1;", "Landroidx/compose/foundation/layout/RowScope;", "Lkotlin/ExtensionFunctionType;", "(Lkotlin/jvm/functions/Function0;Landroidx/compose/ui/Modifier;ZLandroidx/compose/foundation/interaction/MutableInteractionSource;Landroidx/compose/ui/graphics/Shape;Landroidx/compose/foundation/BorderStroke;Landroidx/compose/material/ChipColors;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function3;Landroidx/compose/runtime/Composer;II)V", "FilterChip", "selected", "Landroidx/compose/material/SelectableChipColors;", "selectedIcon", "trailingIcon", "(ZLkotlin/jvm/functions/Function0;Landroidx/compose/ui/Modifier;ZLandroidx/compose/foundation/interaction/MutableInteractionSource;Landroidx/compose/ui/graphics/Shape;Landroidx/compose/foundation/BorderStroke;Landroidx/compose/material/SelectableChipColors;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function3;Landroidx/compose/runtime/Composer;III)V", "material_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ChipKt {
    private static final float SelectedOverlayOpacity = 0.16f;
    private static final float SurfaceOverlayOpacity = 0.12f;
    private static final float HorizontalPadding = Dp.m5122constructorimpl(12);
    private static final float LeadingIconStartSpacing = Dp.m5122constructorimpl(4);
    private static final float LeadingIconEndSpacing = Dp.m5122constructorimpl(8);
    private static final float TrailingIconSpacing = Dp.m5122constructorimpl(8);
    private static final float SelectedIconContainerSize = Dp.m5122constructorimpl(24);

    /* JADX WARN: Removed duplicated region for block: B:118:0x0199  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x019e  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x01a2  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x01a4  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x01a8  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x01eb  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x01f3  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x020f  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x0215  */
    /* JADX WARN: Removed duplicated region for block: B:138:0x0232  */
    /* JADX WARN: Removed duplicated region for block: B:140:0x0236  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x0246  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x025d  */
    /* JADX WARN: Removed duplicated region for block: B:147:0x030f  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x0319  */
    /* JADX WARN: Removed duplicated region for block: B:153:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void Chip(final kotlin.jvm.functions.Function0<kotlin.Unit> r35, androidx.compose.ui.Modifier r36, boolean r37, androidx.compose.foundation.interaction.MutableInteractionSource r38, androidx.compose.ui.graphics.Shape r39, androidx.compose.foundation.BorderStroke r40, androidx.compose.material.ChipColors r41, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r42, final kotlin.jvm.functions.Function3<? super androidx.compose.foundation.layout.RowScope, ? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r43, androidx.compose.runtime.Composer r44, final int r45, final int r46) {
        /*
            Method dump skipped, instructions count: 827
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material.ChipKt.Chip(kotlin.jvm.functions.Function0, androidx.compose.ui.Modifier, boolean, androidx.compose.foundation.interaction.MutableInteractionSource, androidx.compose.ui.graphics.Shape, androidx.compose.foundation.BorderStroke, androidx.compose.material.ChipColors, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function3, androidx.compose.runtime.Composer, int, int):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final long Chip$lambda$1(State<Color> state) {
        Object thisObj$iv = state.getValue();
        return ((Color) thisObj$iv).m2616unboximpl();
    }

    public static final void FilterChip(final boolean selected, final Function0<Unit> onClick, Modifier modifier, boolean enabled, MutableInteractionSource interactionSource, Shape shape, BorderStroke border, SelectableChipColors colors, Function2<? super Composer, ? super Integer, Unit> function2, Function2<? super Composer, ? super Integer, Unit> function22, Function2<? super Composer, ? super Integer, Unit> function23, final Function3<? super RowScope, ? super Composer, ? super Integer, Unit> content, Composer $composer, final int $changed, final int $changed1, final int i) {
        Object modifier2;
        Modifier modifier3;
        boolean enabled2;
        MutableInteractionSource interactionSource2;
        CornerBasedShape shape2;
        SelectableChipColors colors2;
        Function2 trailingIcon;
        Function2 leadingIcon;
        MutableInteractionSource interactionSource3;
        Shape shape3;
        Function2 selectedIcon;
        BorderStroke border2;
        SelectableChipColors colors3;
        boolean enabled3;
        int $dirty;
        Object value$iv$iv;
        long m2604copywmQWz5c;
        final SelectableChipColors colors4;
        final boolean enabled4;
        Modifier modifier4;
        Composer $composer2;
        int i2;
        int i3;
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        Intrinsics.checkNotNullParameter(content, "content");
        Composer $composer3 = $composer.startRestartGroup(-1259208246);
        ComposerKt.sourceInformation($composer3, "C(FilterChip)P(8,7,6,3,4,10!2,5,9,11)188@8703L39,189@8777L6,191@8904L18,198@9235L31,205@9473L34,199@9271L4037:Chip.kt#jmzs0o");
        int $dirty2 = $changed;
        int $dirty1 = $changed1;
        if ((i & 1) != 0) {
            $dirty2 |= 6;
        } else if (($changed & 14) == 0) {
            $dirty2 |= $composer3.changed(selected) ? 4 : 2;
        }
        if ((i & 2) != 0) {
            $dirty2 |= 48;
        } else if (($changed & 112) == 0) {
            $dirty2 |= $composer3.changedInstance(onClick) ? 32 : 16;
        }
        int i4 = i & 4;
        if (i4 != 0) {
            $dirty2 |= 384;
            modifier2 = modifier;
        } else if (($changed & 896) == 0) {
            modifier2 = modifier;
            $dirty2 |= $composer3.changed(modifier2) ? 256 : 128;
        } else {
            modifier2 = modifier;
        }
        int i5 = i & 8;
        if (i5 != 0) {
            $dirty2 |= 3072;
        } else if (($changed & 7168) == 0) {
            $dirty2 |= $composer3.changed(enabled) ? 2048 : 1024;
        }
        int i6 = i & 16;
        if (i6 != 0) {
            $dirty2 |= 24576;
        } else if (($changed & 57344) == 0) {
            $dirty2 |= $composer3.changed(interactionSource) ? 16384 : 8192;
        }
        if (($changed & 458752) == 0) {
            if ((i & 32) == 0 && $composer3.changed(shape)) {
                i3 = 131072;
                $dirty2 |= i3;
            }
            i3 = 65536;
            $dirty2 |= i3;
        }
        int i7 = i & 64;
        if (i7 != 0) {
            $dirty2 |= 1572864;
        } else if (($changed & 3670016) == 0) {
            $dirty2 |= $composer3.changed(border) ? 1048576 : 524288;
        }
        if (($changed & 29360128) == 0) {
            if ((i & 128) == 0 && $composer3.changed(colors)) {
                i2 = 8388608;
                $dirty2 |= i2;
            }
            i2 = 4194304;
            $dirty2 |= i2;
        }
        int i8 = i & 256;
        if (i8 != 0) {
            $dirty2 |= 100663296;
        } else if (($changed & 234881024) == 0) {
            $dirty2 |= $composer3.changedInstance(function2) ? 67108864 : 33554432;
        }
        int i9 = i & 512;
        if (i9 != 0) {
            $dirty2 |= 805306368;
        } else if (($changed & 1879048192) == 0) {
            $dirty2 |= $composer3.changedInstance(function22) ? 536870912 : 268435456;
        }
        int i10 = i & 1024;
        if (i10 != 0) {
            $dirty1 |= 6;
        } else if (($changed1 & 14) == 0) {
            $dirty1 |= $composer3.changedInstance(function23) ? 4 : 2;
        }
        if ((i & 2048) != 0) {
            $dirty1 |= 48;
        } else if (($changed1 & 112) == 0) {
            $dirty1 |= $composer3.changedInstance(content) ? 32 : 16;
        }
        final int $dirty12 = $dirty1;
        if ((1533916891 & $dirty2) == 306783378 && ($dirty12 & 91) == 18 && $composer3.getSkipping()) {
            $composer3.skipToGroupEnd();
            enabled4 = enabled;
            interactionSource3 = interactionSource;
            shape3 = shape;
            border2 = border;
            colors4 = colors;
            leadingIcon = function2;
            selectedIcon = function22;
            trailingIcon = function23;
            modifier4 = modifier2;
            $composer2 = $composer3;
        } else {
            $composer3.startDefaults();
            if (($changed & 1) == 0 || $composer3.getDefaultsInvalid()) {
                Modifier.Companion modifier5 = i4 != 0 ? Modifier.Companion : modifier2;
                boolean enabled5 = i5 != 0 ? true : enabled;
                if (i6 != 0) {
                    $composer3.startReplaceableGroup(-492369756);
                    ComposerKt.sourceInformation($composer3, "CC(remember):Composables.kt#9igjgp");
                    modifier3 = modifier5;
                    Object it$iv$iv = $composer3.rememberedValue();
                    enabled2 = enabled5;
                    if (it$iv$iv == Composer.Companion.getEmpty()) {
                        value$iv$iv = InteractionSourceKt.MutableInteractionSource();
                        $composer3.updateRememberedValue(value$iv$iv);
                    } else {
                        value$iv$iv = it$iv$iv;
                    }
                    $composer3.endReplaceableGroup();
                    interactionSource2 = (MutableInteractionSource) value$iv$iv;
                } else {
                    modifier3 = modifier5;
                    enabled2 = enabled5;
                    interactionSource2 = interactionSource;
                }
                if ((i & 32) != 0) {
                    shape2 = MaterialTheme.INSTANCE.getShapes($composer3, 6).getSmall().copy(CornerSizeKt.CornerSize(50));
                    $dirty2 &= -458753;
                } else {
                    shape2 = shape;
                }
                BorderStroke border3 = i7 != 0 ? null : border;
                if ((i & 128) != 0) {
                    colors2 = ChipDefaults.INSTANCE.m946filterChipColorsJ08w3E(0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, $composer3, 805306368, FrameMetricsAggregator.EVERY_DURATION);
                    $dirty2 &= -29360129;
                } else {
                    colors2 = colors;
                }
                Function2 leadingIcon2 = i8 != 0 ? null : function2;
                Function2 selectedIcon2 = i9 != 0 ? null : function22;
                if (i10 != 0) {
                    leadingIcon = leadingIcon2;
                    interactionSource3 = interactionSource2;
                    shape3 = shape2;
                    selectedIcon = selectedIcon2;
                    trailingIcon = null;
                    border2 = border3;
                    colors3 = colors2;
                    modifier2 = modifier3;
                    enabled3 = enabled2;
                    $dirty = $dirty2;
                } else {
                    trailingIcon = function23;
                    leadingIcon = leadingIcon2;
                    interactionSource3 = interactionSource2;
                    shape3 = shape2;
                    selectedIcon = selectedIcon2;
                    border2 = border3;
                    colors3 = colors2;
                    modifier2 = modifier3;
                    enabled3 = enabled2;
                    $dirty = $dirty2;
                }
            } else {
                $composer3.skipToGroupEnd();
                if ((i & 32) != 0) {
                    $dirty2 &= -458753;
                }
                if ((i & 128) != 0) {
                    enabled3 = enabled;
                    interactionSource3 = interactionSource;
                    shape3 = shape;
                    border2 = border;
                    colors3 = colors;
                    leadingIcon = function2;
                    selectedIcon = function22;
                    trailingIcon = function23;
                    $dirty = (-29360129) & $dirty2;
                } else {
                    enabled3 = enabled;
                    interactionSource3 = interactionSource;
                    shape3 = shape;
                    border2 = border;
                    colors3 = colors;
                    leadingIcon = function2;
                    selectedIcon = function22;
                    trailingIcon = function23;
                    $dirty = $dirty2;
                }
            }
            $composer3.endDefaults();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(-1259208246, $dirty, $dirty12, "androidx.compose.material.FilterChip (Chip.kt:183)");
            }
            final State contentColor = colors3.contentColor(enabled3, selected, $composer3, (($dirty >> 9) & 14) | (($dirty << 3) & 112) | (($dirty >> 15) & 896));
            Modifier semantics$default = SemanticsModifierKt.semantics$default(modifier2, false, new Function1<SemanticsPropertyReceiver, Unit>() { // from class: androidx.compose.material.ChipKt$FilterChip$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(SemanticsPropertyReceiver semanticsPropertyReceiver) {
                    invoke2(semanticsPropertyReceiver);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2(SemanticsPropertyReceiver semantics) {
                    Intrinsics.checkNotNullParameter(semantics, "$this$semantics");
                    SemanticsPropertiesKt.m4495setRolekuIjeqM(semantics, Role.Companion.m4482getCheckboxo7Vup1c());
                }
            }, 1, null);
            long m2616unboximpl = colors3.backgroundColor(enabled3, selected, $composer3, (($dirty >> 9) & 14) | (($dirty << 3) & 112) | (($dirty >> 15) & 896)).getValue().m2616unboximpl();
            m2604copywmQWz5c = Color.m2604copywmQWz5c(r0, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r0) : 1.0f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r0) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r0) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(contentColor.getValue().m2616unboximpl()) : 0.0f);
            final Function2 function24 = leadingIcon;
            final int $dirty3 = $dirty;
            final Function2 function25 = selectedIcon;
            colors4 = colors3;
            final Function2 function26 = trailingIcon;
            enabled4 = enabled3;
            modifier4 = modifier2;
            $composer2 = $composer3;
            SurfaceKt.m1126SurfaceNy5ogXk(selected, onClick, semantics$default, enabled4, shape3, m2616unboximpl, m2604copywmQWz5c, border2, 0.0f, interactionSource3, ComposableLambdaKt.composableLambda($composer3, 722126431, true, new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material.ChipKt$FilterChip$3
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
                    ComposerKt.sourceInformation($composer4, "C210@9657L3645:Chip.kt#jmzs0o");
                    if (($changed2 & 11) != 2 || !$composer4.getSkipping()) {
                        if (ComposerKt.isTraceInProgress()) {
                            ComposerKt.traceEventStart(722126431, $changed2, -1, "androidx.compose.material.FilterChip.<anonymous> (Chip.kt:209)");
                        }
                        ProvidedValue[] providedValueArr = {ContentAlphaKt.getLocalContentAlpha().provides(Float.valueOf(Color.m2608getAlphaimpl(contentColor.getValue().m2616unboximpl())))};
                        final Function2<Composer, Integer, Unit> function27 = function24;
                        final boolean z = selected;
                        final Function2<Composer, Integer, Unit> function28 = function25;
                        final Function2<Composer, Integer, Unit> function29 = function26;
                        final Function3<RowScope, Composer, Integer, Unit> function3 = content;
                        final int i11 = $dirty12;
                        final SelectableChipColors selectableChipColors = colors4;
                        final boolean z2 = enabled4;
                        final int i12 = $dirty3;
                        final State<Color> state = contentColor;
                        CompositionLocalKt.CompositionLocalProvider(providedValueArr, ComposableLambdaKt.composableLambda($composer4, 1582291359, true, new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material.ChipKt$FilterChip$3.1
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

                            public final void invoke(Composer $composer5, int $changed3) {
                                ComposerKt.sourceInformation($composer5, "C212@9805L10,211@9749L3543:Chip.kt#jmzs0o");
                                if (($changed3 & 11) != 2 || !$composer5.getSkipping()) {
                                    if (ComposerKt.isTraceInProgress()) {
                                        ComposerKt.traceEventStart(1582291359, $changed3, -1, "androidx.compose.material.FilterChip.<anonymous>.<anonymous> (Chip.kt:210)");
                                    }
                                    TextStyle body2 = MaterialTheme.INSTANCE.getTypography($composer5, 6).getBody2();
                                    final Function2<Composer, Integer, Unit> function210 = function27;
                                    final boolean z3 = z;
                                    final Function2<Composer, Integer, Unit> function211 = function28;
                                    final Function2<Composer, Integer, Unit> function212 = function29;
                                    final Function3<RowScope, Composer, Integer, Unit> function32 = function3;
                                    final int i13 = i11;
                                    final SelectableChipColors selectableChipColors2 = selectableChipColors;
                                    final boolean z4 = z2;
                                    final int i14 = i12;
                                    final State<Color> state2 = state;
                                    TextKt.ProvideTextStyle(body2, ComposableLambdaKt.composableLambda($composer5, -1543702066, true, new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material.ChipKt.FilterChip.3.1.1
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

                                        /* JADX WARN: Multi-variable type inference failed */
                                        /* JADX WARN: Type inference failed for: r2v27, types: [androidx.compose.ui.Modifier] */
                                        public final void invoke(Composer $composer6, int $changed4) {
                                            float m5122constructorimpl;
                                            float m5122constructorimpl2;
                                            float f;
                                            Composer $composer$iv;
                                            RowScope $this$invoke_u24lambda_u242;
                                            int $changed5;
                                            float f2;
                                            float f3;
                                            float f4;
                                            float f5;
                                            float f6;
                                            float f7;
                                            ComposerKt.sourceInformation($composer6, "C214@9854L3424:Chip.kt#jmzs0o");
                                            if (($changed4 & 11) != 2 || !$composer6.getSkipping()) {
                                                if (ComposerKt.isTraceInProgress()) {
                                                    ComposerKt.traceEventStart(-1543702066, $changed4, -1, "androidx.compose.material.FilterChip.<anonymous>.<anonymous>.<anonymous> (Chip.kt:213)");
                                                }
                                                Modifier m442defaultMinSizeVpY3zN4$default = SizeKt.m442defaultMinSizeVpY3zN4$default(Modifier.Companion, 0.0f, ChipDefaults.INSTANCE.m948getMinHeightD9Ej5fM(), 1, null);
                                                if (function210 == null && (!z3 || function211 == null)) {
                                                    f7 = ChipKt.HorizontalPadding;
                                                    m5122constructorimpl = f7;
                                                } else {
                                                    m5122constructorimpl = Dp.m5122constructorimpl(0);
                                                }
                                                if (function212 == null) {
                                                    f6 = ChipKt.HorizontalPadding;
                                                    m5122constructorimpl2 = f6;
                                                } else {
                                                    m5122constructorimpl2 = Dp.m5122constructorimpl(0);
                                                }
                                                Modifier modifier$iv = PaddingKt.m418paddingqDBjuR0$default(m442defaultMinSizeVpY3zN4$default, m5122constructorimpl, 0.0f, m5122constructorimpl2, 0.0f, 10, null);
                                                Arrangement.Horizontal horizontalArrangement$iv = Arrangement.INSTANCE.getStart();
                                                Alignment.Vertical verticalAlignment$iv = Alignment.Companion.getCenterVertically();
                                                Function2<Composer, Integer, Unit> function213 = function210;
                                                boolean z5 = z3;
                                                Function2<Composer, Integer, Unit> function214 = function211;
                                                Function3<RowScope, Composer, Integer, Unit> function33 = function32;
                                                int i15 = i13;
                                                Function2<Composer, Integer, Unit> function215 = function212;
                                                SelectableChipColors selectableChipColors3 = selectableChipColors2;
                                                boolean z6 = z4;
                                                int i16 = i14;
                                                State<Color> state3 = state2;
                                                $composer6.startReplaceableGroup(693286680);
                                                ComposerKt.sourceInformation($composer6, "CC(Row)P(2,1,3)78@3913L58,79@3976L130:Row.kt#2w3rfo");
                                                MeasurePolicy measurePolicy$iv = RowKt.rowMeasurePolicy(horizontalArrangement$iv, verticalAlignment$iv, $composer6, ((432 >> 3) & 14) | ((432 >> 3) & 112));
                                                int $changed$iv$iv = (432 << 3) & 112;
                                                $composer6.startReplaceableGroup(-1323940314);
                                                ComposerKt.sourceInformation($composer6, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                                                ComposerKt.sourceInformationMarkerStart($composer6, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                                Object consume = $composer6.consume(CompositionLocalsKt.getLocalDensity());
                                                ComposerKt.sourceInformationMarkerEnd($composer6);
                                                Density density$iv$iv = (Density) consume;
                                                ComposerKt.sourceInformationMarkerStart($composer6, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                                Object consume2 = $composer6.consume(CompositionLocalsKt.getLocalLayoutDirection());
                                                ComposerKt.sourceInformationMarkerEnd($composer6);
                                                LayoutDirection layoutDirection$iv$iv = (LayoutDirection) consume2;
                                                ComposerKt.sourceInformationMarkerStart($composer6, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                                Object consume3 = $composer6.consume(CompositionLocalsKt.getLocalViewConfiguration());
                                                ComposerKt.sourceInformationMarkerEnd($composer6);
                                                ViewConfiguration viewConfiguration$iv$iv = (ViewConfiguration) consume3;
                                                Function0 factory$iv$iv$iv = ComposeUiNode.Companion.getConstructor();
                                                Function3 skippableUpdate$iv$iv$iv = LayoutKt.materializerOf(modifier$iv);
                                                int $changed$iv$iv$iv = (($changed$iv$iv << 9) & 7168) | 6;
                                                if (!($composer6.getApplier() instanceof Applier)) {
                                                    ComposablesKt.invalidApplier();
                                                }
                                                $composer6.startReusableNode();
                                                if ($composer6.getInserting()) {
                                                    $composer6.createNode(factory$iv$iv$iv);
                                                } else {
                                                    $composer6.useNode();
                                                }
                                                $composer6.disableReusing();
                                                Composer $this$Layout_u24lambda_u2d0$iv$iv = Updater.m2247constructorimpl($composer6);
                                                Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, measurePolicy$iv, ComposeUiNode.Companion.getSetMeasurePolicy());
                                                Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, density$iv$iv, ComposeUiNode.Companion.getSetDensity());
                                                Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, layoutDirection$iv$iv, ComposeUiNode.Companion.getSetLayoutDirection());
                                                Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, viewConfiguration$iv$iv, ComposeUiNode.Companion.getSetViewConfiguration());
                                                $composer6.enableReusing();
                                                skippableUpdate$iv$iv$iv.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer6)), $composer6, Integer.valueOf(($changed$iv$iv$iv >> 3) & 112));
                                                $composer6.startReplaceableGroup(2058660585);
                                                int i17 = ($changed$iv$iv$iv >> 9) & 14;
                                                ComposerKt.sourceInformationMarkerStart($composer6, -326682283, "C80@4021L9:Row.kt#2w3rfo");
                                                int $changed6 = ((432 >> 6) & 112) | 6;
                                                RowScope $this$invoke_u24lambda_u2422 = RowScopeInstance.INSTANCE;
                                                ComposerKt.sourceInformationMarkerStart($composer6, -1943412077, "C276@13006L9:Chip.kt#jmzs0o");
                                                $composer6.startReplaceableGroup(-1943412077);
                                                ComposerKt.sourceInformation($composer6, "237@10866L47,238@10938L1955,274@12918L45");
                                                if (function213 != null || (z5 && function214 != null)) {
                                                    f = ChipKt.LeadingIconStartSpacing;
                                                    SpacerKt.Spacer(SizeKt.m462width3ABfNKs(Modifier.Companion, f), $composer6, 6);
                                                    $composer6.startReplaceableGroup(733328855);
                                                    ComposerKt.sourceInformation($composer6, "CC(Box)P(2,1,3)70@3267L67,71@3339L130:Box.kt#2w3rfo");
                                                    Modifier modifier$iv2 = Modifier.Companion;
                                                    Alignment contentAlignment$iv = Alignment.Companion.getTopStart();
                                                    $composer$iv = $composer6;
                                                    MeasurePolicy measurePolicy$iv2 = BoxKt.rememberBoxMeasurePolicy(contentAlignment$iv, false, $composer6, ((0 >> 3) & 14) | ((0 >> 3) & 112));
                                                    int $changed$iv$iv2 = (0 << 3) & 112;
                                                    $composer6.startReplaceableGroup(-1323940314);
                                                    ComposerKt.sourceInformation($composer6, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                                                    ComposerKt.sourceInformationMarkerStart($composer6, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                                    Object consume4 = $composer6.consume(CompositionLocalsKt.getLocalDensity());
                                                    ComposerKt.sourceInformationMarkerEnd($composer6);
                                                    Density density$iv$iv2 = (Density) consume4;
                                                    $this$invoke_u24lambda_u242 = $this$invoke_u24lambda_u2422;
                                                    ComposerKt.sourceInformationMarkerStart($composer6, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                                    Object consume5 = $composer6.consume(CompositionLocalsKt.getLocalLayoutDirection());
                                                    ComposerKt.sourceInformationMarkerEnd($composer6);
                                                    LayoutDirection layoutDirection$iv$iv2 = (LayoutDirection) consume5;
                                                    $changed5 = $changed6;
                                                    ComposerKt.sourceInformationMarkerStart($composer6, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                                    Object consume6 = $composer6.consume(CompositionLocalsKt.getLocalViewConfiguration());
                                                    ComposerKt.sourceInformationMarkerEnd($composer6);
                                                    ViewConfiguration viewConfiguration$iv$iv2 = (ViewConfiguration) consume6;
                                                    Function0 factory$iv$iv$iv2 = ComposeUiNode.Companion.getConstructor();
                                                    Function3 skippableUpdate$iv$iv$iv2 = LayoutKt.materializerOf(modifier$iv2);
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
                                                    int i18 = ($changed$iv$iv$iv2 >> 9) & 14;
                                                    ComposerKt.sourceInformationMarkerStart($composer6, -1253629305, "C72@3384L9:Box.kt#2w3rfo");
                                                    BoxScopeInstance boxScopeInstance = BoxScopeInstance.INSTANCE;
                                                    int i19 = ((0 >> 6) & 112) | 6;
                                                    ComposerKt.sourceInformationMarkerStart($composer6, 649985655, "C:Chip.kt#jmzs0o");
                                                    $composer6.startReplaceableGroup(649985655);
                                                    ComposerKt.sourceInformation($composer6, "240@11061L141,244@11235L297");
                                                    if (function213 != null) {
                                                        State leadingIconColor = selectableChipColors3.leadingIconColor(z6, z5, $composer6, ((i16 >> 9) & 14) | ((i16 << 3) & 112) | ((i16 >> 15) & 896));
                                                        CompositionLocalKt.CompositionLocalProvider(new ProvidedValue[]{ContentColorKt.getLocalContentColor().provides(leadingIconColor.getValue()), ContentAlphaKt.getLocalContentAlpha().provides(Float.valueOf(Color.m2608getAlphaimpl(leadingIconColor.getValue().m2616unboximpl())))}, function213, $composer6, ((i16 >> 21) & 112) | 8);
                                                    }
                                                    $composer6.endReplaceableGroup();
                                                    $composer6.startReplaceableGroup(-1943411263);
                                                    ComposerKt.sourceInformation($composer6, "263@12386L451");
                                                    if (z5 && function214 != null) {
                                                        Modifier.Companion companion = Modifier.Companion;
                                                        long iconColor = state3.getValue().m2616unboximpl();
                                                        $composer6.startReplaceableGroup(649986486);
                                                        ComposerKt.sourceInformation($composer6, "261@12279L34");
                                                        if (function213 != null) {
                                                            f3 = ChipKt.SelectedIconContainerSize;
                                                            companion = ClipKt.clip(BackgroundKt.m150backgroundbw27NRU(SizeKt.m449requiredSize3ABfNKs(Modifier.Companion, f3), state3.getValue().m2616unboximpl(), RoundedCornerShapeKt.getCircleShape()), RoundedCornerShapeKt.getCircleShape());
                                                            iconColor = selectableChipColors3.backgroundColor(z6, z5, $composer6, ((i16 >> 9) & 14) | ((i16 << 3) & 112) | ((i16 >> 15) & 896)).getValue().m2616unboximpl();
                                                        }
                                                        $composer6.endReplaceableGroup();
                                                        Alignment contentAlignment$iv2 = Alignment.Companion.getCenter();
                                                        $composer6.startReplaceableGroup(733328855);
                                                        ComposerKt.sourceInformation($composer6, "CC(Box)P(2,1,3)70@3267L67,71@3339L130:Box.kt#2w3rfo");
                                                        MeasurePolicy measurePolicy$iv3 = BoxKt.rememberBoxMeasurePolicy(contentAlignment$iv2, false, $composer6, ((48 >> 3) & 14) | ((48 >> 3) & 112));
                                                        int $changed$iv$iv3 = (48 << 3) & 112;
                                                        $composer6.startReplaceableGroup(-1323940314);
                                                        ComposerKt.sourceInformation($composer6, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                                                        ComposerKt.sourceInformationMarkerStart($composer6, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                                        Object consume7 = $composer6.consume(CompositionLocalsKt.getLocalDensity());
                                                        ComposerKt.sourceInformationMarkerEnd($composer6);
                                                        Density density$iv$iv3 = (Density) consume7;
                                                        ComposerKt.sourceInformationMarkerStart($composer6, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                                        Object consume8 = $composer6.consume(CompositionLocalsKt.getLocalLayoutDirection());
                                                        ComposerKt.sourceInformationMarkerEnd($composer6);
                                                        LayoutDirection layoutDirection$iv$iv3 = (LayoutDirection) consume8;
                                                        ComposerKt.sourceInformationMarkerStart($composer6, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                                        Object consume9 = $composer6.consume(CompositionLocalsKt.getLocalViewConfiguration());
                                                        ComposerKt.sourceInformationMarkerEnd($composer6);
                                                        ViewConfiguration viewConfiguration$iv$iv3 = (ViewConfiguration) consume9;
                                                        Function0 factory$iv$iv$iv3 = ComposeUiNode.Companion.getConstructor();
                                                        Function3 skippableUpdate$iv$iv$iv3 = LayoutKt.materializerOf(companion);
                                                        int $changed$iv$iv$iv3 = (($changed$iv$iv3 << 9) & 7168) | 6;
                                                        if (!($composer6.getApplier() instanceof Applier)) {
                                                            ComposablesKt.invalidApplier();
                                                        }
                                                        $composer6.startReusableNode();
                                                        if ($composer6.getInserting()) {
                                                            $composer6.createNode(factory$iv$iv$iv3);
                                                        } else {
                                                            $composer6.useNode();
                                                        }
                                                        $composer6.disableReusing();
                                                        Composer $this$Layout_u24lambda_u2d0$iv$iv3 = Updater.m2247constructorimpl($composer6);
                                                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv3, measurePolicy$iv3, ComposeUiNode.Companion.getSetMeasurePolicy());
                                                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv3, density$iv$iv3, ComposeUiNode.Companion.getSetDensity());
                                                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv3, layoutDirection$iv$iv3, ComposeUiNode.Companion.getSetLayoutDirection());
                                                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv3, viewConfiguration$iv$iv3, ComposeUiNode.Companion.getSetViewConfiguration());
                                                        $composer6.enableReusing();
                                                        skippableUpdate$iv$iv$iv3.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer6)), $composer6, Integer.valueOf(($changed$iv$iv$iv3 >> 3) & 112));
                                                        $composer6.startReplaceableGroup(2058660585);
                                                        int i20 = ($changed$iv$iv$iv3 >> 9) & 14;
                                                        ComposerKt.sourceInformationMarkerStart($composer6, -1253629305, "C72@3384L9:Box.kt#2w3rfo");
                                                        BoxScopeInstance boxScopeInstance2 = BoxScopeInstance.INSTANCE;
                                                        int i21 = ((48 >> 6) & 112) | 6;
                                                        ComposerKt.sourceInformationMarkerStart($composer6, 333805171, "C267@12599L204:Chip.kt#jmzs0o");
                                                        CompositionLocalKt.CompositionLocalProvider(new ProvidedValue[]{ContentColorKt.getLocalContentColor().provides(Color.m2596boximpl(iconColor))}, function214, $composer6, ((i16 >> 24) & 112) | 8);
                                                        ComposerKt.sourceInformationMarkerEnd($composer6);
                                                        ComposerKt.sourceInformationMarkerEnd($composer6);
                                                        $composer6.endReplaceableGroup();
                                                        $composer6.endNode();
                                                        $composer6.endReplaceableGroup();
                                                        $composer6.endReplaceableGroup();
                                                    }
                                                    $composer6.endReplaceableGroup();
                                                    ComposerKt.sourceInformationMarkerEnd($composer6);
                                                    ComposerKt.sourceInformationMarkerEnd($composer6);
                                                    $composer6.endReplaceableGroup();
                                                    $composer6.endNode();
                                                    $composer6.endReplaceableGroup();
                                                    $composer6.endReplaceableGroup();
                                                    f2 = ChipKt.LeadingIconEndSpacing;
                                                    SpacerKt.Spacer(SizeKt.m462width3ABfNKs(Modifier.Companion, f2), $composer6, 6);
                                                } else {
                                                    $this$invoke_u24lambda_u242 = $this$invoke_u24lambda_u2422;
                                                    $composer$iv = $composer6;
                                                    $changed5 = $changed6;
                                                }
                                                $composer6.endReplaceableGroup();
                                                function33.invoke($this$invoke_u24lambda_u242, $composer6, Integer.valueOf(($changed5 & 14) | (i15 & 112)));
                                                $composer6.startReplaceableGroup(-1181292859);
                                                ComposerKt.sourceInformation($composer6, "278@13088L43,279@13156L14,280@13195L43");
                                                if (function215 != null) {
                                                    f4 = ChipKt.TrailingIconSpacing;
                                                    SpacerKt.Spacer(SizeKt.m462width3ABfNKs(Modifier.Companion, f4), $composer6, 6);
                                                    function215.invoke($composer6, Integer.valueOf(i15 & 14));
                                                    f5 = ChipKt.TrailingIconSpacing;
                                                    SpacerKt.Spacer(SizeKt.m462width3ABfNKs(Modifier.Companion, f5), $composer6, 6);
                                                }
                                                $composer6.endReplaceableGroup();
                                                ComposerKt.sourceInformationMarkerEnd($composer6);
                                                ComposerKt.sourceInformationMarkerEnd($composer$iv);
                                                $composer6.endReplaceableGroup();
                                                $composer6.endNode();
                                                $composer6.endReplaceableGroup();
                                                $composer6.endReplaceableGroup();
                                                if (ComposerKt.isTraceInProgress()) {
                                                    ComposerKt.traceEventEnd();
                                                    return;
                                                }
                                                return;
                                            }
                                            $composer6.skipToGroupEnd();
                                        }
                                    }), $composer5, 48);
                                    if (ComposerKt.isTraceInProgress()) {
                                        ComposerKt.traceEventEnd();
                                        return;
                                    }
                                    return;
                                }
                                $composer5.skipToGroupEnd();
                            }
                        }), $composer4, 56);
                        if (ComposerKt.isTraceInProgress()) {
                            ComposerKt.traceEventEnd();
                            return;
                        }
                        return;
                    }
                    $composer4.skipToGroupEnd();
                }
            }), $composer3, ($dirty3 & 14) | ($dirty3 & 112) | ($dirty3 & 7168) | (($dirty3 >> 3) & 57344) | (($dirty3 << 3) & 29360128) | (($dirty3 << 15) & 1879048192), 6, 256);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Modifier modifier6 = modifier4;
        final boolean z = enabled4;
        final MutableInteractionSource mutableInteractionSource = interactionSource3;
        final Shape shape4 = shape3;
        final BorderStroke borderStroke = border2;
        final SelectableChipColors selectableChipColors = colors4;
        final Function2 function27 = leadingIcon;
        final Function2 function28 = selectedIcon;
        final Function2 function29 = trailingIcon;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material.ChipKt$FilterChip$4
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

            public final void invoke(Composer composer, int i11) {
                ChipKt.FilterChip(selected, onClick, modifier6, z, mutableInteractionSource, shape4, borderStroke, selectableChipColors, function27, function28, function29, content, composer, RecomposeScopeImplKt.updateChangedFlags($changed | 1), RecomposeScopeImplKt.updateChangedFlags($changed1), i);
            }
        });
    }
}
