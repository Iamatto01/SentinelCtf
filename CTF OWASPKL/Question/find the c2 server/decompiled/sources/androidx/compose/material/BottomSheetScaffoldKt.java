package androidx.compose.material;

import androidx.autofill.HintConstants;
import androidx.compose.animation.core.AnimationSpec;
import androidx.compose.foundation.gestures.Orientation;
import androidx.compose.foundation.layout.ColumnScope;
import androidx.compose.foundation.layout.PaddingKt;
import androidx.compose.foundation.layout.PaddingValues;
import androidx.compose.foundation.layout.SizeKt;
import androidx.compose.foundation.shape.CornerBasedShape;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.RecomposeScopeImplKt;
import androidx.compose.runtime.ScopeUpdateScope;
import androidx.compose.runtime.internal.ComposableLambdaKt;
import androidx.compose.runtime.saveable.RememberSaveableKt;
import androidx.compose.runtime.saveable.Saver;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.graphics.Shape;
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection;
import androidx.compose.ui.layout.MeasureResult;
import androidx.compose.ui.layout.MeasureScope;
import androidx.compose.ui.layout.Placeable;
import androidx.compose.ui.layout.SubcomposeLayoutKt;
import androidx.compose.ui.layout.SubcomposeMeasureScope;
import androidx.compose.ui.platform.CompositionLocalsKt;
import androidx.compose.ui.unit.Constraints;
import androidx.compose.ui.unit.Density;
import androidx.compose.ui.unit.Dp;
import androidx.profileinstaller.ProfileVerifier;
import java.util.Map;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.ReplaceWith;
import kotlin.Unit;
import kotlin.collections.MapsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
import kotlin.math.MathKt;
/* compiled from: BottomSheetScaffold.kt */
@Metadata(d1 = {"\u0000¶\u0001\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\b\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\u001a§\u0001\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\b28\u0010\t\u001a4\u0012\u0013\u0012\u00110\u000b¢\u0006\f\b\f\u0012\b\b\r\u0012\u0004\b\b(\u0005\u0012\u0013\u0012\u00110\u000e¢\u0006\f\b\f\u0012\b\b\r\u0012\u0004\b\b(\u000f\u0012\u0006\u0012\u0004\u0018\u00010\u00100\n2\u0006\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00012\u0006\u0010\u0014\u001a\u00020\u00152\u0006\u0010\u0016\u001a\u00020\u00152\b\b\u0002\u0010\u0017\u001a\u00020\u00182\u001c\u0010\u0019\u001a\u0018\u0012\u0004\u0012\u00020\u001b\u0012\u0004\u0012\u00020\u00040\u001a¢\u0006\u0002\b\u001c¢\u0006\u0002\b\u001dH\u0003ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\u001e\u0010\u001f\u001aá\u0002\u0010 \u001a\u00020\u00042\u001c\u0010!\u001a\u0018\u0012\u0004\u0012\u00020\u001b\u0012\u0004\u0012\u00020\u00040\u001a¢\u0006\u0002\b\u001c¢\u0006\u0002\b\u001d2\b\b\u0002\u0010\u0017\u001a\u00020\u00182\b\b\u0002\u0010\"\u001a\u00020#2\u0015\b\u0002\u0010$\u001a\u000f\u0012\u0004\u0012\u00020\u0004\u0018\u00010%¢\u0006\u0002\b\u001c2\u0019\b\u0002\u0010&\u001a\u0013\u0012\u0004\u0012\u00020'\u0012\u0004\u0012\u00020\u00040\u001a¢\u0006\u0002\b\u001c2\u0015\b\u0002\u0010(\u001a\u000f\u0012\u0004\u0012\u00020\u0004\u0018\u00010%¢\u0006\u0002\b\u001c2\b\b\u0002\u0010)\u001a\u00020*2\b\b\u0002\u0010\u0007\u001a\u00020\b2\b\b\u0002\u0010\u0011\u001a\u00020\u00122\b\b\u0002\u0010\u0013\u001a\u00020\u00012\b\b\u0002\u0010\u0014\u001a\u00020\u00152\b\b\u0002\u0010\u0016\u001a\u00020\u00152\b\b\u0002\u0010+\u001a\u00020\u00012 \b\u0002\u0010,\u001a\u001a\u0012\u0004\u0012\u00020\u001b\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u001a¢\u0006\u0002\b\u001c¢\u0006\u0002\b\u001d2\b\b\u0002\u0010-\u001a\u00020\b2\b\b\u0002\u0010.\u001a\u00020\u00122\b\b\u0002\u0010/\u001a\u00020\u00012\b\b\u0002\u00100\u001a\u00020\u00152\b\b\u0002\u00101\u001a\u00020\u00152\b\b\u0002\u00102\u001a\u00020\u00152\b\b\u0002\u00103\u001a\u00020\u00152\b\b\u0002\u00104\u001a\u00020\u00152\u0017\u0010\u0019\u001a\u0013\u0012\u0004\u0012\u000205\u0012\u0004\u0012\u00020\u00040\u001a¢\u0006\u0002\b\u001cH\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b6\u00107\u001a\\\u00108\u001a\b\u0012\u0004\u0012\u00020\u000b092\u0006\u0010\u0005\u001a\u00020\u00062!\u0010:\u001a\u001d\u0012\u0013\u0012\u00110\u000b¢\u0006\f\b\f\u0012\b\b\r\u0012\u0004\b\b(;\u0012\u0004\u0012\u00020\u00040\u001a2!\u0010<\u001a\u001d\u0012\u0013\u0012\u00110\u000b¢\u0006\f\b\f\u0012\b\b\r\u0012\u0004\b\b(;\u0012\u0004\u0012\u00020\u00040\u001aH\u0002\u001aÈ\u0001\u0010=\u001a\u00020\u00042\u0013\u0010$\u001a\u000f\u0012\u0004\u0012\u00020\u0004\u0018\u00010%¢\u0006\u0002\b\u001c2&\u0010>\u001a\"\u0012\u0013\u0012\u001105¢\u0006\f\b\f\u0012\b\b\r\u0012\u0004\b\b(?\u0012\u0004\u0012\u00020\u00040\u001a¢\u0006\u0002\b\u001c2&\u0010@\u001a\"\u0012\u0013\u0012\u00110A¢\u0006\f\b\f\u0012\b\b\r\u0012\u0004\b\b(B\u0012\u0004\u0012\u00020\u00040\u001a¢\u0006\u0002\b\u001c2\u0013\u0010(\u001a\u000f\u0012\u0004\u0012\u00020\u0004\u0018\u00010%¢\u0006\u0002\b\u001c2\u0011\u0010&\u001a\r\u0012\u0004\u0012\u00020\u00040%¢\u0006\u0002\b\u001c2\u0006\u0010+\u001a\u00020\u00012\u0006\u0010)\u001a\u00020*2\f\u0010C\u001a\b\u0012\u0004\u0012\u00020\u00100%2\u0006\u0010D\u001a\u00020\u0006H\u0003ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\bE\u0010F\u001a4\u0010G\u001a\u00020\u00062\u0006\u0010H\u001a\u00020\u000b2\u000e\b\u0002\u0010I\u001a\b\u0012\u0004\u0012\u00020\u00100J2\u0012\u0010K\u001a\u000e\u0012\u0004\u0012\u00020\u000b\u0012\u0004\u0012\u00020\b0\u001aH\u0007\u001a\u001c\u0010L\u001a\u00020M2\n\u0010\u0005\u001a\u0006\u0012\u0002\b\u00030N2\u0006\u0010O\u001a\u00020PH\u0002\u001a+\u0010Q\u001a\u00020#2\b\b\u0002\u0010R\u001a\u00020S2\b\b\u0002\u0010T\u001a\u00020\u00062\b\b\u0002\u0010U\u001a\u00020'H\u0007¢\u0006\u0002\u0010V\u001a;\u0010W\u001a\u00020\u00062\u0006\u0010H\u001a\u00020\u000b2\u000e\b\u0002\u0010I\u001a\b\u0012\u0004\u0012\u00020\u00100J2\u0014\b\u0002\u0010K\u001a\u000e\u0012\u0004\u0012\u00020\u000b\u0012\u0004\u0012\u00020\b0\u001aH\u0007¢\u0006\u0002\u0010X\"\u0013\u0010\u0000\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\u0082\u0002\u000b\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001¨\u0006Y"}, d2 = {"FabSpacing", "Landroidx/compose/ui/unit/Dp;", "F", "BottomSheet", "", "state", "Landroidx/compose/material/BottomSheetState;", "sheetGesturesEnabled", "", "anchors", "Lkotlin/Function2;", "Landroidx/compose/material/BottomSheetValue;", "Lkotlin/ParameterName;", HintConstants.AUTOFILL_HINT_NAME, "Landroidx/compose/ui/unit/IntSize;", "sheetSize", "", "sheetShape", "Landroidx/compose/ui/graphics/Shape;", "sheetElevation", "sheetBackgroundColor", "Landroidx/compose/ui/graphics/Color;", "sheetContentColor", "modifier", "Landroidx/compose/ui/Modifier;", "content", "Lkotlin/Function1;", "Landroidx/compose/foundation/layout/ColumnScope;", "Landroidx/compose/runtime/Composable;", "Lkotlin/ExtensionFunctionType;", "BottomSheet-0cLKjW4", "(Landroidx/compose/material/BottomSheetState;ZLkotlin/jvm/functions/Function2;Landroidx/compose/ui/graphics/Shape;FJJLandroidx/compose/ui/Modifier;Lkotlin/jvm/functions/Function3;Landroidx/compose/runtime/Composer;II)V", "BottomSheetScaffold", "sheetContent", "scaffoldState", "Landroidx/compose/material/BottomSheetScaffoldState;", "topBar", "Lkotlin/Function0;", "snackbarHost", "Landroidx/compose/material/SnackbarHostState;", "floatingActionButton", "floatingActionButtonPosition", "Landroidx/compose/material/FabPosition;", "sheetPeekHeight", "drawerContent", "drawerGesturesEnabled", "drawerShape", "drawerElevation", "drawerBackgroundColor", "drawerContentColor", "drawerScrimColor", "backgroundColor", "contentColor", "Landroidx/compose/foundation/layout/PaddingValues;", "BottomSheetScaffold-bGncdBI", "(Lkotlin/jvm/functions/Function3;Landroidx/compose/ui/Modifier;Landroidx/compose/material/BottomSheetScaffoldState;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function3;Lkotlin/jvm/functions/Function2;IZLandroidx/compose/ui/graphics/Shape;FJJFLkotlin/jvm/functions/Function3;ZLandroidx/compose/ui/graphics/Shape;FJJJJJLkotlin/jvm/functions/Function3;Landroidx/compose/runtime/Composer;IIII)V", "BottomSheetScaffoldAnchorChangeHandler", "Landroidx/compose/material/AnchorChangeHandler;", "animateTo", "target", "snapTo", "BottomSheetScaffoldLayout", "body", "innerPadding", "bottomSheet", "", "layoutHeight", "sheetOffset", "sheetState", "BottomSheetScaffoldLayout-KCBPh4w", "(Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function3;Lkotlin/jvm/functions/Function3;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;FILkotlin/jvm/functions/Function0;Landroidx/compose/material/BottomSheetState;Landroidx/compose/runtime/Composer;I)V", "BottomSheetScaffoldState", "initialValue", "animationSpec", "Landroidx/compose/animation/core/AnimationSpec;", "confirmStateChange", "ConsumeSwipeWithinBottomSheetBoundsNestedScrollConnection", "Landroidx/compose/ui/input/nestedscroll/NestedScrollConnection;", "Landroidx/compose/material/SwipeableV2State;", "orientation", "Landroidx/compose/foundation/gestures/Orientation;", "rememberBottomSheetScaffoldState", "drawerState", "Landroidx/compose/material/DrawerState;", "bottomSheetState", "snackbarHostState", "(Landroidx/compose/material/DrawerState;Landroidx/compose/material/BottomSheetState;Landroidx/compose/material/SnackbarHostState;Landroidx/compose/runtime/Composer;II)Landroidx/compose/material/BottomSheetScaffoldState;", "rememberBottomSheetState", "(Landroidx/compose/material/BottomSheetValue;Landroidx/compose/animation/core/AnimationSpec;Lkotlin/jvm/functions/Function1;Landroidx/compose/runtime/Composer;II)Landroidx/compose/material/BottomSheetState;", "material_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class BottomSheetScaffoldKt {
    private static final float FabSpacing = Dp.m5122constructorimpl(16);

    public static /* synthetic */ BottomSheetState BottomSheetScaffoldState$default(BottomSheetValue bottomSheetValue, AnimationSpec animationSpec, Function1 function1, int i, Object obj) {
        if ((i & 2) != 0) {
            animationSpec = SwipeableDefaults.INSTANCE.getAnimationSpec();
        }
        return BottomSheetScaffoldState(bottomSheetValue, animationSpec, function1);
    }

    @Deprecated(message = "This constructor is deprecated. confirmStateChange has been renamed to confirmValueChange.", replaceWith = @ReplaceWith(expression = "BottomSheetScaffoldState(initialValue, animationSpec, confirmStateChange)", imports = {}))
    public static final BottomSheetState BottomSheetScaffoldState(BottomSheetValue initialValue, AnimationSpec<Float> animationSpec, Function1<? super BottomSheetValue, Boolean> confirmStateChange) {
        Intrinsics.checkNotNullParameter(initialValue, "initialValue");
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        Intrinsics.checkNotNullParameter(confirmStateChange, "confirmStateChange");
        return new BottomSheetState(initialValue, animationSpec, confirmStateChange);
    }

    public static final BottomSheetState rememberBottomSheetState(final BottomSheetValue initialValue, final AnimationSpec<Float> animationSpec, final Function1<? super BottomSheetValue, Boolean> function1, Composer $composer, int $changed, int i) {
        Intrinsics.checkNotNullParameter(initialValue, "initialValue");
        $composer.startReplaceableGroup(1808153344);
        ComposerKt.sourceInformation($composer, "C(rememberBottomSheetState)P(2)202@7418L371:BottomSheetScaffold.kt#jmzs0o");
        if ((i & 2) != 0) {
            AnimationSpec animationSpec2 = SwipeableDefaults.INSTANCE.getAnimationSpec();
            animationSpec = animationSpec2;
        }
        if ((i & 4) != 0) {
            Function1 confirmStateChange = new Function1<BottomSheetValue, Boolean>() { // from class: androidx.compose.material.BottomSheetScaffoldKt$rememberBottomSheetState$1
                @Override // kotlin.jvm.functions.Function1
                public final Boolean invoke(BottomSheetValue it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                    return true;
                }
            };
            function1 = confirmStateChange;
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(1808153344, $changed, -1, "androidx.compose.material.rememberBottomSheetState (BottomSheetScaffold.kt:197)");
        }
        BottomSheetState bottomSheetState = (BottomSheetState) RememberSaveableKt.m2260rememberSaveable(new Object[]{animationSpec}, (Saver<Object, ? extends Object>) BottomSheetState.Companion.Saver(animationSpec, function1), (String) null, (Function0<? extends Object>) new Function0<BottomSheetState>() { // from class: androidx.compose.material.BottomSheetScaffoldKt$rememberBottomSheetState$2
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final BottomSheetState invoke() {
                return new BottomSheetState(BottomSheetValue.this, animationSpec, function1);
            }
        }, $composer, 72, 4);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return bottomSheetState;
    }

    public static final BottomSheetScaffoldState rememberBottomSheetScaffoldState(DrawerState drawerState, BottomSheetState bottomSheetState, SnackbarHostState snackbarHostState, Composer $composer, int $changed, int i) {
        Object value$iv$iv;
        Object value$iv$iv2;
        $composer.startReplaceableGroup(-1353009744);
        ComposerKt.sourceInformation($composer, "C(rememberBottomSheetScaffoldState)P(1)240@8661L39,241@8743L35,242@8823L32,244@8897L248:BottomSheetScaffold.kt#jmzs0o");
        if ((i & 1) != 0) {
            drawerState = DrawerKt.rememberDrawerState(DrawerValue.Closed, null, $composer, 6, 2);
        }
        if ((i & 2) != 0) {
            bottomSheetState = rememberBottomSheetState(BottomSheetValue.Collapsed, null, null, $composer, 6, 6);
        }
        if ((i & 4) != 0) {
            $composer.startReplaceableGroup(-492369756);
            ComposerKt.sourceInformation($composer, "CC(remember):Composables.kt#9igjgp");
            Object it$iv$iv = $composer.rememberedValue();
            if (it$iv$iv == Composer.Companion.getEmpty()) {
                value$iv$iv2 = new SnackbarHostState();
                $composer.updateRememberedValue(value$iv$iv2);
            } else {
                value$iv$iv2 = it$iv$iv;
            }
            $composer.endReplaceableGroup();
            snackbarHostState = (SnackbarHostState) value$iv$iv2;
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-1353009744, $changed, -1, "androidx.compose.material.rememberBottomSheetScaffoldState (BottomSheetScaffold.kt:239)");
        }
        int i2 = ($changed & 14) | ($changed & 112) | ($changed & 896);
        $composer.startReplaceableGroup(1618982084);
        ComposerKt.sourceInformation($composer, "CC(remember)P(1,2,3):Composables.kt#9igjgp");
        boolean invalid$iv$iv = $composer.changed(drawerState) | $composer.changed(bottomSheetState) | $composer.changed(snackbarHostState);
        Object it$iv$iv2 = $composer.rememberedValue();
        if (invalid$iv$iv || it$iv$iv2 == Composer.Companion.getEmpty()) {
            value$iv$iv = new BottomSheetScaffoldState(drawerState, bottomSheetState, snackbarHostState);
            $composer.updateRememberedValue(value$iv$iv);
        } else {
            value$iv$iv = it$iv$iv2;
        }
        $composer.endReplaceableGroup();
        BottomSheetScaffoldState bottomSheetScaffoldState = (BottomSheetScaffoldState) value$iv$iv;
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return bottomSheetScaffoldState;
    }

    /* renamed from: BottomSheetScaffold-bGncdBI  reason: not valid java name */
    public static final void m921BottomSheetScaffoldbGncdBI(final Function3<? super ColumnScope, ? super Composer, ? super Integer, Unit> sheetContent, Modifier modifier, BottomSheetScaffoldState scaffoldState, Function2<? super Composer, ? super Integer, Unit> function2, Function3<? super SnackbarHostState, ? super Composer, ? super Integer, Unit> function3, Function2<? super Composer, ? super Integer, Unit> function22, int floatingActionButtonPosition, boolean sheetGesturesEnabled, Shape sheetShape, float sheetElevation, long sheetBackgroundColor, long sheetContentColor, float sheetPeekHeight, Function3<? super ColumnScope, ? super Composer, ? super Integer, Unit> function32, boolean drawerGesturesEnabled, Shape drawerShape, float drawerElevation, long drawerBackgroundColor, long drawerContentColor, long drawerScrimColor, long backgroundColor, long contentColor, final Function3<? super PaddingValues, ? super Composer, ? super Integer, Unit> content, Composer $composer, final int $changed, final int $changed1, final int $changed2, final int i) {
        Modifier modifier2;
        Function2 topBar;
        int i2;
        int i3;
        int i4;
        int i5;
        long j;
        int $dirty2;
        int i6;
        int i7;
        int i8;
        BottomSheetScaffoldState scaffoldState2;
        Function2 floatingActionButton;
        boolean sheetGesturesEnabled2;
        CornerBasedShape sheetShape2;
        float sheetElevation2;
        int $dirty;
        long sheetBackgroundColor2;
        long sheetContentColor2;
        Function3 drawerContent;
        boolean drawerGesturesEnabled2;
        long sheetBackgroundColor3;
        CornerBasedShape drawerShape2;
        Shape drawerShape3;
        float drawerElevation2;
        long drawerBackgroundColor2;
        float sheetPeekHeight2;
        long drawerContentColor2;
        long drawerBackgroundColor3;
        int i9;
        long drawerScrimColor2;
        long drawerScrimColor3;
        long backgroundColor2;
        int $dirty22;
        int $dirty3;
        Shape drawerShape4;
        float drawerElevation3;
        float sheetPeekHeight3;
        long contentColor2;
        long backgroundColor3;
        int $dirty23;
        int $dirty24;
        int $dirty1;
        BottomSheetScaffoldState scaffoldState3;
        Function3 snackbarHost;
        long drawerScrimColor4;
        Function3 snackbarHost2;
        int floatingActionButtonPosition2;
        float sheetPeekHeight4;
        Function2 floatingActionButton2;
        Function2 topBar2;
        boolean sheetGesturesEnabled3;
        Shape sheetShape3;
        Shape drawerShape5;
        float sheetElevation3;
        Function3 drawerContent2;
        boolean drawerGesturesEnabled3;
        float drawerElevation4;
        long sheetContentColor3;
        long drawerScrimColor5;
        long drawerContentColor3;
        long sheetBackgroundColor4;
        long drawerBackgroundColor4;
        long backgroundColor4;
        long contentColor3;
        BottomSheetScaffoldState scaffoldState4;
        Modifier modifier3;
        int i10;
        int i11;
        int i12;
        int i13;
        int i14;
        int i15;
        int i16;
        int i17;
        int i18;
        int i19;
        Intrinsics.checkNotNullParameter(sheetContent, "sheetContent");
        Intrinsics.checkNotNullParameter(content, "content");
        Composer $composer2 = $composer.startRestartGroup(46422755);
        ComposerKt.sourceInformation($composer2, "C(BottomSheetScaffold)P(15,12,13,22,21,10,11:c#material.FabPosition,18,20,17:c#ui.unit.Dp,14:c#ui.graphics.Color,16:c#ui.graphics.Color,19:c#ui.unit.Dp,4,7,9,6:c#ui.unit.Dp,3:c#ui.graphics.Color,5:c#ui.graphics.Color,8:c#ui.graphics.Color,0:c#ui.graphics.Color,2:c#ui.graphics.Color)305@12585L34,311@12954L6,313@13085L6,314@13132L37,318@13389L6,320@13504L6,321@13552L38,322@13637L10,323@13692L6,324@13737L32,*327@13865L7,374@16050L713:BottomSheetScaffold.kt#jmzs0o");
        int $dirty4 = $changed;
        int $dirty12 = $changed1;
        int $dirty25 = $changed2;
        if ((i & 1) != 0) {
            $dirty4 |= 6;
        } else if (($changed & 14) == 0) {
            $dirty4 |= $composer2.changedInstance(sheetContent) ? 4 : 2;
        }
        int i20 = i & 2;
        if (i20 != 0) {
            $dirty4 |= 48;
            modifier2 = modifier;
        } else if (($changed & 112) == 0) {
            modifier2 = modifier;
            $dirty4 |= $composer2.changed(modifier2) ? 32 : 16;
        } else {
            modifier2 = modifier;
        }
        if (($changed & 896) == 0) {
            if ((i & 4) == 0 && $composer2.changed(scaffoldState)) {
                i19 = 256;
                $dirty4 |= i19;
            }
            i19 = 128;
            $dirty4 |= i19;
        }
        int i21 = i & 8;
        if (i21 != 0) {
            $dirty4 |= 3072;
            topBar = function2;
        } else if (($changed & 7168) == 0) {
            topBar = function2;
            $dirty4 |= $composer2.changedInstance(topBar) ? 2048 : 1024;
        } else {
            topBar = function2;
        }
        int i22 = i & 16;
        if (i22 != 0) {
            $dirty4 |= 24576;
        } else if (($changed & 57344) == 0) {
            $dirty4 |= $composer2.changedInstance(function3) ? 16384 : 8192;
        }
        int i23 = i & 32;
        if (i23 != 0) {
            $dirty4 |= ProfileVerifier.CompilationStatus.RESULT_CODE_ERROR_CANT_WRITE_PROFILE_VERIFICATION_RESULT_CACHE_FILE;
        } else if (($changed & 458752) == 0) {
            $dirty4 |= $composer2.changedInstance(function22) ? 131072 : 65536;
        }
        int i24 = i & 64;
        if (i24 != 0) {
            $dirty4 |= 1572864;
        } else if (($changed & 3670016) == 0) {
            $dirty4 |= $composer2.changed(floatingActionButtonPosition) ? 1048576 : 524288;
        }
        int i25 = i & 128;
        if (i25 != 0) {
            $dirty4 |= 12582912;
            i2 = i25;
        } else if (($changed & 29360128) == 0) {
            i2 = i25;
            $dirty4 |= $composer2.changed(sheetGesturesEnabled) ? 8388608 : 4194304;
        } else {
            i2 = i25;
        }
        if (($changed & 234881024) == 0) {
            if ((i & 256) == 0 && $composer2.changed(sheetShape)) {
                i18 = 67108864;
                $dirty4 |= i18;
            }
            i18 = 33554432;
            $dirty4 |= i18;
        }
        int i26 = i & 512;
        if (i26 != 0) {
            $dirty4 |= 805306368;
            i3 = i26;
        } else if (($changed & 1879048192) == 0) {
            i3 = i26;
            $dirty4 |= $composer2.changed(sheetElevation) ? 536870912 : 268435456;
        } else {
            i3 = i26;
        }
        if (($changed1 & 14) == 0) {
            if ((i & 1024) == 0 && $composer2.changed(sheetBackgroundColor)) {
                i17 = 4;
                $dirty12 |= i17;
            }
            i17 = 2;
            $dirty12 |= i17;
        }
        if (($changed1 & 112) == 0) {
            if ((i & 2048) == 0 && $composer2.changed(sheetContentColor)) {
                i16 = 32;
                $dirty12 |= i16;
            }
            i16 = 16;
            $dirty12 |= i16;
        }
        int i27 = i & 4096;
        if (i27 != 0) {
            $dirty12 |= 384;
            i4 = i27;
        } else {
            i4 = i27;
            if (($changed1 & 896) == 0) {
                $dirty12 |= $composer2.changed(sheetPeekHeight) ? 256 : 128;
            }
        }
        int i28 = i & 8192;
        if (i28 != 0) {
            $dirty12 |= 3072;
        } else if (($changed1 & 7168) == 0) {
            $dirty12 |= $composer2.changedInstance(function32) ? 2048 : 1024;
        }
        int i29 = i & 16384;
        if (i29 != 0) {
            $dirty12 |= 24576;
            i5 = i29;
        } else if (($changed1 & 57344) == 0) {
            i5 = i29;
            $dirty12 |= $composer2.changed(drawerGesturesEnabled) ? 16384 : 8192;
        } else {
            i5 = i29;
        }
        if (($changed1 & 458752) == 0) {
            if ((i & 32768) == 0 && $composer2.changed(drawerShape)) {
                i15 = 131072;
                $dirty12 |= i15;
            }
            i15 = 65536;
            $dirty12 |= i15;
        }
        int i30 = i & 65536;
        if (i30 != 0) {
            $dirty12 |= 1572864;
        } else if (($changed1 & 3670016) == 0) {
            $dirty12 |= $composer2.changed(drawerElevation) ? 1048576 : 524288;
        }
        if (($changed1 & 29360128) == 0) {
            if ((i & 131072) == 0 && $composer2.changed(drawerBackgroundColor)) {
                i14 = 8388608;
                $dirty12 |= i14;
            }
            i14 = 4194304;
            $dirty12 |= i14;
        }
        if (($changed1 & 234881024) == 0) {
            if ((i & 262144) == 0 && $composer2.changed(drawerContentColor)) {
                i13 = 67108864;
                $dirty12 |= i13;
            }
            i13 = 33554432;
            $dirty12 |= i13;
        }
        if (($changed1 & 1879048192) == 0) {
            if ((i & 524288) == 0 && $composer2.changed(drawerScrimColor)) {
                i12 = 536870912;
                $dirty12 |= i12;
            }
            i12 = 268435456;
            $dirty12 |= i12;
        }
        int $dirty13 = $dirty12;
        if (($changed2 & 14) == 0) {
            if ((i & 1048576) == 0 && $composer2.changed(backgroundColor)) {
                i11 = 4;
                $dirty25 |= i11;
            }
            i11 = 2;
            $dirty25 |= i11;
        }
        if (($changed2 & 112) == 0) {
            if ((2097152 & i) == 0) {
                j = contentColor;
                if ($composer2.changed(j)) {
                    i10 = 32;
                    $dirty25 |= i10;
                }
            } else {
                j = contentColor;
            }
            i10 = 16;
            $dirty25 |= i10;
        } else {
            j = contentColor;
        }
        if ((4194304 & i) != 0) {
            $dirty25 |= 384;
        } else if (($changed2 & 896) == 0) {
            $dirty25 |= $composer2.changedInstance(content) ? 256 : 128;
        }
        if ((1533916891 & $dirty4) == 306783378 && ($dirty13 & 1533916891) == 306783378 && ($dirty25 & 731) == 146 && $composer2.getSkipping()) {
            $composer2.skipToGroupEnd();
            scaffoldState4 = scaffoldState;
            snackbarHost2 = function3;
            floatingActionButton2 = function22;
            floatingActionButtonPosition2 = floatingActionButtonPosition;
            sheetGesturesEnabled3 = sheetGesturesEnabled;
            sheetShape3 = sheetShape;
            sheetElevation3 = sheetElevation;
            sheetBackgroundColor4 = sheetBackgroundColor;
            sheetContentColor3 = sheetContentColor;
            sheetPeekHeight4 = sheetPeekHeight;
            drawerContent2 = function32;
            drawerGesturesEnabled3 = drawerGesturesEnabled;
            drawerShape5 = drawerShape;
            drawerElevation4 = drawerElevation;
            drawerBackgroundColor4 = drawerBackgroundColor;
            drawerContentColor3 = drawerContentColor;
            drawerScrimColor5 = drawerScrimColor;
            backgroundColor4 = backgroundColor;
            topBar2 = topBar;
            contentColor3 = j;
            modifier3 = modifier2;
        } else {
            $composer2.startDefaults();
            if (($changed & 1) == 0 || $composer2.getDefaultsInvalid()) {
                if (i20 != 0) {
                    modifier2 = Modifier.Companion;
                }
                if ((i & 4) != 0) {
                    $dirty2 = $dirty25;
                    i8 = i4;
                    i6 = i2;
                    i7 = i3;
                    scaffoldState2 = rememberBottomSheetScaffoldState(null, null, null, $composer2, 0, 7);
                    $dirty4 &= -897;
                } else {
                    $dirty2 = $dirty25;
                    i6 = i2;
                    i7 = i3;
                    i8 = i4;
                    scaffoldState2 = scaffoldState;
                }
                Function2 topBar3 = i21 != 0 ? null : function2;
                Function3 snackbarHost3 = i22 != 0 ? ComposableSingletons$BottomSheetScaffoldKt.INSTANCE.m987getLambda1$material_release() : function3;
                floatingActionButton = i23 != 0 ? null : function22;
                int floatingActionButtonPosition3 = i24 != 0 ? FabPosition.Companion.m1033getEnd5ygKITE() : floatingActionButtonPosition;
                sheetGesturesEnabled2 = i6 != 0 ? true : sheetGesturesEnabled;
                BottomSheetScaffoldState scaffoldState5 = scaffoldState2;
                if ((i & 256) != 0) {
                    sheetShape2 = MaterialTheme.INSTANCE.getShapes($composer2, 6).getLarge();
                    $dirty4 &= -234881025;
                } else {
                    sheetShape2 = sheetShape;
                }
                sheetElevation2 = i7 != 0 ? BottomSheetScaffoldDefaults.INSTANCE.m918getSheetElevationD9Ej5fM() : sheetElevation;
                if ((i & 1024) != 0) {
                    $dirty = $dirty4;
                    sheetBackgroundColor2 = MaterialTheme.INSTANCE.getColors($composer2, 6).m966getSurface0d7_KjU();
                    $dirty13 &= -15;
                } else {
                    $dirty = $dirty4;
                    sheetBackgroundColor2 = sheetBackgroundColor;
                }
                Function2 topBar4 = topBar3;
                if ((i & 2048) != 0) {
                    sheetContentColor2 = ColorsKt.m980contentColorForek8zF_U(sheetBackgroundColor2, $composer2, $dirty13 & 14);
                    $dirty13 &= -113;
                } else {
                    sheetContentColor2 = sheetContentColor;
                }
                float sheetPeekHeight5 = i8 != 0 ? BottomSheetScaffoldDefaults.INSTANCE.m919getSheetPeekHeightD9Ej5fM() : sheetPeekHeight;
                drawerContent = i28 != 0 ? null : function32;
                drawerGesturesEnabled2 = i5 != 0 ? true : drawerGesturesEnabled;
                if ((i & 32768) != 0) {
                    sheetBackgroundColor3 = sheetBackgroundColor2;
                    drawerShape2 = MaterialTheme.INSTANCE.getShapes($composer2, 6).getLarge();
                    $dirty13 &= -458753;
                } else {
                    sheetBackgroundColor3 = sheetBackgroundColor2;
                    drawerShape2 = drawerShape;
                }
                float drawerElevation5 = i30 != 0 ? DrawerDefaults.INSTANCE.m1002getElevationD9Ej5fM() : drawerElevation;
                if ((i & 131072) != 0) {
                    drawerShape3 = drawerShape2;
                    drawerElevation2 = drawerElevation5;
                    drawerBackgroundColor2 = MaterialTheme.INSTANCE.getColors($composer2, 6).m966getSurface0d7_KjU();
                    $dirty13 &= -29360129;
                } else {
                    drawerShape3 = drawerShape2;
                    drawerElevation2 = drawerElevation5;
                    drawerBackgroundColor2 = drawerBackgroundColor;
                }
                if ((i & 262144) != 0) {
                    sheetPeekHeight2 = sheetPeekHeight5;
                    drawerContentColor2 = ColorsKt.m980contentColorForek8zF_U(drawerBackgroundColor2, $composer2, ($dirty13 >> 21) & 14);
                    $dirty13 &= -234881025;
                } else {
                    sheetPeekHeight2 = sheetPeekHeight5;
                    drawerContentColor2 = drawerContentColor;
                }
                if ((i & 524288) != 0) {
                    drawerBackgroundColor3 = drawerBackgroundColor2;
                    i9 = 6;
                    drawerScrimColor2 = DrawerDefaults.INSTANCE.getScrimColor($composer2, 6);
                    $dirty13 &= -1879048193;
                } else {
                    drawerBackgroundColor3 = drawerBackgroundColor2;
                    i9 = 6;
                    drawerScrimColor2 = drawerScrimColor;
                }
                if ((i & 1048576) != 0) {
                    drawerScrimColor3 = drawerScrimColor2;
                    backgroundColor2 = MaterialTheme.INSTANCE.getColors($composer2, i9).m955getBackground0d7_KjU();
                    $dirty22 = $dirty2 & (-15);
                } else {
                    drawerScrimColor3 = drawerScrimColor2;
                    backgroundColor2 = backgroundColor;
                    $dirty22 = $dirty2;
                }
                if ((i & 2097152) != 0) {
                    Function3 snackbarHost4 = snackbarHost3;
                    long contentColor4 = ColorsKt.m980contentColorForek8zF_U(backgroundColor2, $composer2, $dirty22 & 14);
                    $dirty3 = $dirty;
                    drawerShape4 = drawerShape3;
                    drawerElevation3 = drawerElevation2;
                    sheetPeekHeight3 = sheetPeekHeight2;
                    $dirty23 = $dirty22 & (-113);
                    $dirty24 = floatingActionButtonPosition3;
                    $dirty1 = $dirty13;
                    contentColor2 = contentColor4;
                    drawerScrimColor4 = drawerScrimColor3;
                    topBar = topBar4;
                    backgroundColor3 = backgroundColor2;
                    scaffoldState3 = scaffoldState5;
                    snackbarHost = snackbarHost4;
                } else {
                    Function3 snackbarHost5 = snackbarHost3;
                    $dirty3 = $dirty;
                    drawerShape4 = drawerShape3;
                    drawerElevation3 = drawerElevation2;
                    sheetPeekHeight3 = sheetPeekHeight2;
                    contentColor2 = contentColor;
                    backgroundColor3 = backgroundColor2;
                    $dirty23 = $dirty22;
                    $dirty24 = floatingActionButtonPosition3;
                    $dirty1 = $dirty13;
                    scaffoldState3 = scaffoldState5;
                    snackbarHost = snackbarHost5;
                    drawerScrimColor4 = drawerScrimColor3;
                    topBar = topBar4;
                }
            } else {
                $composer2.skipToGroupEnd();
                if ((i & 4) != 0) {
                    $dirty4 &= -897;
                }
                if ((i & 256) != 0) {
                    $dirty4 &= -234881025;
                }
                if ((i & 1024) != 0) {
                    $dirty13 &= -15;
                }
                if ((i & 2048) != 0) {
                    $dirty13 &= -113;
                }
                if ((32768 & i) != 0) {
                    $dirty13 &= -458753;
                }
                if ((i & 131072) != 0) {
                    $dirty13 &= -29360129;
                }
                if ((262144 & i) != 0) {
                    $dirty13 &= -234881025;
                }
                if ((i & 524288) != 0) {
                    $dirty13 &= -1879048193;
                }
                if ((i & 1048576) != 0) {
                    $dirty25 &= -15;
                }
                if ((2097152 & i) != 0) {
                    int i31 = $dirty25 & (-113);
                    floatingActionButton = function22;
                    $dirty24 = floatingActionButtonPosition;
                    sheetElevation2 = sheetElevation;
                    sheetBackgroundColor3 = sheetBackgroundColor;
                    sheetContentColor2 = sheetContentColor;
                    sheetPeekHeight3 = sheetPeekHeight;
                    drawerContent = function32;
                    drawerGesturesEnabled2 = drawerGesturesEnabled;
                    drawerShape4 = drawerShape;
                    drawerElevation3 = drawerElevation;
                    drawerBackgroundColor3 = drawerBackgroundColor;
                    drawerContentColor2 = drawerContentColor;
                    backgroundColor3 = backgroundColor;
                    $dirty3 = $dirty4;
                    $dirty23 = i31;
                    contentColor2 = j;
                    $dirty1 = $dirty13;
                    scaffoldState3 = scaffoldState;
                    snackbarHost = function3;
                    sheetGesturesEnabled2 = sheetGesturesEnabled;
                    sheetShape2 = sheetShape;
                    drawerScrimColor4 = drawerScrimColor;
                } else {
                    snackbarHost = function3;
                    floatingActionButton = function22;
                    sheetElevation2 = sheetElevation;
                    sheetBackgroundColor3 = sheetBackgroundColor;
                    sheetContentColor2 = sheetContentColor;
                    sheetPeekHeight3 = sheetPeekHeight;
                    drawerContent = function32;
                    drawerGesturesEnabled2 = drawerGesturesEnabled;
                    drawerShape4 = drawerShape;
                    drawerElevation3 = drawerElevation;
                    drawerBackgroundColor3 = drawerBackgroundColor;
                    drawerContentColor2 = drawerContentColor;
                    backgroundColor3 = backgroundColor;
                    $dirty3 = $dirty4;
                    $dirty23 = $dirty25;
                    contentColor2 = j;
                    $dirty1 = $dirty13;
                    scaffoldState3 = scaffoldState;
                    $dirty24 = floatingActionButtonPosition;
                    sheetGesturesEnabled2 = sheetGesturesEnabled;
                    sheetShape2 = sheetShape;
                    drawerScrimColor4 = drawerScrimColor;
                }
            }
            $composer2.endDefaults();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(46422755, $dirty3, $dirty1, "androidx.compose.material.BottomSheetScaffold (BottomSheetScaffold.kt:302)");
            }
            ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "CC:CompositionLocal.kt#9igjgp");
            Object consume = $composer2.consume(CompositionLocalsKt.getLocalDensity());
            ComposerKt.sourceInformationMarkerEnd($composer2);
            Density $this$BottomSheetScaffold_bGncdBI_u24lambda_u242 = (Density) consume;
            final float peekHeightPx = $this$BottomSheetScaffold_bGncdBI_u24lambda_u242.mo301toPx0680j_4(sheetPeekHeight3);
            final BottomSheetScaffoldState bottomSheetScaffoldState = scaffoldState3;
            final Function2 function23 = topBar;
            final Function2 function24 = floatingActionButton;
            final float f = sheetPeekHeight3;
            final int i32 = $dirty24;
            final int i33 = $dirty3;
            final int i34 = $dirty23;
            final int i35 = $dirty1;
            final boolean z = sheetGesturesEnabled2;
            final Shape shape = sheetShape2;
            final float f2 = sheetElevation2;
            final long j2 = sheetBackgroundColor3;
            final long j3 = sheetContentColor2;
            final Function3 function33 = snackbarHost;
            Function2<Composer, Integer, Unit> function25 = new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material.BottomSheetScaffoldKt$BottomSheetScaffold$child$1
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

                /* JADX WARN: Removed duplicated region for block: B:21:0x010d  */
                /* JADX WARN: Removed duplicated region for block: B:24:? A[RETURN, SYNTHETIC] */
                /*
                    Code decompiled incorrectly, please refer to instructions dump.
                    To view partially-correct add '--show-bad-code' argument
                */
                public final void invoke(androidx.compose.runtime.Composer r32, int r33) {
                    /*
                        Method dump skipped, instructions count: 273
                        To view this dump add '--comments-level debug' option
                    */
                    throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material.BottomSheetScaffoldKt$BottomSheetScaffold$child$1.invoke(androidx.compose.runtime.Composer, int):void");
                }
            };
            Function3 snackbarHost6 = snackbarHost;
            final Function2 child = ComposableLambdaKt.composableLambda($composer2, 893101063, true, function25);
            int floatingActionButtonPosition4 = $dirty24;
            final Function3 function34 = drawerContent;
            final BottomSheetScaffoldState bottomSheetScaffoldState2 = scaffoldState3;
            final boolean z2 = drawerGesturesEnabled2;
            final Shape shape2 = drawerShape4;
            final float f3 = drawerElevation3;
            final long j4 = drawerBackgroundColor3;
            final long j5 = drawerContentColor2;
            final long j6 = drawerScrimColor4;
            final int i36 = $dirty1;
            BottomSheetScaffoldState scaffoldState6 = scaffoldState3;
            SurfaceKt.m1124SurfaceFjzlyU(SizeKt.fillMaxSize$default(modifier2, 0.0f, 1, null), null, backgroundColor3, contentColor2, null, 0.0f, ComposableLambdaKt.composableLambda($composer2, 1273816607, true, new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material.BottomSheetScaffoldKt$BottomSheetScaffold$1
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

                public final void invoke(Composer $composer3, int $changed3) {
                    ComposerKt.sourceInformation($composer3, "C:BottomSheetScaffold.kt#jmzs0o");
                    if (($changed3 & 11) != 2 || !$composer3.getSkipping()) {
                        if (ComposerKt.isTraceInProgress()) {
                            ComposerKt.traceEventStart(1273816607, $changed3, -1, "androidx.compose.material.BottomSheetScaffold.<anonymous> (BottomSheetScaffold.kt:379)");
                        }
                        if (function34 == null) {
                            $composer3.startReplaceableGroup(-249544811);
                            ComposerKt.sourceInformation($composer3, "381@16230L7");
                            child.invoke($composer3, 6);
                            $composer3.endReplaceableGroup();
                        } else {
                            $composer3.startReplaceableGroup(-249544774);
                            ComposerKt.sourceInformation($composer3, "383@16267L480");
                            Function3<ColumnScope, Composer, Integer, Unit> function35 = function34;
                            DrawerState drawerState = bottomSheetScaffoldState2.getDrawerState();
                            boolean z3 = z2;
                            Shape shape3 = shape2;
                            float f4 = f3;
                            long j7 = j4;
                            long j8 = j5;
                            long j9 = j6;
                            Function2<Composer, Integer, Unit> function26 = child;
                            int i37 = i36;
                            DrawerKt.m1005ModalDrawerGs3lGvM(function35, null, drawerState, z3, shape3, f4, j7, j8, j9, function26, $composer3, ((i37 >> 9) & 14) | 805306368 | ((i37 >> 3) & 7168) | ((i37 >> 3) & 57344) | ((i37 >> 3) & 458752) | ((i37 >> 3) & 3670016) | ((i37 >> 3) & 29360128) | ((i37 >> 3) & 234881024), 2);
                            $composer3.endReplaceableGroup();
                        }
                        if (ComposerKt.isTraceInProgress()) {
                            ComposerKt.traceEventEnd();
                            return;
                        }
                        return;
                    }
                    $composer3.skipToGroupEnd();
                }
            }), $composer2, (($dirty23 << 6) & 896) | 1572864 | (($dirty23 << 6) & 7168), 50);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            snackbarHost2 = snackbarHost6;
            floatingActionButtonPosition2 = floatingActionButtonPosition4;
            sheetPeekHeight4 = sheetPeekHeight3;
            floatingActionButton2 = floatingActionButton;
            topBar2 = topBar;
            sheetGesturesEnabled3 = sheetGesturesEnabled2;
            sheetShape3 = sheetShape2;
            drawerShape5 = drawerShape4;
            sheetElevation3 = sheetElevation2;
            drawerContent2 = drawerContent;
            drawerGesturesEnabled3 = drawerGesturesEnabled2;
            drawerElevation4 = drawerElevation3;
            sheetContentColor3 = sheetContentColor2;
            drawerScrimColor5 = drawerScrimColor4;
            drawerContentColor3 = drawerContentColor2;
            sheetBackgroundColor4 = sheetBackgroundColor3;
            drawerBackgroundColor4 = drawerBackgroundColor3;
            backgroundColor4 = backgroundColor3;
            contentColor3 = contentColor2;
            scaffoldState4 = scaffoldState6;
            modifier3 = modifier2;
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Modifier modifier4 = modifier3;
        final BottomSheetScaffoldState bottomSheetScaffoldState3 = scaffoldState4;
        final Function2 function26 = topBar2;
        final Function3 function35 = snackbarHost2;
        final Function2 function27 = floatingActionButton2;
        final int i37 = floatingActionButtonPosition2;
        final boolean z3 = sheetGesturesEnabled3;
        final Shape shape3 = sheetShape3;
        final float f4 = sheetElevation3;
        final long j7 = sheetBackgroundColor4;
        final long j8 = sheetContentColor3;
        final float f5 = sheetPeekHeight4;
        final Function3 function36 = drawerContent2;
        final boolean z4 = drawerGesturesEnabled3;
        final Shape shape4 = drawerShape5;
        final float f6 = drawerElevation4;
        final long j9 = drawerBackgroundColor4;
        final long j10 = drawerContentColor3;
        final long j11 = drawerScrimColor5;
        final long j12 = backgroundColor4;
        final long j13 = contentColor3;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material.BottomSheetScaffoldKt$BottomSheetScaffold$2
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

            public final void invoke(Composer composer, int i38) {
                BottomSheetScaffoldKt.m921BottomSheetScaffoldbGncdBI(sheetContent, modifier4, bottomSheetScaffoldState3, function26, function35, function27, i37, z3, shape3, f4, j7, j8, f5, function36, z4, shape4, f6, j9, j10, j11, j12, j13, content, composer, RecomposeScopeImplKt.updateChangedFlags($changed | 1), RecomposeScopeImplKt.updateChangedFlags($changed1), RecomposeScopeImplKt.updateChangedFlags($changed2), i);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:105:0x0139  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x013e  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x0146  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x0186  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x01a5  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x02a3  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x02ac  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x02b1  */
    /* renamed from: BottomSheet-0cLKjW4  reason: not valid java name */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void m920BottomSheet0cLKjW4(final androidx.compose.material.BottomSheetState r30, final boolean r31, final kotlin.jvm.functions.Function2<? super androidx.compose.material.BottomSheetValue, ? super androidx.compose.ui.unit.IntSize, java.lang.Float> r32, final androidx.compose.ui.graphics.Shape r33, final float r34, final long r35, final long r37, androidx.compose.ui.Modifier r39, final kotlin.jvm.functions.Function3<? super androidx.compose.foundation.layout.ColumnScope, ? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r40, androidx.compose.runtime.Composer r41, final int r42, final int r43) {
        /*
            Method dump skipped, instructions count: 732
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material.BottomSheetScaffoldKt.m920BottomSheet0cLKjW4(androidx.compose.material.BottomSheetState, boolean, kotlin.jvm.functions.Function2, androidx.compose.ui.graphics.Shape, float, long, long, androidx.compose.ui.Modifier, kotlin.jvm.functions.Function3, androidx.compose.runtime.Composer, int, int):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: BottomSheetScaffoldLayout-KCBPh4w  reason: not valid java name */
    public static final void m922BottomSheetScaffoldLayoutKCBPh4w(final Function2<? super Composer, ? super Integer, Unit> function2, final Function3<? super PaddingValues, ? super Composer, ? super Integer, Unit> function3, final Function3<? super Integer, ? super Composer, ? super Integer, Unit> function32, final Function2<? super Composer, ? super Integer, Unit> function22, final Function2<? super Composer, ? super Integer, Unit> function23, final float sheetPeekHeight, final int floatingActionButtonPosition, final Function0<Float> function0, final BottomSheetState sheetState, Composer $composer, final int $changed) {
        int i;
        Composer $composer2 = $composer.startRestartGroup(1621720523);
        ComposerKt.sourceInformation($composer2, "C(BottomSheetScaffoldLayout)P(8!3,7,5:c#ui.unit.Dp,3:c#material.FabPosition)487@19983L2466,487@19966L2483:BottomSheetScaffold.kt#jmzs0o");
        int $dirty = $changed;
        if (($changed & 14) == 0) {
            $dirty |= $composer2.changedInstance(function2) ? 4 : 2;
        }
        if (($changed & 112) == 0) {
            $dirty |= $composer2.changedInstance(function3) ? 32 : 16;
        }
        if (($changed & 896) == 0) {
            $dirty |= $composer2.changedInstance(function32) ? 256 : 128;
        }
        if (($changed & 7168) == 0) {
            $dirty |= $composer2.changedInstance(function22) ? 2048 : 1024;
        }
        if ((57344 & $changed) == 0) {
            $dirty |= $composer2.changedInstance(function23) ? 16384 : 8192;
        }
        if ((458752 & $changed) == 0) {
            $dirty |= $composer2.changed(sheetPeekHeight) ? 131072 : 65536;
        }
        if ((3670016 & $changed) == 0) {
            $dirty |= $composer2.changed(floatingActionButtonPosition) ? 1048576 : 524288;
        }
        if ((29360128 & $changed) == 0) {
            $dirty |= $composer2.changedInstance(function0) ? 8388608 : 4194304;
        }
        if ((234881024 & $changed) == 0) {
            $dirty |= $composer2.changed(sheetState) ? 67108864 : 33554432;
        }
        if ((191739611 & $dirty) != 38347922 || !$composer2.getSkipping()) {
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(1621720523, $dirty, -1, "androidx.compose.material.BottomSheetScaffoldLayout (BottomSheetScaffold.kt:476)");
            }
            Object[] keys$iv = {function32, function0, function2, function3, Dp.m5120boximpl(sheetPeekHeight), function22, FabPosition.m1025boximpl(floatingActionButtonPosition), function23, sheetState};
            $composer2.startReplaceableGroup(-568225417);
            ComposerKt.sourceInformation($composer2, "CC(remember)P(1):Composables.kt#9igjgp");
            boolean invalid$iv = false;
            for (Object key$iv : keys$iv) {
                invalid$iv |= $composer2.changed(key$iv);
            }
            Object value$iv$iv = $composer2.rememberedValue();
            if (invalid$iv || value$iv$iv == Composer.Companion.getEmpty()) {
                i = 0;
                final int i2 = $dirty;
                value$iv$iv = new Function2<SubcomposeMeasureScope, Constraints, MeasureResult>() { // from class: androidx.compose.material.BottomSheetScaffoldKt$BottomSheetScaffoldLayout$1$1

                    /* compiled from: BottomSheetScaffold.kt */
                    @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
                    /* loaded from: classes.dex */
                    public /* synthetic */ class WhenMappings {
                        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

                        static {
                            int[] iArr = new int[BottomSheetValue.values().length];
                            try {
                                iArr[BottomSheetValue.Collapsed.ordinal()] = 1;
                            } catch (NoSuchFieldError e) {
                            }
                            try {
                                iArr[BottomSheetValue.Expanded.ordinal()] = 2;
                            } catch (NoSuchFieldError e2) {
                            }
                            $EnumSwitchMapping$0 = iArr;
                        }
                    }

                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    /* JADX WARN: Multi-variable type inference failed */
                    {
                        super(2);
                    }

                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ MeasureResult invoke(SubcomposeMeasureScope subcomposeMeasureScope, Constraints constraints) {
                        return m926invoke0kLqBqw(subcomposeMeasureScope, constraints.m5084unboximpl());
                    }

                    /* renamed from: invoke-0kLqBqw  reason: not valid java name */
                    public final MeasureResult m926invoke0kLqBqw(SubcomposeMeasureScope SubcomposeLayout, long constraints) {
                        long looseConstraints;
                        Placeable placeable;
                        long bodyConstraints;
                        float f;
                        final int fabOffsetX;
                        int i3;
                        final int snackbarOffsetY;
                        float f2;
                        Intrinsics.checkNotNullParameter(SubcomposeLayout, "$this$SubcomposeLayout");
                        int layoutWidth = Constraints.m5078getMaxWidthimpl(constraints);
                        final int layoutHeight = Constraints.m5077getMaxHeightimpl(constraints);
                        looseConstraints = Constraints.m5068copyZbe2FdA(constraints, (r12 & 1) != 0 ? Constraints.m5080getMinWidthimpl(constraints) : 0, (r12 & 2) != 0 ? Constraints.m5078getMaxWidthimpl(constraints) : 0, (r12 & 4) != 0 ? Constraints.m5079getMinHeightimpl(constraints) : 0, (r12 & 8) != 0 ? Constraints.m5077getMaxHeightimpl(constraints) : 0);
                        BottomSheetScaffoldLayoutSlot bottomSheetScaffoldLayoutSlot = BottomSheetScaffoldLayoutSlot.Sheet;
                        final Function3<Integer, Composer, Integer, Unit> function33 = function32;
                        final int i4 = i2;
                        final Placeable sheetPlaceable = SubcomposeLayout.subcompose(bottomSheetScaffoldLayoutSlot, ComposableLambdaKt.composableLambdaInstance(-2120029209, true, new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material.BottomSheetScaffoldKt$BottomSheetScaffoldLayout$1$1$sheetPlaceable$1
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

                            public final void invoke(Composer $composer3, int $changed2) {
                                ComposerKt.sourceInformation($composer3, "C492@20264L25:BottomSheetScaffold.kt#jmzs0o");
                                if (($changed2 & 11) == 2 && $composer3.getSkipping()) {
                                    $composer3.skipToGroupEnd();
                                    return;
                                }
                                if (ComposerKt.isTraceInProgress()) {
                                    ComposerKt.traceEventStart(-2120029209, $changed2, -1, "androidx.compose.material.BottomSheetScaffoldLayout.<anonymous>.<anonymous>.<anonymous> (BottomSheetScaffold.kt:491)");
                                }
                                function33.invoke(Integer.valueOf(layoutHeight), $composer3, Integer.valueOf((i4 >> 3) & 112));
                                if (ComposerKt.isTraceInProgress()) {
                                    ComposerKt.traceEventEnd();
                                }
                            }
                        })).get(0).mo4125measureBRTryo0(looseConstraints);
                        final int sheetOffsetY = MathKt.roundToInt(function0.invoke().floatValue());
                        final Function2<Composer, Integer, Unit> function24 = function2;
                        if (function24 != null) {
                            final int i5 = i2;
                            placeable = SubcomposeLayout.subcompose(BottomSheetScaffoldLayoutSlot.TopBar, ComposableLambdaKt.composableLambdaInstance(1477114206, true, new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material.BottomSheetScaffoldKt$BottomSheetScaffoldLayout$1$1$topBarPlaceable$1$1
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

                                public final void invoke(Composer $composer3, int $changed2) {
                                    ComposerKt.sourceInformation($composer3, "C496@20490L8:BottomSheetScaffold.kt#jmzs0o");
                                    if (($changed2 & 11) == 2 && $composer3.getSkipping()) {
                                        $composer3.skipToGroupEnd();
                                        return;
                                    }
                                    if (ComposerKt.isTraceInProgress()) {
                                        ComposerKt.traceEventStart(1477114206, $changed2, -1, "androidx.compose.material.BottomSheetScaffoldLayout.<anonymous>.<anonymous>.<anonymous>.<anonymous> (BottomSheetScaffold.kt:496)");
                                    }
                                    function24.invoke($composer3, Integer.valueOf(i5 & 14));
                                    if (ComposerKt.isTraceInProgress()) {
                                        ComposerKt.traceEventEnd();
                                    }
                                }
                            })).get(0).mo4125measureBRTryo0(looseConstraints);
                        } else {
                            placeable = null;
                        }
                        final Placeable topBarPlaceable = placeable;
                        final int topBarHeight = topBarPlaceable != null ? topBarPlaceable.getHeight() : 0;
                        bodyConstraints = Constraints.m5068copyZbe2FdA(looseConstraints, (r12 & 1) != 0 ? Constraints.m5080getMinWidthimpl(looseConstraints) : 0, (r12 & 2) != 0 ? Constraints.m5078getMaxWidthimpl(looseConstraints) : 0, (r12 & 4) != 0 ? Constraints.m5079getMinHeightimpl(looseConstraints) : 0, (r12 & 8) != 0 ? Constraints.m5077getMaxHeightimpl(looseConstraints) : layoutHeight - topBarHeight);
                        BottomSheetScaffoldLayoutSlot bottomSheetScaffoldLayoutSlot2 = BottomSheetScaffoldLayoutSlot.Body;
                        final Function3<PaddingValues, Composer, Integer, Unit> function34 = function3;
                        final float f3 = sheetPeekHeight;
                        final int i6 = i2;
                        final Placeable bodyPlaceable = SubcomposeLayout.subcompose(bottomSheetScaffoldLayoutSlot2, ComposableLambdaKt.composableLambdaInstance(2078633916, true, new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material.BottomSheetScaffoldKt$BottomSheetScaffoldLayout$1$1$bodyPlaceable$1
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

                            public final void invoke(Composer $composer3, int $changed2) {
                                ComposerKt.sourceInformation($composer3, "C502@20795L45:BottomSheetScaffold.kt#jmzs0o");
                                if (($changed2 & 11) == 2 && $composer3.getSkipping()) {
                                    $composer3.skipToGroupEnd();
                                    return;
                                }
                                if (ComposerKt.isTraceInProgress()) {
                                    ComposerKt.traceEventStart(2078633916, $changed2, -1, "androidx.compose.material.BottomSheetScaffoldLayout.<anonymous>.<anonymous>.<anonymous> (BottomSheetScaffold.kt:501)");
                                }
                                function34.invoke(PaddingKt.m411PaddingValuesa9UjIt4$default(0.0f, 0.0f, 0.0f, f3, 7, null), $composer3, Integer.valueOf(i6 & 112));
                                if (ComposerKt.isTraceInProgress()) {
                                    ComposerKt.traceEventEnd();
                                }
                            }
                        })).get(0).mo4125measureBRTryo0(bodyConstraints);
                        Function2 fab = function22;
                        final Placeable fabPlaceable = fab != null ? SubcomposeLayout.subcompose(BottomSheetScaffoldLayoutSlot.Fab, fab).get(0).mo4125measureBRTryo0(looseConstraints) : null;
                        int fabWidth = fabPlaceable != null ? fabPlaceable.getWidth() : 0;
                        int fabHeight = fabPlaceable != null ? fabPlaceable.getHeight() : 0;
                        if (FabPosition.m1028equalsimpl0(floatingActionButtonPosition, FabPosition.Companion.m1032getCenter5ygKITE())) {
                            fabOffsetX = (layoutWidth - fabWidth) / 2;
                        } else {
                            f = BottomSheetScaffoldKt.FabSpacing;
                            fabOffsetX = (layoutWidth - fabWidth) - SubcomposeLayout.mo295roundToPx0680j_4(f);
                        }
                        if (SubcomposeLayout.mo301toPx0680j_4(sheetPeekHeight) < fabHeight / 2) {
                            f2 = BottomSheetScaffoldKt.FabSpacing;
                            i3 = (sheetOffsetY - fabHeight) - SubcomposeLayout.mo295roundToPx0680j_4(f2);
                        } else {
                            i3 = sheetOffsetY - (fabHeight / 2);
                        }
                        final int fabOffsetY = i3;
                        final Placeable snackbarPlaceable = SubcomposeLayout.subcompose(BottomSheetScaffoldLayoutSlot.Snackbar, function23).get(0).mo4125measureBRTryo0(looseConstraints);
                        final int snackbarOffsetX = (layoutWidth - snackbarPlaceable.getWidth()) / 2;
                        switch (WhenMappings.$EnumSwitchMapping$0[sheetState.getCurrentValue().ordinal()]) {
                            case 1:
                                snackbarOffsetY = fabOffsetY - snackbarPlaceable.getHeight();
                                break;
                            case 2:
                                snackbarOffsetY = layoutHeight - snackbarPlaceable.getHeight();
                                break;
                            default:
                                throw new NoWhenBranchMatchedException();
                        }
                        return MeasureScope.layout$default(SubcomposeLayout, layoutWidth, layoutHeight, null, new Function1<Placeable.PlacementScope, Unit>() { // from class: androidx.compose.material.BottomSheetScaffoldKt$BottomSheetScaffoldLayout$1$1.1
                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            {
                                super(1);
                            }

                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(Placeable.PlacementScope placementScope) {
                                invoke2(placementScope);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke  reason: avoid collision after fix types in other method */
                            public final void invoke2(Placeable.PlacementScope layout) {
                                Intrinsics.checkNotNullParameter(layout, "$this$layout");
                                Placeable.PlacementScope.placeRelative$default(layout, Placeable.this, 0, topBarHeight, 0.0f, 4, null);
                                Placeable placeable2 = topBarPlaceable;
                                if (placeable2 != null) {
                                    Placeable.PlacementScope.placeRelative$default(layout, placeable2, 0, 0, 0.0f, 4, null);
                                }
                                Placeable.PlacementScope.placeRelative$default(layout, sheetPlaceable, 0, sheetOffsetY, 0.0f, 4, null);
                                Placeable placeable3 = fabPlaceable;
                                if (placeable3 != null) {
                                    Placeable.PlacementScope.placeRelative$default(layout, placeable3, fabOffsetX, fabOffsetY, 0.0f, 4, null);
                                }
                                Placeable.PlacementScope.placeRelative$default(layout, snackbarPlaceable, snackbarOffsetX, snackbarOffsetY, 0.0f, 4, null);
                            }
                        }, 4, null);
                    }
                };
                $composer2.updateRememberedValue(value$iv$iv);
            } else {
                i = 0;
            }
            $composer2.endReplaceableGroup();
            SubcomposeLayoutKt.SubcomposeLayout(null, (Function2) value$iv$iv, $composer2, i, 1);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
        } else {
            $composer2.skipToGroupEnd();
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material.BottomSheetScaffoldKt$BottomSheetScaffoldLayout$2
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

            public final void invoke(Composer composer, int i3) {
                BottomSheetScaffoldKt.m922BottomSheetScaffoldLayoutKCBPh4w(function2, function3, function32, function22, function23, sheetPeekHeight, floatingActionButtonPosition, function0, sheetState, composer, RecomposeScopeImplKt.updateChangedFlags($changed | 1));
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final NestedScrollConnection ConsumeSwipeWithinBottomSheetBoundsNestedScrollConnection(SwipeableV2State<?> swipeableV2State, Orientation orientation) {
        return new BottomSheetScaffoldKt$ConsumeSwipeWithinBottomSheetBoundsNestedScrollConnection$1(swipeableV2State, orientation);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final AnchorChangeHandler<BottomSheetValue> BottomSheetScaffoldAnchorChangeHandler(final BottomSheetState state, final Function1<? super BottomSheetValue, Unit> function1, final Function1<? super BottomSheetValue, Unit> function12) {
        return new AnchorChangeHandler<BottomSheetValue>() { // from class: androidx.compose.material.BottomSheetScaffoldKt$BottomSheetScaffoldAnchorChangeHandler$1

            /* compiled from: BottomSheetScaffold.kt */
            @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
            /* loaded from: classes.dex */
            public /* synthetic */ class WhenMappings {
                public static final /* synthetic */ int[] $EnumSwitchMapping$0;

                static {
                    int[] iArr = new int[BottomSheetValue.values().length];
                    try {
                        iArr[BottomSheetValue.Collapsed.ordinal()] = 1;
                    } catch (NoSuchFieldError e) {
                    }
                    try {
                        iArr[BottomSheetValue.Expanded.ordinal()] = 2;
                    } catch (NoSuchFieldError e2) {
                    }
                    $EnumSwitchMapping$0 = iArr;
                }
            }

            @Override // androidx.compose.material.AnchorChangeHandler
            public final void onAnchorsChanged(BottomSheetValue previousTarget, Map<BottomSheetValue, Float> previousAnchors, Map<BottomSheetValue, Float> newAnchors) {
                BottomSheetValue newTarget;
                Intrinsics.checkNotNullParameter(previousTarget, "previousTarget");
                Intrinsics.checkNotNullParameter(previousAnchors, "previousAnchors");
                Intrinsics.checkNotNullParameter(newAnchors, "newAnchors");
                Float previousTargetOffset = previousAnchors.get(previousTarget);
                switch (WhenMappings.$EnumSwitchMapping$0[previousTarget.ordinal()]) {
                    case 1:
                        newTarget = BottomSheetValue.Collapsed;
                        break;
                    case 2:
                        if (!newAnchors.containsKey(BottomSheetValue.Expanded)) {
                            newTarget = BottomSheetValue.Collapsed;
                            break;
                        } else {
                            newTarget = BottomSheetValue.Expanded;
                            break;
                        }
                    default:
                        throw new NoWhenBranchMatchedException();
                }
                float newTargetOffset = ((Number) MapsKt.getValue(newAnchors, newTarget)).floatValue();
                if (!Intrinsics.areEqual(newTargetOffset, previousTargetOffset)) {
                    if (BottomSheetState.this.isAnimationRunning$material_release()) {
                        function1.invoke(newTarget);
                    } else {
                        function12.invoke(newTarget);
                    }
                }
            }
        };
    }
}
