package androidx.compose.material.pullrefresh;

import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.CompositionScopedCoroutineScopeCanceller;
import androidx.compose.runtime.EffectsKt;
import androidx.compose.runtime.SnapshotStateKt;
import androidx.compose.runtime.State;
import androidx.compose.ui.platform.CompositionLocalsKt;
import androidx.compose.ui.unit.Density;
import androidx.compose.ui.unit.Dp;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Ref;
import kotlinx.coroutines.CoroutineScope;
/* compiled from: PullRefreshState.kt */
@Metadata(d1 = {"\u0000&\n\u0000\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\u001a?\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\f\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\b0\u00072\b\b\u0002\u0010\t\u001a\u00020\n2\b\b\u0002\u0010\u000b\u001a\u00020\nH\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\f\u0010\r\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006\u000e"}, d2 = {"DragMultiplier", "", "rememberPullRefreshState", "Landroidx/compose/material/pullrefresh/PullRefreshState;", "refreshing", "", "onRefresh", "Lkotlin/Function0;", "", "refreshThreshold", "Landroidx/compose/ui/unit/Dp;", "refreshingOffset", "rememberPullRefreshState-UuyPYSY", "(ZLkotlin/jvm/functions/Function0;FFLandroidx/compose/runtime/Composer;II)Landroidx/compose/material/pullrefresh/PullRefreshState;", "material_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class PullRefreshStateKt {
    private static final float DragMultiplier = 0.5f;

    /* renamed from: rememberPullRefreshState-UuyPYSY  reason: not valid java name */
    public static final PullRefreshState m1207rememberPullRefreshStateUuyPYSY(final boolean refreshing, Function0<Unit> onRefresh, float refreshThreshold, float refreshingOffset, Composer $composer, int $changed, int i) {
        float refreshingOffset2;
        Object value$iv$iv$iv;
        Object value$iv$iv;
        Intrinsics.checkNotNullParameter(onRefresh, "onRefresh");
        $composer.startReplaceableGroup(-174977512);
        ComposerKt.sourceInformation($composer, "C(rememberPullRefreshState)P(2!1,1:c#ui.unit.Dp,3:c#ui.unit.Dp)63@2539L24,64@2589L31,*68@2705L7,73@2838L104,77@2948L152:PullRefreshState.kt#t44y28");
        float refreshThreshold2 = (i & 4) != 0 ? PullRefreshDefaults.INSTANCE.m1200getRefreshThresholdD9Ej5fM() : refreshThreshold;
        if ((i & 8) == 0) {
            refreshingOffset2 = refreshingOffset;
        } else {
            refreshingOffset2 = PullRefreshDefaults.INSTANCE.m1201getRefreshingOffsetD9Ej5fM();
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-174977512, $changed, -1, "androidx.compose.material.pullrefresh.rememberPullRefreshState (PullRefreshState.kt:55)");
        }
        int $this$dp$iv = Dp.m5121compareTo0680j_4(refreshThreshold2, Dp.m5122constructorimpl(0));
        if ($this$dp$iv > 0) {
            $composer.startReplaceableGroup(773894976);
            ComposerKt.sourceInformation($composer, "CC(rememberCoroutineScope)476@19869L144:Effects.kt#9igjgp");
            $composer.startReplaceableGroup(-492369756);
            ComposerKt.sourceInformation($composer, "CC(remember):Composables.kt#9igjgp");
            Object it$iv$iv$iv = $composer.rememberedValue();
            if (it$iv$iv$iv == Composer.Companion.getEmpty()) {
                value$iv$iv$iv = new CompositionScopedCoroutineScopeCanceller(EffectsKt.createCompositionCoroutineScope(EmptyCoroutineContext.INSTANCE, $composer));
                $composer.updateRememberedValue(value$iv$iv$iv);
            } else {
                value$iv$iv$iv = it$iv$iv$iv;
            }
            $composer.endReplaceableGroup();
            CompositionScopedCoroutineScopeCanceller wrapper$iv = (CompositionScopedCoroutineScopeCanceller) value$iv$iv$iv;
            CoroutineScope scope = wrapper$iv.getCoroutineScope();
            $composer.endReplaceableGroup();
            State onRefreshState = SnapshotStateKt.rememberUpdatedState(onRefresh, $composer, ($changed >> 3) & 14);
            final Ref.FloatRef thresholdPx = new Ref.FloatRef();
            final Ref.FloatRef refreshingOffsetPx = new Ref.FloatRef();
            ComposerKt.sourceInformationMarkerStart($composer, 2023513938, "CC:CompositionLocal.kt#9igjgp");
            Object consume = $composer.consume(CompositionLocalsKt.getLocalDensity());
            ComposerKt.sourceInformationMarkerEnd($composer);
            Density $this$rememberPullRefreshState_UuyPYSY_u24lambda_u241 = (Density) consume;
            thresholdPx.element = $this$rememberPullRefreshState_UuyPYSY_u24lambda_u241.mo301toPx0680j_4(refreshThreshold2);
            refreshingOffsetPx.element = $this$rememberPullRefreshState_UuyPYSY_u24lambda_u241.mo301toPx0680j_4(refreshingOffset2);
            $composer.startReplaceableGroup(1157296644);
            ComposerKt.sourceInformation($composer, "CC(remember)P(1):Composables.kt#9igjgp");
            boolean invalid$iv$iv = $composer.changed(scope);
            Object it$iv$iv = $composer.rememberedValue();
            if (invalid$iv$iv || it$iv$iv == Composer.Companion.getEmpty()) {
                float f = refreshingOffsetPx.element;
                float refreshThreshold3 = thresholdPx.element;
                Object value$iv$iv2 = new PullRefreshState(scope, onRefreshState, f, refreshThreshold3);
                $composer.updateRememberedValue(value$iv$iv2);
                value$iv$iv = value$iv$iv2;
            } else {
                value$iv$iv = it$iv$iv;
            }
            $composer.endReplaceableGroup();
            final PullRefreshState state = (PullRefreshState) value$iv$iv;
            EffectsKt.SideEffect(new Function0<Unit>() { // from class: androidx.compose.material.pullrefresh.PullRefreshStateKt$rememberPullRefreshState$3
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                    PullRefreshState.this.setRefreshing$material_release(refreshing);
                    PullRefreshState.this.setThreshold$material_release(thresholdPx.element);
                    PullRefreshState.this.setRefreshingOffset$material_release(refreshingOffsetPx.element);
                }
            }, $composer, 0);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            $composer.endReplaceableGroup();
            return state;
        }
        throw new IllegalArgumentException("The refresh trigger must be greater than zero!".toString());
    }
}
