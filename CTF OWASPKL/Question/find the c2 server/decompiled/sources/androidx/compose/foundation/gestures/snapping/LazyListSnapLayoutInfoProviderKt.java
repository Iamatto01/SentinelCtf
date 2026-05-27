package androidx.compose.foundation.gestures.snapping;

import androidx.autofill.HintConstants;
import androidx.compose.animation.SplineBasedDecayKt;
import androidx.compose.animation.core.DecayAnimationSpec;
import androidx.compose.animation.core.DecayAnimationSpecKt;
import androidx.compose.foundation.gestures.FlingBehavior;
import androidx.compose.foundation.gestures.Orientation;
import androidx.compose.foundation.lazy.LazyListItemInfo;
import androidx.compose.foundation.lazy.LazyListLayoutInfo;
import androidx.compose.foundation.lazy.LazyListState;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.ui.unit.Density;
import androidx.compose.ui.unit.IntSize;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.ClosedFloatingPointRange;
import kotlin.ranges.RangesKt;
/* compiled from: LazyListSnapLayoutInfoProvider.kt */
@Metadata(d1 = {"\u0000B\n\u0000\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\u001aU\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\b2C\b\u0002\u0010\t\u001a=\u0012\u0004\u0012\u00020\u000b\u0012\u0013\u0012\u00110\f¢\u0006\f\b\r\u0012\b\b\u000e\u0012\u0004\b\b(\u000f\u0012\u0013\u0012\u00110\f¢\u0006\f\b\r\u0012\b\b\u000e\u0012\u0004\b\b(\u0010\u0012\u0004\u0012\u00020\f0\n¢\u0006\u0002\b\u0011H\u0007\u001a\u0015\u0010\u0012\u001a\u00020\u00132\u0006\u0010\u0007\u001a\u00020\bH\u0007¢\u0006\u0002\u0010\u0014\u001a_\u0010\u0015\u001a\u00020\f*\u00020\u000b2\u0006\u0010\u0016\u001a\u00020\u00022\u0006\u0010\u0017\u001a\u00020\u00182A\u0010\t\u001a=\u0012\u0004\u0012\u00020\u000b\u0012\u0013\u0012\u00110\f¢\u0006\f\b\r\u0012\b\b\u000e\u0012\u0004\b\b(\u000f\u0012\u0013\u0012\u00110\f¢\u0006\f\b\r\u0012\b\b\u000e\u0012\u0004\b\b(\u0010\u0012\u0004\u0012\u00020\f0\n¢\u0006\u0002\b\u0011H\u0000\"\u0018\u0010\u0000\u001a\u00020\u0001*\u00020\u00028BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u0003\u0010\u0004¨\u0006\u0019"}, d2 = {"singleAxisViewportSize", "", "Landroidx/compose/foundation/lazy/LazyListLayoutInfo;", "getSingleAxisViewportSize", "(Landroidx/compose/foundation/lazy/LazyListLayoutInfo;)I", "SnapLayoutInfoProvider", "Landroidx/compose/foundation/gestures/snapping/SnapLayoutInfoProvider;", "lazyListState", "Landroidx/compose/foundation/lazy/LazyListState;", "positionInLayout", "Lkotlin/Function3;", "Landroidx/compose/ui/unit/Density;", "", "Lkotlin/ParameterName;", HintConstants.AUTOFILL_HINT_NAME, "layoutSize", "itemSize", "Lkotlin/ExtensionFunctionType;", "rememberSnapFlingBehavior", "Landroidx/compose/foundation/gestures/FlingBehavior;", "(Landroidx/compose/foundation/lazy/LazyListState;Landroidx/compose/runtime/Composer;I)Landroidx/compose/foundation/gestures/FlingBehavior;", "calculateDistanceToDesiredSnapPosition", "layoutInfo", "item", "Landroidx/compose/foundation/lazy/LazyListItemInfo;", "foundation_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LazyListSnapLayoutInfoProviderKt {
    public static /* synthetic */ SnapLayoutInfoProvider SnapLayoutInfoProvider$default(LazyListState lazyListState, Function3 function3, int i, Object obj) {
        if ((i & 2) != 0) {
            function3 = new Function3<Density, Float, Float, Float>() { // from class: androidx.compose.foundation.gestures.snapping.LazyListSnapLayoutInfoProviderKt$SnapLayoutInfoProvider$1
                public final Float invoke(Density $this$null, float layoutSize, float itemSize) {
                    Intrinsics.checkNotNullParameter($this$null, "$this$null");
                    return Float.valueOf((layoutSize / 2.0f) - (itemSize / 2.0f));
                }

                @Override // kotlin.jvm.functions.Function3
                public /* bridge */ /* synthetic */ Float invoke(Density density, Float f, Float f2) {
                    return invoke(density, f.floatValue(), f2.floatValue());
                }
            };
        }
        return SnapLayoutInfoProvider(lazyListState, function3);
    }

    public static final SnapLayoutInfoProvider SnapLayoutInfoProvider(final LazyListState lazyListState, final Function3<? super Density, ? super Float, ? super Float, Float> positionInLayout) {
        Intrinsics.checkNotNullParameter(lazyListState, "lazyListState");
        Intrinsics.checkNotNullParameter(positionInLayout, "positionInLayout");
        return new SnapLayoutInfoProvider() { // from class: androidx.compose.foundation.gestures.snapping.LazyListSnapLayoutInfoProviderKt$SnapLayoutInfoProvider$2
            private final LazyListLayoutInfo getLayoutInfo() {
                return LazyListState.this.getLayoutInfo();
            }

            @Override // androidx.compose.foundation.gestures.snapping.SnapLayoutInfoProvider
            public float calculateApproachOffset(Density $this$calculateApproachOffset, float initialVelocity) {
                Intrinsics.checkNotNullParameter($this$calculateApproachOffset, "<this>");
                DecayAnimationSpec decayAnimationSpec = SplineBasedDecayKt.splineBasedDecay($this$calculateApproachOffset);
                float offset = Math.abs(DecayAnimationSpecKt.calculateTargetValue(decayAnimationSpec, 0.0f, initialVelocity));
                float finalDecayOffset = RangesKt.coerceAtLeast(offset - calculateSnapStepSize($this$calculateApproachOffset), 0.0f);
                if (finalDecayOffset == 0.0f) {
                    return finalDecayOffset;
                }
                return Math.signum(initialVelocity) * finalDecayOffset;
            }

            @Override // androidx.compose.foundation.gestures.snapping.SnapLayoutInfoProvider
            public ClosedFloatingPointRange<Float> calculateSnappingOffsetBounds(Density $this$calculateSnappingOffsetBounds) {
                Intrinsics.checkNotNullParameter($this$calculateSnappingOffsetBounds, "<this>");
                float lowerBoundOffset = Float.NEGATIVE_INFINITY;
                float upperBoundOffset = Float.POSITIVE_INFINITY;
                List $this$fastForEach$iv = getLayoutInfo().getVisibleItemsInfo();
                Function3<Density, Float, Float, Float> function3 = positionInLayout;
                int size = $this$fastForEach$iv.size();
                for (int index$iv = 0; index$iv < size; index$iv++) {
                    Object item$iv = $this$fastForEach$iv.get(index$iv);
                    LazyListItemInfo item = (LazyListItemInfo) item$iv;
                    float offset = LazyListSnapLayoutInfoProviderKt.calculateDistanceToDesiredSnapPosition($this$calculateSnappingOffsetBounds, getLayoutInfo(), item, function3);
                    if (offset <= 0.0f && offset > lowerBoundOffset) {
                        lowerBoundOffset = offset;
                    }
                    if (offset >= 0.0f && offset < upperBoundOffset) {
                        upperBoundOffset = offset;
                    }
                }
                return RangesKt.rangeTo(lowerBoundOffset, upperBoundOffset);
            }

            @Override // androidx.compose.foundation.gestures.snapping.SnapLayoutInfoProvider
            public float calculateSnapStepSize(Density $this$calculateSnapStepSize) {
                Intrinsics.checkNotNullParameter($this$calculateSnapStepSize, "<this>");
                LazyListLayoutInfo $this$calculateSnapStepSize_u24lambda_u242 = getLayoutInfo();
                if (!$this$calculateSnapStepSize_u24lambda_u242.getVisibleItemsInfo().isEmpty()) {
                    List $this$fastSumBy$iv = $this$calculateSnapStepSize_u24lambda_u242.getVisibleItemsInfo();
                    int sum$iv = 0;
                    int size = $this$fastSumBy$iv.size();
                    for (int index$iv$iv = 0; index$iv$iv < size; index$iv$iv++) {
                        Object item$iv$iv = $this$fastSumBy$iv.get(index$iv$iv);
                        LazyListItemInfo it = (LazyListItemInfo) item$iv$iv;
                        sum$iv += it.getSize();
                    }
                    return sum$iv / $this$calculateSnapStepSize_u24lambda_u242.getVisibleItemsInfo().size();
                }
                return 0.0f;
            }
        };
    }

    public static final FlingBehavior rememberSnapFlingBehavior(LazyListState lazyListState, Composer $composer, int $changed) {
        SnapLayoutInfoProvider value$iv$iv;
        Intrinsics.checkNotNullParameter(lazyListState, "lazyListState");
        $composer.startReplaceableGroup(1148456277);
        ComposerKt.sourceInformation($composer, "C(rememberSnapFlingBehavior)109@4330L65,110@4407L41:LazyListSnapLayoutInfoProvider.kt#ppz6w6");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(1148456277, $changed, -1, "androidx.compose.foundation.gestures.snapping.rememberSnapFlingBehavior (LazyListSnapLayoutInfoProvider.kt:108)");
        }
        int i = $changed & 14;
        $composer.startReplaceableGroup(1157296644);
        ComposerKt.sourceInformation($composer, "CC(remember)P(1):Composables.kt#9igjgp");
        boolean invalid$iv$iv = $composer.changed(lazyListState);
        Object it$iv$iv = $composer.rememberedValue();
        if (invalid$iv$iv || it$iv$iv == Composer.Companion.getEmpty()) {
            value$iv$iv = SnapLayoutInfoProvider$default(lazyListState, null, 2, null);
            $composer.updateRememberedValue(value$iv$iv);
        } else {
            value$iv$iv = it$iv$iv;
        }
        $composer.endReplaceableGroup();
        SnapLayoutInfoProvider snappingLayout = value$iv$iv;
        SnapFlingBehavior rememberSnapFlingBehavior = SnapFlingBehaviorKt.rememberSnapFlingBehavior(snappingLayout, $composer, 0);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return rememberSnapFlingBehavior;
    }

    public static final float calculateDistanceToDesiredSnapPosition(Density $this$calculateDistanceToDesiredSnapPosition, LazyListLayoutInfo layoutInfo, LazyListItemInfo item, Function3<? super Density, ? super Float, ? super Float, Float> positionInLayout) {
        Intrinsics.checkNotNullParameter($this$calculateDistanceToDesiredSnapPosition, "<this>");
        Intrinsics.checkNotNullParameter(layoutInfo, "layoutInfo");
        Intrinsics.checkNotNullParameter(item, "item");
        Intrinsics.checkNotNullParameter(positionInLayout, "positionInLayout");
        int containerSize = (getSingleAxisViewportSize(layoutInfo) - layoutInfo.getBeforeContentPadding()) - layoutInfo.getAfterContentPadding();
        float desiredDistance = positionInLayout.invoke($this$calculateDistanceToDesiredSnapPosition, Float.valueOf(containerSize), Float.valueOf(item.getSize())).floatValue();
        int itemCurrentPosition = item.getOffset();
        return itemCurrentPosition - desiredDistance;
    }

    private static final int getSingleAxisViewportSize(LazyListLayoutInfo $this$singleAxisViewportSize) {
        return $this$singleAxisViewportSize.getOrientation() == Orientation.Vertical ? IntSize.m5281getHeightimpl($this$singleAxisViewportSize.mo514getViewportSizeYbymL2g()) : IntSize.m5282getWidthimpl($this$singleAxisViewportSize.mo514getViewportSizeYbymL2g());
    }
}
