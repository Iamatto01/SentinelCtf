package androidx.compose.foundation.lazy.layout;

import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.EffectsKt;
import androidx.compose.runtime.MutableState;
import androidx.compose.runtime.SnapshotStateKt__SnapshotStateKt;
import androidx.compose.runtime.State;
import androidx.compose.runtime.snapshots.Snapshot;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.ranges.RangesKt;
/* compiled from: LazyNearestItemsRange.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a \u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0003H\u0002\u001a=\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\u00010\u00072\f\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00030\t2\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\t2\f\u0010\u0005\u001a\b\u0012\u0004\u0012\u00020\u00030\tH\u0007¢\u0006\u0002\u0010\n¨\u0006\u000b"}, d2 = {"calculateNearestItemsRange", "Lkotlin/ranges/IntRange;", "firstVisibleItem", "", "slidingWindowSize", "extraItemCount", "rememberLazyNearestItemsRangeState", "Landroidx/compose/runtime/State;", "firstVisibleItemIndex", "Lkotlin/Function0;", "(Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;Landroidx/compose/runtime/Composer;I)Landroidx/compose/runtime/State;", "foundation_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LazyNearestItemsRangeKt {
    public static final State<IntRange> rememberLazyNearestItemsRangeState(Function0<Integer> firstVisibleItemIndex, Function0<Integer> slidingWindowSize, Function0<Integer> extraItemCount, Composer $composer, int $changed) {
        Snapshot previous$iv$iv;
        Snapshot this_$iv$iv;
        Snapshot previous$iv$iv2;
        Object value$iv$iv;
        Intrinsics.checkNotNullParameter(firstVisibleItemIndex, "firstVisibleItemIndex");
        Intrinsics.checkNotNullParameter(slidingWindowSize, "slidingWindowSize");
        Intrinsics.checkNotNullParameter(extraItemCount, "extraItemCount");
        $composer.startReplaceableGroup(429733345);
        ComposerKt.sourceInformation($composer, "C(rememberLazyNearestItemsRangeState)P(1,2)46@1947L353,58@2328L254,58@2306L276:LazyNearestItemsRange.kt#wow0x6");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(429733345, $changed, -1, "androidx.compose.foundation.lazy.layout.rememberLazyNearestItemsRangeState (LazyNearestItemsRange.kt:41)");
        }
        int i = ($changed & 14) | ($changed & 112) | ($changed & 896);
        $composer.startReplaceableGroup(1618982084);
        ComposerKt.sourceInformation($composer, "CC(remember)P(1,2,3):Composables.kt#9igjgp");
        boolean invalid$iv$iv = $composer.changed(firstVisibleItemIndex) | $composer.changed(slidingWindowSize) | $composer.changed(extraItemCount);
        Object it$iv$iv = $composer.rememberedValue();
        if (invalid$iv$iv || it$iv$iv == Composer.Companion.getEmpty()) {
            Snapshot.Companion this_$iv = Snapshot.Companion;
            Snapshot snapshot$iv = this_$iv.createNonObservableSnapshot();
            try {
                previous$iv$iv = snapshot$iv.makeCurrent();
            } catch (Throwable th) {
                th = th;
            }
            try {
                try {
                    int intValue = firstVisibleItemIndex.invoke().intValue();
                    try {
                        int $changed$iv = slidingWindowSize.invoke().intValue();
                        try {
                            int $i$f$remember = extraItemCount.invoke().intValue();
                            value$iv$iv = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(calculateNearestItemsRange(intValue, $changed$iv, $i$f$remember), null, 2, null);
                            snapshot$iv.restoreCurrent(previous$iv$iv);
                            snapshot$iv.dispose();
                            $composer.updateRememberedValue(value$iv$iv);
                        } catch (Throwable th2) {
                            th = th2;
                            this_$iv$iv = snapshot$iv;
                            previous$iv$iv2 = previous$iv$iv;
                            this_$iv$iv.restoreCurrent(previous$iv$iv2);
                            throw th;
                        }
                    } catch (Throwable th3) {
                        th = th3;
                        this_$iv$iv = snapshot$iv;
                        previous$iv$iv2 = previous$iv$iv;
                    }
                } catch (Throwable th4) {
                    th = th4;
                    this_$iv$iv = snapshot$iv;
                    previous$iv$iv2 = previous$iv$iv;
                }
            } catch (Throwable th5) {
                th = th5;
                snapshot$iv.dispose();
                throw th;
            }
        } else {
            value$iv$iv = it$iv$iv;
        }
        $composer.endReplaceableGroup();
        MutableState state = (MutableState) value$iv$iv;
        Object[] keys$iv = {firstVisibleItemIndex, slidingWindowSize, extraItemCount, state};
        $composer.startReplaceableGroup(-568225417);
        ComposerKt.sourceInformation($composer, "CC(remember)P(1):Composables.kt#9igjgp");
        boolean invalid$iv = false;
        for (Object key$iv : keys$iv) {
            invalid$iv |= $composer.changed(key$iv);
        }
        Object value$iv$iv2 = $composer.rememberedValue();
        if (invalid$iv || value$iv$iv2 == Composer.Companion.getEmpty()) {
            value$iv$iv2 = new LazyNearestItemsRangeKt$rememberLazyNearestItemsRangeState$1$1(firstVisibleItemIndex, slidingWindowSize, extraItemCount, state, null);
            $composer.updateRememberedValue(value$iv$iv2);
        }
        $composer.endReplaceableGroup();
        EffectsKt.LaunchedEffect(state, (Function2) value$iv$iv2, $composer, 64);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return state;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final IntRange calculateNearestItemsRange(int firstVisibleItem, int slidingWindowSize, int extraItemCount) {
        int slidingWindowStart = (firstVisibleItem / slidingWindowSize) * slidingWindowSize;
        int start = Math.max(slidingWindowStart - extraItemCount, 0);
        int end = slidingWindowStart + slidingWindowSize + extraItemCount;
        return RangesKt.until(start, end);
    }
}
