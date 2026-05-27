package androidx.compose.foundation.lazy.staggeredgrid;

import androidx.autofill.HintConstants;
import androidx.compose.foundation.lazy.layout.LazyLayoutItemProvider;
import androidx.compose.foundation.lazy.layout.LazyLayoutItemProviderKt;
import androidx.compose.runtime.MutableState;
import androidx.compose.runtime.SnapshotStateKt__SnapshotStateKt;
import androidx.compose.runtime.State;
import androidx.compose.runtime.snapshots.Snapshot;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.ArraysKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
/* compiled from: LazyStaggeredGridScrollPosition.kt */
@Metadata(d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0015\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\u000e\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\b\u0001\u0018\u00002\u00020\u0001BM\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u00126\u0010\u0005\u001a2\u0012\u0013\u0012\u00110\u0007¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0013\u0012\u00110\u0007¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u000b\u0012\u0004\u0012\u00020\u00030\u0006¢\u0006\u0002\u0010\fJ\u0016\u0010\u001c\u001a\u00020\u001d2\u0006\u0010\u001e\u001a\u00020\u00072\u0006\u0010\u001f\u001a\u00020\u0007J\u0018\u0010 \u001a\u00020\u001d2\u0006\u0010\u0010\u001a\u00020\u00032\u0006\u0010\u0018\u001a\u00020\u0003H\u0002J\u000e\u0010!\u001a\u00020\u001d2\u0006\u0010\"\u001a\u00020#J\u0010\u0010$\u001a\u00020\u001d2\u0006\u0010%\u001a\u00020&H\u0007R>\u0010\u0005\u001a2\u0012\u0013\u0012\u00110\u0007¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0013\u0012\u00110\u0007¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u000b\u0012\u0004\u0012\u00020\u00030\u0006X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\r\u001a\u00020\u000eX\u0082\u000e¢\u0006\u0002\n\u0000R+\u0010\u0010\u001a\u00020\u00032\u0006\u0010\u000f\u001a\u00020\u00038F@FX\u0086\u008e\u0002¢\u0006\u0012\n\u0004\b\u0015\u0010\u0016\u001a\u0004\b\u0011\u0010\u0012\"\u0004\b\u0013\u0010\u0014R\u0010\u0010\u0017\u001a\u0004\u0018\u00010\u0001X\u0082\u000e¢\u0006\u0002\n\u0000R+\u0010\u0018\u001a\u00020\u00032\u0006\u0010\u000f\u001a\u00020\u00038F@FX\u0086\u008e\u0002¢\u0006\u0012\n\u0004\b\u001b\u0010\u0016\u001a\u0004\b\u0019\u0010\u0012\"\u0004\b\u001a\u0010\u0014¨\u0006'"}, d2 = {"Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridScrollPosition;", "", "initialIndices", "", "initialOffsets", "fillIndices", "Lkotlin/Function2;", "", "Lkotlin/ParameterName;", HintConstants.AUTOFILL_HINT_NAME, "targetIndex", "laneCount", "([I[ILkotlin/jvm/functions/Function2;)V", "hadFirstNotEmptyLayout", "", "<set-?>", "indices", "getIndices", "()[I", "setIndices", "([I)V", "indices$delegate", "Landroidx/compose/runtime/MutableState;", "lastKnownFirstItemKey", "offsets", "getOffsets", "setOffsets", "offsets$delegate", "requestPosition", "", "index", "scrollOffset", "update", "updateFromMeasureResult", "measureResult", "Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridMeasureResult;", "updateScrollPositionIfTheFirstItemWasMoved", "itemProvider", "Landroidx/compose/foundation/lazy/layout/LazyLayoutItemProvider;", "foundation_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LazyStaggeredGridScrollPosition {
    private final Function2<Integer, Integer, int[]> fillIndices;
    private boolean hadFirstNotEmptyLayout;
    private final MutableState indices$delegate;
    private Object lastKnownFirstItemKey;
    private final MutableState offsets$delegate;

    /* JADX WARN: Multi-variable type inference failed */
    public LazyStaggeredGridScrollPosition(int[] initialIndices, int[] initialOffsets, Function2<? super Integer, ? super Integer, int[]> fillIndices) {
        MutableState mutableStateOf$default;
        MutableState mutableStateOf$default2;
        Intrinsics.checkNotNullParameter(initialIndices, "initialIndices");
        Intrinsics.checkNotNullParameter(initialOffsets, "initialOffsets");
        Intrinsics.checkNotNullParameter(fillIndices, "fillIndices");
        this.fillIndices = fillIndices;
        mutableStateOf$default = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(initialIndices, null, 2, null);
        this.indices$delegate = mutableStateOf$default;
        mutableStateOf$default2 = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(initialOffsets, null, 2, null);
        this.offsets$delegate = mutableStateOf$default2;
    }

    public final int[] getIndices() {
        State $this$getValue$iv = this.indices$delegate;
        return (int[]) $this$getValue$iv.getValue();
    }

    public final void setIndices(int[] iArr) {
        Intrinsics.checkNotNullParameter(iArr, "<set-?>");
        MutableState $this$setValue$iv = this.indices$delegate;
        $this$setValue$iv.setValue(iArr);
    }

    public final int[] getOffsets() {
        State $this$getValue$iv = this.offsets$delegate;
        return (int[]) $this$getValue$iv.getValue();
    }

    public final void setOffsets(int[] iArr) {
        Intrinsics.checkNotNullParameter(iArr, "<set-?>");
        MutableState $this$setValue$iv = this.offsets$delegate;
        $this$setValue$iv.setValue(iArr);
    }

    /* JADX WARN: Type inference failed for: r10v4, types: [kotlin.collections.IntIterator] */
    public final void updateFromMeasureResult(LazyStaggeredGridMeasureResult measureResult) {
        Object it$iv;
        Intrinsics.checkNotNullParameter(measureResult, "measureResult");
        int[] $this$minBy$iv = measureResult.getFirstVisibleItemIndices();
        if ($this$minBy$iv.length == 0) {
            throw new NoSuchElementException();
        }
        int minElem$iv = $this$minBy$iv[0];
        int lastIndex$iv = ArraysKt.getLastIndex($this$minBy$iv);
        if (lastIndex$iv != 0) {
            int it = minElem$iv;
            if (it == -1) {
                it = Integer.MAX_VALUE;
            }
            ?? it2 = new IntRange(1, lastIndex$iv).iterator();
            while (it2.hasNext()) {
                int i$iv = it2.nextInt();
                int e$iv = $this$minBy$iv[i$iv];
                int it3 = e$iv;
                if (it3 == -1) {
                    it3 = Integer.MAX_VALUE;
                }
                if (it > it3) {
                    minElem$iv = e$iv;
                    it = it3;
                }
            }
        }
        int it4 = minElem$iv;
        if (it4 == Integer.MAX_VALUE) {
            it4 = 0;
        }
        int i = it4;
        List $this$fastFirstOrNull$iv = measureResult.getVisibleItemsInfo();
        int index$iv$iv = 0;
        int size = $this$fastFirstOrNull$iv.size();
        while (true) {
            if (index$iv$iv < size) {
                Object item$iv$iv = $this$fastFirstOrNull$iv.get(index$iv$iv);
                it$iv = item$iv$iv;
                if (((LazyStaggeredGridItemInfo) it$iv).getIndex() == i) {
                    break;
                }
                index$iv$iv++;
            } else {
                it$iv = null;
                break;
            }
        }
        LazyStaggeredGridItemInfo lazyStaggeredGridItemInfo = (LazyStaggeredGridItemInfo) it$iv;
        this.lastKnownFirstItemKey = lazyStaggeredGridItemInfo != null ? lazyStaggeredGridItemInfo.getKey() : null;
        if (this.hadFirstNotEmptyLayout || measureResult.getTotalItemsCount() > 0) {
            this.hadFirstNotEmptyLayout = true;
            Snapshot.Companion this_$iv = Snapshot.Companion;
            Snapshot snapshot$iv = this_$iv.createNonObservableSnapshot();
            try {
                Snapshot previous$iv$iv = snapshot$iv.makeCurrent();
                update(measureResult.getFirstVisibleItemIndices(), measureResult.getFirstVisibleItemScrollOffsets());
                Unit unit = Unit.INSTANCE;
                snapshot$iv.restoreCurrent(previous$iv$iv);
            } finally {
                snapshot$iv.dispose();
            }
        }
    }

    public final void requestPosition(int index, int scrollOffset) {
        int[] newIndices = this.fillIndices.invoke(Integer.valueOf(index), Integer.valueOf(getIndices().length));
        int length = newIndices.length;
        int[] newOffsets = new int[length];
        for (int i = 0; i < length; i++) {
            newOffsets[i] = scrollOffset;
        }
        update(newIndices, newOffsets);
        this.lastKnownFirstItemKey = null;
    }

    public final void updateScrollPositionIfTheFirstItemWasMoved(LazyLayoutItemProvider itemProvider) {
        Intrinsics.checkNotNullParameter(itemProvider, "itemProvider");
        Snapshot.Companion this_$iv = Snapshot.Companion;
        Snapshot snapshot$iv = this_$iv.createNonObservableSnapshot();
        try {
            Snapshot previous$iv$iv = snapshot$iv.makeCurrent();
            Object obj = this.lastKnownFirstItemKey;
            Integer orNull = ArraysKt.getOrNull(getIndices(), 0);
            int lastIndex = LazyLayoutItemProviderKt.findIndexByKey(itemProvider, obj, orNull != null ? orNull.intValue() : 0);
            if (!ArraysKt.contains(getIndices(), lastIndex)) {
                update(this.fillIndices.invoke(Integer.valueOf(lastIndex), Integer.valueOf(getIndices().length)), getOffsets());
            }
            Unit unit = Unit.INSTANCE;
            snapshot$iv.restoreCurrent(previous$iv$iv);
        } finally {
            snapshot$iv.dispose();
        }
    }

    private final void update(int[] indices, int[] offsets) {
        if (!Arrays.equals(indices, getIndices())) {
            setIndices(indices);
        }
        if (!Arrays.equals(offsets, getOffsets())) {
            setOffsets(offsets);
        }
    }
}
