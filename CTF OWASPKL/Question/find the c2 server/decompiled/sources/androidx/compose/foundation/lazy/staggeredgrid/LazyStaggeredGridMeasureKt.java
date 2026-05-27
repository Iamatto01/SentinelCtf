package androidx.compose.foundation.lazy.staggeredgrid;

import androidx.autofill.HintConstants;
import androidx.compose.foundation.lazy.layout.LazyLayoutItemProviderKt;
import androidx.compose.foundation.lazy.layout.LazyLayoutMeasureScope;
import androidx.compose.foundation.lazy.layout.LazyLayoutPinnedItemList;
import androidx.compose.runtime.snapshots.Snapshot;
import androidx.compose.ui.layout.MeasureScope;
import androidx.compose.ui.layout.Placeable;
import androidx.compose.ui.unit.Constraints;
import androidx.compose.ui.unit.ConstraintsKt;
import androidx.compose.ui.unit.IntSizeKt;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.ArrayDeque;
import kotlin.collections.ArraysKt;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Ref;
import kotlin.math.MathKt;
import kotlin.ranges.RangesKt;
/* compiled from: LazyStaggeredGridMeasure.kt */
@Metadata(d1 = {"\u0000\u008c\u0001\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0015\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u000b\u001a\u0017\u0010\u0002\u001a\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00060\u0005H\u0082\b\u001a5\u0010\u0007\u001a\u0002H\b\"\u0004\b\u0000\u0010\b2\u0006\u0010\t\u001a\u00020\n2\u0017\u0010\u000b\u001a\u0013\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u0002H\b0\f¢\u0006\u0002\b\rH\u0083\b¢\u0006\u0002\u0010\u000e\u001aJ\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00110\u0010*\u00020\u00122\u0012\u0010\u0013\u001a\u000e\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u00110\f2!\u0010\u0015\u001a\u001d\u0012\u0013\u0012\u00110\u0016¢\u0006\f\b\u0017\u0012\b\b\u0018\u0012\u0004\b\b(\u0019\u0012\u0004\u0012\u00020\u00010\fH\u0083\b\u001a;\u0010\u001a\u001a\b\u0012\u0004\u0012\u00020\u00110\u0010*\u00020\u00122\u0012\u0010\u001b\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00140\u001d0\u001c2\u0006\u0010\u001e\u001a\u00020\u001f2\u0006\u0010 \u001a\u00020\u0016H\u0002¢\u0006\u0002\u0010!\u001a\u001d\u0010\"\u001a\u00020\u0006*\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00140\u001d0\u001cH\u0002¢\u0006\u0002\u0010#\u001a\u001c\u0010$\u001a\u00020\u0003*\u00020\u00122\u0006\u0010%\u001a\u00020\u001f2\u0006\u0010&\u001a\u00020\u0016H\u0002\u001a\u001c\u0010'\u001a\u00020\u0016*\u00020\u00122\u0006\u0010(\u001a\u00020\u00162\u0006\u0010)\u001a\u00020\u0016H\u0002\u001a.\u0010*\u001a\u00020\u0003*\u00020+2\u0012\u0010\u000b\u001a\u000e\u0012\u0004\u0012\u00020\u0016\u0012\u0004\u0012\u00020\u00030\fH\u0082\bø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b,\u0010-\u001a\f\u0010.\u001a\u00020\u0016*\u00020\u001fH\u0002\u001a2\u0010/\u001a\u00020\u0016\"\u0004\b\u0000\u0010\b*\b\u0012\u0004\u0012\u0002H\b0\u001c2\u0012\u0010\u000b\u001a\u000e\u0012\u0004\u0012\u0002H\b\u0012\u0004\u0012\u00020\u00160\fH\u0082\b¢\u0006\u0002\u00100\u001a\u0016\u00101\u001a\u00020\u0016*\u00020\u001f2\b\b\u0002\u00102\u001a\u00020\u0016H\u0000\u001a!\u00103\u001a\u00020\u0016*\u00020\u001f2\u0006\u00104\u001a\u00020+H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b5\u00106\u001a,\u00107\u001a\u000208*\u00020\u00122\u0006\u00109\u001a\u00020\u00162\u0006\u0010:\u001a\u00020\u001f2\u0006\u0010;\u001a\u00020\u001f2\u0006\u0010<\u001a\u00020\u0001H\u0003\u001ay\u0010=\u001a\u000208*\u00020\n2\u0006\u0010>\u001a\u00020?2\u0006\u0010@\u001a\u00020A2\u0006\u0010B\u001a\u00020\u001f2\u0006\u0010C\u001a\u00020D2\u0006\u0010E\u001a\u00020\u00012\u0006\u0010F\u001a\u00020\u00012\u0006\u0010G\u001a\u00020H2\u0006\u0010I\u001a\u00020\u00162\u0006\u0010J\u001a\u00020\u00162\u0006\u0010K\u001a\u00020\u00162\u0006\u0010L\u001a\u00020\u00162\u0006\u0010M\u001a\u00020\u0016H\u0001ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\bN\u0010O\u001a\u0014\u0010P\u001a\u00020\u0003*\u00020\u001f2\u0006\u0010Q\u001a\u00020\u0016H\u0002\u001a!\u0010R\u001a\u00020\u001f*\u00020\u001f2\u0012\u0010\u000b\u001a\u000e\u0012\u0004\u0012\u00020\u0016\u0012\u0004\u0012\u00020\u00160\fH\u0082\b\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006S"}, d2 = {"DebugLoggingEnabled", "", "debugLog", "", "message", "Lkotlin/Function0;", "", "withDebugLogging", "T", "scope", "Landroidx/compose/foundation/lazy/layout/LazyLayoutMeasureScope;", "block", "Lkotlin/Function1;", "Lkotlin/ExtensionFunctionType;", "(Landroidx/compose/foundation/lazy/layout/LazyLayoutMeasureScope;Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;", "calculateExtraItems", "", "Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridPositionedItem;", "Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridMeasureContext;", "position", "Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridMeasuredItem;", "filter", "", "Lkotlin/ParameterName;", HintConstants.AUTOFILL_HINT_NAME, "itemIndex", "calculatePositionedItems", "measuredItems", "", "Lkotlin/collections/ArrayDeque;", "itemScrollOffsets", "", "mainAxisLayoutSize", "(Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridMeasureContext;[Lkotlin/collections/ArrayDeque;[II)Ljava/util/List;", "debugRender", "([Lkotlin/collections/ArrayDeque;)Ljava/lang/String;", "ensureIndicesInRange", "indices", "itemCount", "findPreviousItemIndex", "item", "lane", "forEach", "Landroidx/compose/foundation/lazy/staggeredgrid/SpanRange;", "forEach-nIS5qE8", "(JLkotlin/jvm/functions/Function1;)V", "indexOfMaxValue", "indexOfMinBy", "([Ljava/lang/Object;Lkotlin/jvm/functions/Function1;)I", "indexOfMinValue", "minBound", "maxInRange", "indexRange", "maxInRange-jy6DScQ", "([IJ)I", "measure", "Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridMeasureResult;", "initialScrollDelta", "initialItemIndices", "initialItemOffsets", "canRestartMeasure", "measureStaggeredGrid", "state", "Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridState;", "itemProvider", "Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridItemProvider;", "resolvedSlotSums", "constraints", "Landroidx/compose/ui/unit/Constraints;", "isVertical", "reverseLayout", "contentOffset", "Landroidx/compose/ui/unit/IntOffset;", "mainAxisAvailableSize", "mainAxisSpacing", "crossAxisSpacing", "beforeContentPadding", "afterContentPadding", "measureStaggeredGrid-BTfHGGE", "(Landroidx/compose/foundation/lazy/layout/LazyLayoutMeasureScope;Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridState;Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridItemProvider;[IJZZJIIIII)Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridMeasureResult;", "offsetBy", "delta", "transform", "foundation_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LazyStaggeredGridMeasureKt {
    private static final boolean DebugLoggingEnabled = false;

    private static final <T> T withDebugLogging(LazyLayoutMeasureScope scope, Function1<? super LazyLayoutMeasureScope, ? extends T> function1) {
        return function1.invoke(scope);
    }

    private static final String debugRender(ArrayDeque<LazyStaggeredGridMeasuredItem>[] arrayDequeArr) {
        return "";
    }

    private static final void debugLog(Function0<String> function0) {
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v25, types: [int[]] */
    /* JADX WARN: Type inference failed for: r0v26, types: [T] */
    /* JADX WARN: Type inference failed for: r0v31 */
    /* JADX WARN: Type inference failed for: r12v10 */
    /* JADX WARN: Type inference failed for: r12v5, types: [T] */
    /* JADX WARN: Type inference failed for: r12v9 */
    /* JADX WARN: Type inference failed for: r15v4 */
    /* JADX WARN: Type inference failed for: r15v5 */
    /* JADX WARN: Type inference failed for: r15v6 */
    /* JADX WARN: Type inference failed for: r16v0, types: [int] */
    /* JADX WARN: Type inference failed for: r16v1 */
    /* JADX WARN: Type inference failed for: r16v2, types: [androidx.compose.runtime.snapshots.Snapshot] */
    /* renamed from: measureStaggeredGrid-BTfHGGE  reason: not valid java name */
    public static final LazyStaggeredGridMeasureResult m636measureStaggeredGridBTfHGGE(LazyLayoutMeasureScope measureStaggeredGrid, LazyStaggeredGridState state, LazyStaggeredGridItemProvider itemProvider, int[] resolvedSlotSums, long constraints, boolean isVertical, boolean reverseLayout, long contentOffset, int mainAxisAvailableSize, int mainAxisSpacing, int crossAxisSpacing, int beforeContentPadding, int afterContentPadding) {
        Snapshot snapshot$iv;
        boolean z;
        boolean z2;
        int i;
        Snapshot snapshot$iv2;
        ?? r12;
        ?? r0;
        ?? r16 = crossAxisSpacing;
        Intrinsics.checkNotNullParameter(measureStaggeredGrid, "$this$measureStaggeredGrid");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(itemProvider, "itemProvider");
        Intrinsics.checkNotNullParameter(resolvedSlotSums, "resolvedSlotSums");
        LazyStaggeredGridMeasureContext context = new LazyStaggeredGridMeasureContext(state, itemProvider, resolvedSlotSums, constraints, isVertical, measureStaggeredGrid, mainAxisAvailableSize, contentOffset, beforeContentPadding, afterContentPadding, reverseLayout, mainAxisSpacing, r16, null);
        Ref.ObjectRef initialItemIndices = new Ref.ObjectRef();
        Ref.ObjectRef initialItemOffsets = new Ref.ObjectRef();
        Snapshot.Companion this_$iv = Snapshot.Companion;
        boolean z3 = false;
        Snapshot snapshot$iv3 = this_$iv.createNonObservableSnapshot();
        try {
            Snapshot previous$iv$iv = snapshot$iv3.makeCurrent();
            try {
                try {
                    int[] firstVisibleIndices = state.getScrollPosition$foundation_release().getIndices();
                    int[] firstVisibleOffsets = state.getScrollPosition$foundation_release().getOffsets();
                    try {
                        if (firstVisibleIndices.length == resolvedSlotSums.length) {
                            snapshot$iv = snapshot$iv3;
                            r12 = firstVisibleIndices;
                            z = false;
                        } else {
                            context.getLaneInfo().reset();
                            int[] $this$measureStaggeredGrid_BTfHGGE_u24lambda_u244_u24lambda_u242 = new int[resolvedSlotSums.length];
                            int length = $this$measureStaggeredGrid_BTfHGGE_u24lambda_u244_u24lambda_u242.length;
                            int lane = 0;
                            while (lane < length) {
                                Snapshot.Companion this_$iv2 = this_$iv;
                                try {
                                    if (lane < firstVisibleIndices.length) {
                                        try {
                                            z2 = z3;
                                            if (firstVisibleIndices[lane] != -1) {
                                                try {
                                                    i = firstVisibleIndices[lane];
                                                    snapshot$iv2 = snapshot$iv3;
                                                    $this$measureStaggeredGrid_BTfHGGE_u24lambda_u244_u24lambda_u242[lane] = i;
                                                    context.getLaneInfo().setLane($this$measureStaggeredGrid_BTfHGGE_u24lambda_u244_u24lambda_u242[lane], lane);
                                                    lane++;
                                                    snapshot$iv3 = snapshot$iv2;
                                                    this_$iv = this_$iv2;
                                                    z3 = z2;
                                                } catch (Throwable th) {
                                                    th = th;
                                                    snapshot$iv3.restoreCurrent(previous$iv$iv);
                                                    throw th;
                                                }
                                            }
                                        } catch (Throwable th2) {
                                            th = th2;
                                        }
                                    } else {
                                        z2 = z3;
                                    }
                                    if (lane == 0) {
                                        snapshot$iv2 = snapshot$iv3;
                                        i = 0;
                                    } else {
                                        snapshot$iv2 = snapshot$iv3;
                                        try {
                                            i = m635maxInRangejy6DScQ($this$measureStaggeredGrid_BTfHGGE_u24lambda_u244_u24lambda_u242, SpanRange.m643constructorimpl(0, lane)) + 1;
                                        } catch (Throwable th3) {
                                            th = th3;
                                            snapshot$iv3.restoreCurrent(previous$iv$iv);
                                            throw th;
                                        }
                                    }
                                    $this$measureStaggeredGrid_BTfHGGE_u24lambda_u244_u24lambda_u242[lane] = i;
                                    context.getLaneInfo().setLane($this$measureStaggeredGrid_BTfHGGE_u24lambda_u244_u24lambda_u242[lane], lane);
                                    lane++;
                                    snapshot$iv3 = snapshot$iv2;
                                    this_$iv = this_$iv2;
                                    z3 = z2;
                                } catch (Throwable th4) {
                                    th = th4;
                                }
                            }
                            snapshot$iv = snapshot$iv3;
                            z = false;
                            r12 = $this$measureStaggeredGrid_BTfHGGE_u24lambda_u244_u24lambda_u242;
                        }
                        initialItemIndices.element = r12;
                        if (firstVisibleOffsets.length == resolvedSlotSums.length) {
                            r0 = firstVisibleOffsets;
                        } else {
                            r0 = new int[resolvedSlotSums.length];
                            int lane2 = 0;
                            int length2 = r0.length;
                            while (lane2 < length2) {
                                r0[lane2] = lane2 < firstVisibleOffsets.length ? firstVisibleOffsets[lane2] : lane2 == 0 ? z : r0[lane2 - 1];
                                lane2++;
                            }
                        }
                        initialItemOffsets.element = r0;
                        Unit unit = Unit.INSTANCE;
                        snapshot$iv3.restoreCurrent(previous$iv$iv);
                        snapshot$iv.dispose();
                        return measure(context, MathKt.roundToInt(state.getScrollToBeConsumed$foundation_release()), (int[]) initialItemIndices.element, (int[]) initialItemOffsets.element, true);
                    } catch (Throwable th5) {
                        th = th5;
                        snapshot$iv3.restoreCurrent(previous$iv$iv);
                        throw th;
                    }
                } catch (Throwable th6) {
                    th = th6;
                    r16.dispose();
                    throw th;
                }
            } catch (Throwable th7) {
                th = th7;
            }
        } catch (Throwable th8) {
            th = th8;
            r16 = snapshot$iv3;
        }
    }

    private static final LazyStaggeredGridMeasureResult measure(final LazyStaggeredGridMeasureContext $this$measure, int initialScrollDelta, int[] initialItemIndices, int[] initialItemOffsets, boolean canRestartMeasure) {
        int itemCount;
        int itemCount2;
        boolean z;
        int itemCount3;
        int[] gaps;
        boolean z2;
        boolean z3;
        int[] currentItemOffsets;
        int maxOffset;
        int[] firstItemIndices;
        int itemCount4;
        int[] currentItemIndices;
        LazyStaggeredGridMeasureContext lazyStaggeredGridMeasureContext;
        int toScrollBack;
        boolean z4;
        boolean canScrollForward;
        boolean z5;
        List extraItemsBefore;
        ArrayDeque[] measuredItems;
        boolean z6;
        int layoutHeight;
        List $this$fastForEach$iv$iv;
        int layoutWidth;
        boolean z7;
        int scrollDelta;
        int maxOffsetLane;
        boolean gapDetected;
        int maxOffsetLane2;
        int[] currentItemOffsets2;
        int scrollDelta2;
        boolean gapDetected2;
        boolean gapDetected3;
        int initialLaneToMeasure;
        boolean z8;
        int scrollDelta3;
        int minOffset;
        int[] firstItemIndices2;
        String str;
        int laneToCheckForGaps;
        int initialLaneToMeasure2;
        int initialItemsMeasured;
        LazyStaggeredGridMeasureContext lazyStaggeredGridMeasureContext2 = $this$measure;
        LazyLayoutMeasureScope scope$iv = $this$measure.getMeasureScope();
        int itemCount5 = $this$measure.getItemProvider().getItemCount();
        if (itemCount5 <= 0) {
            itemCount = itemCount5;
        } else if ($this$measure.getLaneCount() != 0) {
            int scrollDelta4 = initialScrollDelta;
            int[] firstItemIndices3 = Arrays.copyOf(initialItemIndices, initialItemIndices.length);
            String str2 = "copyOf(this, size)";
            Intrinsics.checkNotNullExpressionValue(firstItemIndices3, "copyOf(this, size)");
            int[] firstItemOffsets = Arrays.copyOf(initialItemOffsets, initialItemOffsets.length);
            Intrinsics.checkNotNullExpressionValue(firstItemOffsets, "copyOf(this, size)");
            ensureIndicesInRange(lazyStaggeredGridMeasureContext2, firstItemIndices3, itemCount5);
            offsetBy(firstItemOffsets, -scrollDelta4);
            int laneCount = $this$measure.getLaneCount();
            ArrayDeque[] arrayDequeArr = new ArrayDeque[laneCount];
            for (int i = 0; i < laneCount; i++) {
                arrayDequeArr[i] = new ArrayDeque(16);
            }
            ArrayDeque[] measuredItems2 = arrayDequeArr;
            offsetBy(firstItemOffsets, -$this$measure.getBeforeContentPadding());
            int laneToCheckForGaps2 = -1;
            while (true) {
                if (!measure$lambda$37$hasSpaceBeforeFirst(firstItemIndices3, firstItemOffsets, lazyStaggeredGridMeasureContext2)) {
                    itemCount2 = itemCount5;
                    break;
                }
                int laneIndex = indexOfMaxValue(firstItemIndices3);
                int itemIndex = firstItemIndices3[laneIndex];
                int length = firstItemOffsets.length;
                for (int i2 = 0; i2 < length; i2++) {
                    if (firstItemIndices3[i2] != firstItemIndices3[laneIndex] && firstItemOffsets[i2] < firstItemOffsets[laneIndex]) {
                        firstItemOffsets[i2] = firstItemOffsets[laneIndex];
                    }
                }
                int previousItemIndex = findPreviousItemIndex(lazyStaggeredGridMeasureContext2, itemIndex, laneIndex);
                if (previousItemIndex < 0) {
                    laneToCheckForGaps2 = laneIndex;
                    itemCount2 = itemCount5;
                    break;
                }
                long spanRange = lazyStaggeredGridMeasureContext2.m632getSpanRangelOCCd4c($this$measure.getItemProvider(), previousItemIndex, laneIndex);
                int laneToCheckForGaps3 = laneToCheckForGaps2;
                int itemCount6 = itemCount5;
                $this$measure.getLaneInfo().setLane(previousItemIndex, ((int) (spanRange & 4294967295L)) - ((int) (spanRange >> 32)) != 1 ? -2 : (int) (spanRange >> 32));
                LazyStaggeredGridMeasuredItem measuredItem = $this$measure.getMeasuredItemProvider().m640getAndMeasurejy6DScQ(previousItemIndex, spanRange);
                int offset = m635maxInRangejy6DScQ(firstItemOffsets, spanRange);
                long $this$isFullSpan$iv = spanRange >> 32;
                int[] gaps2 = ((int) (spanRange & 4294967295L)) - ((int) $this$isFullSpan$iv) != 1 ? $this$measure.getLaneInfo().getGaps(previousItemIndex) : null;
                long $this$forEach_u2dnIS5qE8$iv = spanRange & 4294967295L;
                int i3 = (int) $this$forEach_u2dnIS5qE8$iv;
                for (int i$iv = (int) (spanRange >> 32); i$iv < i3; i$iv++) {
                    int lane = i$iv;
                    firstItemIndices3[lane] = previousItemIndex;
                    int gap = gaps2 == null ? 0 : gaps2[lane];
                    firstItemOffsets[lane] = offset + measuredItem.getSizeWithSpacings() + gap;
                }
                laneToCheckForGaps2 = laneToCheckForGaps3;
                itemCount5 = itemCount6;
            }
            int $i$f$debugLog = $this$measure.getBeforeContentPadding();
            int minOffset2 = -$i$f$debugLog;
            if (firstItemOffsets[0] < minOffset2) {
                scrollDelta4 += firstItemOffsets[0];
                offsetBy(firstItemOffsets, minOffset2 - firstItemOffsets[0]);
            }
            int $i$f$debugLog2 = $this$measure.getBeforeContentPadding();
            offsetBy(firstItemOffsets, $i$f$debugLog2);
            int i4 = -1;
            int laneToCheckForGaps4 = laneToCheckForGaps2 == -1 ? ArraysKt.indexOf(firstItemIndices3, 0) : laneToCheckForGaps2;
            if (laneToCheckForGaps4 != -1 && measure$lambda$37$misalignedStart(firstItemIndices3, lazyStaggeredGridMeasureContext2, firstItemOffsets, laneToCheckForGaps4) && canRestartMeasure) {
                $this$measure.getLaneInfo().reset();
                int length2 = firstItemIndices3.length;
                int[] iArr = new int[length2];
                for (int i5 = 0; i5 < length2; i5++) {
                    iArr[i5] = -1;
                }
                int length3 = firstItemOffsets.length;
                int[] iArr2 = new int[length3];
                for (int i6 = 0; i6 < length3; i6++) {
                    iArr2[i6] = firstItemOffsets[laneToCheckForGaps4];
                }
                return measure(lazyStaggeredGridMeasureContext2, scrollDelta4, iArr, iArr2, false);
            }
            int[] currentItemIndices2 = Arrays.copyOf(firstItemIndices3, firstItemIndices3.length);
            Intrinsics.checkNotNullExpressionValue(currentItemIndices2, "copyOf(this, size)");
            int length4 = firstItemOffsets.length;
            int[] iArr3 = new int[length4];
            for (int i7 = 0; i7 < length4; i7++) {
                iArr3[i7] = -firstItemOffsets[i7];
            }
            int[] currentItemOffsets3 = iArr3;
            int maxOffset2 = RangesKt.coerceAtLeast($this$measure.getMainAxisAvailableSize() + $this$measure.getAfterContentPadding(), 0);
            int initialItemsMeasured2 = 0;
            int initialLaneToMeasure3 = indexOfMinValue$default(currentItemIndices2, 0, 1, null);
            while (initialLaneToMeasure3 != i4 && initialItemsMeasured2 < $this$measure.getLaneCount()) {
                int itemIndex2 = currentItemIndices2[initialLaneToMeasure3];
                int laneIndex2 = initialLaneToMeasure3;
                int initialLaneToMeasure4 = indexOfMinValue(currentItemIndices2, itemIndex2);
                int initialItemsMeasured3 = initialItemsMeasured2 + 1;
                if (itemIndex2 >= 0) {
                    initialLaneToMeasure2 = initialLaneToMeasure4;
                    initialItemsMeasured = initialItemsMeasured3;
                    long spanRange2 = lazyStaggeredGridMeasureContext2.m632getSpanRangelOCCd4c($this$measure.getItemProvider(), itemIndex2, laneIndex2);
                    LazyStaggeredGridMeasuredItem measuredItem2 = $this$measure.getMeasuredItemProvider().m640getAndMeasurejy6DScQ(itemIndex2, spanRange2);
                    laneToCheckForGaps = laneToCheckForGaps4;
                    scrollDelta3 = scrollDelta4;
                    firstItemIndices2 = firstItemIndices3;
                    str = str2;
                    $this$measure.getLaneInfo().setLane(itemIndex2, ((int) (spanRange2 & 4294967295L)) - ((int) (spanRange2 >> 32)) != 1 ? -2 : (int) (spanRange2 >> 32));
                    int offset2 = m635maxInRangejy6DScQ(currentItemOffsets3, spanRange2) + measuredItem2.getSizeWithSpacings();
                    minOffset = minOffset2;
                    int i$iv2 = (int) (spanRange2 >> 32);
                    int i8 = (int) (spanRange2 & 4294967295L);
                    int i$iv3 = i$iv2;
                    while (i$iv3 < i8) {
                        int lane2 = i$iv3;
                        currentItemOffsets3[lane2] = offset2;
                        currentItemIndices2[lane2] = itemIndex2;
                        measuredItems2[lane2].addLast(measuredItem2);
                        i$iv3++;
                        offset2 = offset2;
                    }
                    if (currentItemOffsets3[(int) (spanRange2 >> 32)] <= minOffset + $this$measure.getMainAxisSpacing()) {
                        measuredItem2.setVisible(false);
                    }
                    long $this$isFullSpan$iv2 = spanRange2 >> 32;
                    if (((int) (spanRange2 & 4294967295L)) - ((int) $this$isFullSpan$iv2) != 1) {
                        initialItemsMeasured2 = $this$measure.getLaneCount();
                        lazyStaggeredGridMeasureContext2 = $this$measure;
                        initialLaneToMeasure3 = initialLaneToMeasure2;
                        laneToCheckForGaps4 = laneToCheckForGaps;
                        minOffset2 = minOffset;
                        firstItemIndices3 = firstItemIndices2;
                        scrollDelta4 = scrollDelta3;
                        str2 = str;
                        i4 = -1;
                    }
                } else {
                    scrollDelta3 = scrollDelta4;
                    minOffset = minOffset2;
                    firstItemIndices2 = firstItemIndices3;
                    str = str2;
                    laneToCheckForGaps = laneToCheckForGaps4;
                    initialLaneToMeasure2 = initialLaneToMeasure4;
                    initialItemsMeasured = initialItemsMeasured3;
                }
                lazyStaggeredGridMeasureContext2 = $this$measure;
                initialLaneToMeasure3 = initialLaneToMeasure2;
                initialItemsMeasured2 = initialItemsMeasured;
                laneToCheckForGaps4 = laneToCheckForGaps;
                minOffset2 = minOffset;
                firstItemIndices3 = firstItemIndices2;
                scrollDelta4 = scrollDelta3;
                str2 = str;
                i4 = -1;
            }
            int scrollDelta5 = scrollDelta4;
            int minOffset3 = minOffset2;
            int[] firstItemIndices4 = firstItemIndices3;
            String str3 = str2;
            while (true) {
                int[] $this$any$iv = currentItemOffsets3;
                int length5 = $this$any$iv.length;
                int i9 = 0;
                while (true) {
                    if (i9 >= length5) {
                        z = false;
                        break;
                    }
                    int element$iv = $this$any$iv[i9];
                    if (element$iv < maxOffset2 || element$iv <= 0) {
                        z = true;
                        break;
                    }
                    i9++;
                }
                if (!z) {
                    ArrayDeque[] arrayDequeArr2 = measuredItems2;
                    int length6 = arrayDequeArr2.length;
                    int i10 = 0;
                    while (true) {
                        if (i10 >= length6) {
                            z8 = true;
                            break;
                        } else if (!arrayDequeArr2[i10].isEmpty()) {
                            z8 = false;
                            break;
                        } else {
                            i10++;
                        }
                    }
                    if (!z8) {
                        itemCount3 = itemCount2;
                        break;
                    }
                }
                int currentLaneIndex = indexOfMinValue$default(currentItemOffsets3, 0, 1, null);
                int previousItemIndex2 = ArraysKt.maxOrThrow(currentItemIndices2);
                int itemIndex3 = previousItemIndex2 + 1;
                itemCount3 = itemCount2;
                if (itemIndex3 >= itemCount3) {
                    break;
                }
                int[] currentItemOffsets4 = currentItemOffsets3;
                int maxOffset3 = maxOffset2;
                int initialLaneToMeasure5 = initialLaneToMeasure3;
                int[] firstItemIndices5 = firstItemIndices4;
                int scrollDelta6 = scrollDelta5;
                ArrayDeque[] measuredItems3 = measuredItems2;
                int[] currentItemIndices3 = currentItemIndices2;
                String str4 = str3;
                int initialItemsMeasured4 = initialItemsMeasured2;
                long spanRange3 = $this$measure.m632getSpanRangelOCCd4c($this$measure.getItemProvider(), itemIndex3, currentLaneIndex);
                int[] firstItemOffsets2 = firstItemOffsets;
                $this$measure.getLaneInfo().setLane(itemIndex3, ((int) (spanRange3 & 4294967295L)) - ((int) (spanRange3 >> 32)) != 1 ? -2 : (int) (spanRange3 >> 32));
                LazyStaggeredGridMeasuredItem measuredItem3 = $this$measure.getMeasuredItemProvider().m640getAndMeasurejy6DScQ(itemIndex3, spanRange3);
                int offset3 = m635maxInRangejy6DScQ(currentItemOffsets4, spanRange3);
                if (((int) (spanRange3 & 4294967295L)) - ((int) (spanRange3 >> 32)) != 1) {
                    gaps = $this$measure.getLaneInfo().getGaps(itemIndex3);
                    if (gaps == null) {
                        gaps = new int[$this$measure.getLaneCount()];
                    }
                } else {
                    gaps = null;
                }
                int[] gaps3 = gaps;
                int i$iv4 = (int) (spanRange3 >> 32);
                int i11 = (int) (spanRange3 & 4294967295L);
                int i$iv5 = i$iv4;
                while (i$iv5 < i11) {
                    int lane3 = i$iv5;
                    if (gaps3 != null) {
                        gaps3[lane3] = offset3 - currentItemOffsets4[lane3];
                    }
                    currentItemIndices3[lane3] = itemIndex3;
                    currentItemOffsets4[lane3] = offset3 + measuredItem3.getSizeWithSpacings();
                    measuredItems3[lane3].addLast(measuredItem3);
                    i$iv5++;
                    previousItemIndex2 = previousItemIndex2;
                }
                $this$measure.getLaneInfo().setGaps(itemIndex3, gaps3);
                if (currentItemOffsets4[(int) (spanRange3 >> 32)] <= minOffset3 + $this$measure.getMainAxisSpacing()) {
                    measuredItem3.setVisible(false);
                    currentItemOffsets3 = currentItemOffsets4;
                    firstItemOffsets = firstItemOffsets2;
                    initialLaneToMeasure3 = initialLaneToMeasure5;
                    measuredItems2 = measuredItems3;
                    initialItemsMeasured2 = initialItemsMeasured4;
                    maxOffset2 = maxOffset3;
                    str3 = str4;
                    firstItemIndices4 = firstItemIndices5;
                    itemCount2 = itemCount3;
                    currentItemIndices2 = currentItemIndices3;
                    scrollDelta5 = scrollDelta6;
                } else {
                    currentItemOffsets3 = currentItemOffsets4;
                    firstItemOffsets = firstItemOffsets2;
                    initialLaneToMeasure3 = initialLaneToMeasure5;
                    measuredItems2 = measuredItems3;
                    initialItemsMeasured2 = initialItemsMeasured4;
                    maxOffset2 = maxOffset3;
                    str3 = str4;
                    firstItemIndices4 = firstItemIndices5;
                    itemCount2 = itemCount3;
                    currentItemIndices2 = currentItemIndices3;
                    scrollDelta5 = scrollDelta6;
                }
            }
            int length7 = measuredItems2.length;
            for (int laneIndex3 = 0; laneIndex3 < length7; laneIndex3++) {
                ArrayDeque laneItems = measuredItems2[laneIndex3];
                while (laneItems.size() > 1 && !((LazyStaggeredGridMeasuredItem) laneItems.first()).isVisible()) {
                    LazyStaggeredGridMeasuredItem item = (LazyStaggeredGridMeasuredItem) laneItems.removeFirst();
                    int[] gaps4 = item.getSpan() != 1 ? $this$measure.getLaneInfo().getGaps(item.getIndex()) : null;
                    firstItemOffsets[laneIndex3] = firstItemOffsets[laneIndex3] - (item.getSizeWithSpacings() + (gaps4 == null ? 0 : gaps4[laneIndex3]));
                }
                LazyStaggeredGridMeasuredItem lazyStaggeredGridMeasuredItem = (LazyStaggeredGridMeasuredItem) laneItems.firstOrNull();
                firstItemIndices4[laneIndex3] = lazyStaggeredGridMeasuredItem != null ? lazyStaggeredGridMeasuredItem.getIndex() : -1;
            }
            int[] $this$any$iv2 = currentItemIndices2;
            int length8 = $this$any$iv2.length;
            int i12 = 0;
            while (true) {
                if (i12 >= length8) {
                    z2 = false;
                    break;
                }
                int element$iv2 = $this$any$iv2[i12];
                int it = element$iv2 == itemCount3 + (-1) ? 1 : 0;
                if (it != 0) {
                    z2 = true;
                    break;
                }
                i12++;
            }
            if (z2) {
                offsetBy(currentItemOffsets3, -$this$measure.getMainAxisSpacing());
            }
            int[] $this$all$iv = currentItemOffsets3;
            int length9 = $this$all$iv.length;
            int i13 = 0;
            while (true) {
                if (i13 >= length9) {
                    z3 = true;
                    break;
                }
                int element$iv3 = $this$all$iv[i13];
                int it2 = element$iv3 < $this$measure.getMainAxisAvailableSize() ? 1 : 0;
                if (it2 == 0) {
                    z3 = false;
                    break;
                }
                i13++;
            }
            if (z3) {
                int maxOffsetLane3 = indexOfMaxValue(currentItemOffsets3);
                int toScrollBack2 = $this$measure.getMainAxisAvailableSize() - currentItemOffsets3[maxOffsetLane3];
                offsetBy(firstItemOffsets, -toScrollBack2);
                offsetBy(currentItemOffsets3, toScrollBack2);
                boolean gapDetected4 = false;
                while (true) {
                    int[] $this$any$iv3 = firstItemOffsets;
                    int length10 = $this$any$iv3.length;
                    int i14 = 0;
                    while (true) {
                        if (i14 >= length10) {
                            maxOffsetLane = maxOffsetLane3;
                            gapDetected = gapDetected4;
                            maxOffsetLane2 = 0;
                            break;
                        }
                        int element$iv4 = $this$any$iv3[i14];
                        maxOffsetLane = maxOffsetLane3;
                        gapDetected = gapDetected4;
                        if (element$iv4 < $this$measure.getBeforeContentPadding()) {
                            maxOffsetLane2 = 1;
                            break;
                        }
                        i14++;
                        maxOffsetLane3 = maxOffsetLane;
                        gapDetected4 = gapDetected;
                    }
                    if (maxOffsetLane2 == 0) {
                        currentItemOffsets2 = currentItemOffsets3;
                        maxOffset = maxOffset2;
                        firstItemIndices = firstItemIndices4;
                        scrollDelta2 = scrollDelta5;
                        itemCount4 = itemCount3;
                        currentItemIndices = currentItemIndices2;
                        gapDetected2 = gapDetected;
                        break;
                    }
                    int laneIndex4 = indexOfMinValue$default(firstItemOffsets, 0, 1, null);
                    boolean gapDetected5 = laneIndex4 != indexOfMaxValue(firstItemIndices4) ? true : gapDetected;
                    int currentIndex = firstItemIndices4[laneIndex4] == -1 ? itemCount3 : firstItemIndices4[laneIndex4];
                    int previousIndex = findPreviousItemIndex($this$measure, currentIndex, laneIndex4);
                    if (previousIndex < 0) {
                        if (gapDetected5) {
                            firstItemIndices = firstItemIndices4;
                        } else {
                            firstItemIndices = firstItemIndices4;
                            if (!measure$lambda$37$misalignedStart(firstItemIndices, $this$measure, firstItemOffsets, laneIndex4)) {
                                gapDetected3 = gapDetected5;
                                initialLaneToMeasure = scrollDelta5;
                                itemCount4 = itemCount3;
                                currentItemIndices = currentItemIndices2;
                                currentItemOffsets2 = currentItemOffsets3;
                                maxOffset = maxOffset2;
                                scrollDelta2 = initialLaneToMeasure;
                                gapDetected2 = gapDetected3;
                            }
                        }
                        if (canRestartMeasure) {
                            $this$measure.getLaneInfo().reset();
                            int length11 = firstItemIndices.length;
                            int[] iArr4 = new int[length11];
                            for (int i15 = 0; i15 < length11; i15++) {
                                iArr4[i15] = -1;
                            }
                            int length12 = firstItemOffsets.length;
                            int[] iArr5 = new int[length12];
                            for (int initialLaneToMeasure6 = 0; initialLaneToMeasure6 < length12; initialLaneToMeasure6++) {
                                iArr5[initialLaneToMeasure6] = firstItemOffsets[laneIndex4];
                            }
                            return measure($this$measure, scrollDelta5, iArr4, iArr5, false);
                        }
                        gapDetected3 = gapDetected5;
                        initialLaneToMeasure = scrollDelta5;
                        itemCount4 = itemCount3;
                        currentItemIndices = currentItemIndices2;
                        currentItemOffsets2 = currentItemOffsets3;
                        maxOffset = maxOffset2;
                        scrollDelta2 = initialLaneToMeasure;
                        gapDetected2 = gapDetected3;
                    } else {
                        boolean gapDetected6 = gapDetected5;
                        int initialLaneToMeasure7 = initialLaneToMeasure3;
                        int[] firstItemIndices6 = firstItemIndices4;
                        int initialLaneToMeasure8 = scrollDelta5;
                        int itemCount7 = itemCount3;
                        long spanRange4 = $this$measure.m632getSpanRangelOCCd4c($this$measure.getItemProvider(), previousIndex, laneIndex4);
                        int[] currentItemIndices4 = currentItemIndices2;
                        int[] currentItemOffsets5 = currentItemOffsets3;
                        int maxOffset4 = maxOffset2;
                        $this$measure.getLaneInfo().setLane(previousIndex, ((int) (spanRange4 & 4294967295L)) - ((int) (spanRange4 >> 32)) != 1 ? -2 : (int) (spanRange4 >> 32));
                        LazyStaggeredGridMeasuredItem measuredItem4 = $this$measure.getMeasuredItemProvider().m640getAndMeasurejy6DScQ(previousIndex, spanRange4);
                        int offset4 = m635maxInRangejy6DScQ(firstItemOffsets, spanRange4);
                        long $this$isFullSpan$iv3 = spanRange4 >> 32;
                        int[] gaps5 = ((int) (spanRange4 & 4294967295L)) - ((int) $this$isFullSpan$iv3) != 1 ? $this$measure.getLaneInfo().getGaps(previousIndex) : null;
                        int i$iv6 = (int) (spanRange4 >> 32);
                        int i$iv7 = i$iv6;
                        int i16 = (int) (spanRange4 & 4294967295L);
                        gapDetected4 = gapDetected6;
                        while (i$iv7 < i16) {
                            int lane4 = i$iv7;
                            int i17 = i16;
                            if (firstItemOffsets[lane4] != offset4) {
                                gapDetected4 = true;
                            }
                            measuredItems2[lane4].addFirst(measuredItem4);
                            firstItemIndices6[lane4] = previousIndex;
                            int gap2 = gaps5 == null ? 0 : gaps5[lane4];
                            firstItemOffsets[lane4] = offset4 + measuredItem4.getSizeWithSpacings() + gap2;
                            i$iv7++;
                            i16 = i17;
                        }
                        maxOffsetLane3 = maxOffsetLane;
                        initialLaneToMeasure3 = initialLaneToMeasure7;
                        itemCount3 = itemCount7;
                        currentItemIndices2 = currentItemIndices4;
                        maxOffset2 = maxOffset4;
                        currentItemOffsets3 = currentItemOffsets5;
                        firstItemIndices4 = firstItemIndices6;
                        scrollDelta5 = initialLaneToMeasure8;
                    }
                }
                if (gapDetected2 && canRestartMeasure) {
                    $this$measure.getLaneInfo().reset();
                    return measure($this$measure, scrollDelta2, firstItemIndices, firstItemOffsets, false);
                }
                lazyStaggeredGridMeasureContext = $this$measure;
                int scrollDelta7 = scrollDelta2 + toScrollBack2;
                int minOffsetLane = indexOfMinValue$default(firstItemOffsets, 0, 1, null);
                if (firstItemOffsets[minOffsetLane] < 0) {
                    int offsetValue = firstItemOffsets[minOffsetLane];
                    currentItemOffsets = currentItemOffsets2;
                    offsetBy(currentItemOffsets, offsetValue);
                    offsetBy(firstItemOffsets, -offsetValue);
                    toScrollBack = scrollDelta7 + offsetValue;
                } else {
                    currentItemOffsets = currentItemOffsets2;
                    toScrollBack = scrollDelta7;
                }
            } else {
                currentItemOffsets = currentItemOffsets3;
                maxOffset = maxOffset2;
                firstItemIndices = firstItemIndices4;
                int scrollDelta8 = scrollDelta5;
                itemCount4 = itemCount3;
                currentItemIndices = currentItemIndices2;
                lazyStaggeredGridMeasureContext = $this$measure;
                toScrollBack = scrollDelta8;
            }
            float consumedScroll = (MathKt.getSign(MathKt.roundToInt($this$measure.getState().getScrollToBeConsumed$foundation_release())) != MathKt.getSign(toScrollBack) || Math.abs(MathKt.roundToInt($this$measure.getState().getScrollToBeConsumed$foundation_release())) < Math.abs(toScrollBack)) ? $this$measure.getState().getScrollToBeConsumed$foundation_release() : toScrollBack;
            int[] $this$transform$iv = Arrays.copyOf(firstItemOffsets, firstItemOffsets.length);
            Intrinsics.checkNotNullExpressionValue($this$transform$iv, str3);
            int length13 = $this$transform$iv.length;
            for (int i$iv8 = 0; i$iv8 < length13; i$iv8++) {
                int it3 = $this$transform$iv[i$iv8];
                $this$transform$iv[i$iv8] = -it3;
            }
            int $i$f$debugLog3 = $this$measure.getBeforeContentPadding();
            if ($i$f$debugLog3 > 0) {
                int laneIndex5 = 0;
                int length14 = measuredItems2.length;
                while (laneIndex5 < length14) {
                    ArrayDeque laneItems2 = measuredItems2[laneIndex5];
                    int i18 = 0;
                    int size = laneItems2.size();
                    while (true) {
                        if (i18 >= size) {
                            scrollDelta = toScrollBack;
                            break;
                        }
                        LazyStaggeredGridMeasuredItem item2 = (LazyStaggeredGridMeasuredItem) laneItems2.get(i18);
                        int[] gaps6 = $this$measure.getLaneInfo().getGaps(item2.getIndex());
                        int size2 = item2.getSizeWithSpacings() + (gaps6 == null ? 0 : gaps6[laneIndex5]);
                        scrollDelta = toScrollBack;
                        if (i18 != CollectionsKt.getLastIndex(laneItems2) && firstItemOffsets[laneIndex5] != 0 && firstItemOffsets[laneIndex5] >= size2) {
                            firstItemOffsets[laneIndex5] = firstItemOffsets[laneIndex5] - size2;
                            firstItemIndices[laneIndex5] = ((LazyStaggeredGridMeasuredItem) laneItems2.get(i18 + 1)).getIndex();
                            i18++;
                            toScrollBack = scrollDelta;
                        }
                    }
                    laneIndex5++;
                    toScrollBack = scrollDelta;
                }
            }
            int layoutWidth2 = $this$measure.isVertical() ? Constraints.m5078getMaxWidthimpl($this$measure.m629getConstraintsmsEJaDk()) : ConstraintsKt.m5092constrainWidthK40F9xA($this$measure.m629getConstraintsmsEJaDk(), ArraysKt.maxOrThrow(currentItemOffsets));
            int layoutHeight2 = $this$measure.isVertical() ? ConstraintsKt.m5091constrainHeightK40F9xA($this$measure.m629getConstraintsmsEJaDk(), ArraysKt.maxOrThrow(currentItemOffsets)) : Constraints.m5077getMaxHeightimpl($this$measure.m629getConstraintsmsEJaDk());
            int mainAxisLayoutSize = Math.min($this$measure.isVertical() ? layoutHeight2 : layoutWidth2, $this$measure.getMainAxisAvailableSize());
            int extraItemOffset = $this$transform$iv[0];
            List list = null;
            LazyLayoutPinnedItemList pinnedItems$iv = $this$measure.getState().getPinnedItems$foundation_release();
            LazyLayoutPinnedItemList $this$fastForEach$iv$iv2 = pinnedItems$iv;
            int extraItemOffset2 = extraItemOffset;
            int extraItemOffset3 = $this$fastForEach$iv$iv2.size();
            int $i$f$calculateExtraItems = 0;
            while ($i$f$calculateExtraItems < extraItemOffset3) {
                Object item$iv$iv = $this$fastForEach$iv$iv2.get($i$f$calculateExtraItems);
                LazyLayoutPinnedItemList.PinnedItem item$iv = (LazyLayoutPinnedItemList.PinnedItem) item$iv$iv;
                int i19 = extraItemOffset3;
                LazyStaggeredGridItemProvider itemProvider = $this$measure.getItemProvider();
                LazyLayoutPinnedItemList pinnedItems$iv2 = pinnedItems$iv;
                Object key = item$iv.getKey();
                int initialItemsMeasured5 = initialItemsMeasured2;
                int initialItemsMeasured6 = item$iv.getIndex();
                int index$iv = LazyLayoutItemProviderKt.findIndexByKey(itemProvider, key, initialItemsMeasured6);
                int lane5 = $this$measure.getLaneInfo().getLane(index$iv);
                switch (lane5) {
                    case -2:
                    case -1:
                        int[] $this$all$iv2 = firstItemIndices;
                        layoutHeight = layoutHeight2;
                        $this$fastForEach$iv$iv = $this$fastForEach$iv$iv2;
                        int layoutHeight3 = $this$all$iv2.length;
                        layoutWidth = layoutWidth2;
                        int layoutWidth3 = 0;
                        while (true) {
                            if (layoutWidth3 >= layoutHeight3) {
                                z7 = true;
                                break;
                            } else {
                                int element$iv5 = $this$all$iv2[layoutWidth3];
                                int i20 = layoutHeight3;
                                int it4 = element$iv5 > index$iv ? 1 : 0;
                                if (it4 == 0) {
                                    z7 = false;
                                    break;
                                } else {
                                    layoutWidth3++;
                                    layoutHeight3 = i20;
                                }
                            }
                        }
                    default:
                        layoutWidth = layoutWidth2;
                        layoutHeight = layoutHeight2;
                        $this$fastForEach$iv$iv = $this$fastForEach$iv$iv2;
                        if (firstItemIndices[lane5] > index$iv) {
                            z7 = true;
                            break;
                        } else {
                            z7 = false;
                            break;
                        }
                }
                if (z7) {
                    long spanRange$iv = $this$measure.m632getSpanRangelOCCd4c($this$measure.getItemProvider(), index$iv, 0);
                    if (list == null) {
                        Object result$iv = new ArrayList();
                        list = (List) result$iv;
                    }
                    LazyStaggeredGridMeasuredItem measuredItem$iv = $this$measure.getMeasuredItemProvider().m640getAndMeasurejy6DScQ(index$iv, spanRange$iv);
                    int extraItemOffset4 = extraItemOffset2 - measuredItem$iv.getSizeWithSpacings();
                    list.add(measuredItem$iv.position(0, extraItemOffset4, 0, mainAxisLayoutSize));
                    extraItemOffset2 = extraItemOffset4;
                }
                $i$f$calculateExtraItems++;
                pinnedItems$iv = pinnedItems$iv2;
                extraItemOffset3 = i19;
                $this$fastForEach$iv$iv2 = $this$fastForEach$iv$iv;
                initialItemsMeasured2 = initialItemsMeasured5;
                layoutHeight2 = layoutHeight;
                layoutWidth2 = layoutWidth;
            }
            int layoutWidth4 = layoutWidth2;
            int layoutHeight4 = layoutHeight2;
            if (list == null) {
                list = CollectionsKt.emptyList();
            }
            List extraItemsBefore2 = list;
            final List positionedItems = calculatePositionedItems(lazyStaggeredGridMeasureContext, measuredItems2, $this$transform$iv, mainAxisLayoutSize);
            int extraItemOffset5 = $this$transform$iv[0];
            List list2 = null;
            LazyLayoutPinnedItemList pinnedItems$iv3 = $this$measure.getState().getPinnedItems$foundation_release();
            LazyLayoutPinnedItemList $this$fastForEach$iv$iv3 = pinnedItems$iv3;
            boolean z9 = false;
            int size3 = $this$fastForEach$iv$iv3.size();
            int $i$f$calculateExtraItems2 = 0;
            while ($i$f$calculateExtraItems2 < size3) {
                Object item$iv$iv2 = $this$fastForEach$iv$iv3.get($i$f$calculateExtraItems2);
                LazyLayoutPinnedItemList.PinnedItem item$iv2 = (LazyLayoutPinnedItemList.PinnedItem) item$iv$iv2;
                int i21 = size3;
                LazyLayoutPinnedItemList pinnedItems$iv4 = pinnedItems$iv3;
                List $this$fastForEach$iv$iv4 = $this$fastForEach$iv$iv3;
                int index$iv2 = LazyLayoutItemProviderKt.findIndexByKey($this$measure.getItemProvider(), item$iv2.getKey(), item$iv2.getIndex());
                boolean z10 = z9;
                int $i$f$fastForEach = itemCount4;
                if (index$iv2 < $i$f$fastForEach) {
                    int lane6 = $this$measure.getLaneInfo().getLane(index$iv2);
                    switch (lane6) {
                        case -2:
                        case -1:
                            int[] $this$all$iv3 = currentItemIndices;
                            extraItemsBefore = extraItemsBefore2;
                            measuredItems = measuredItems2;
                            int length15 = $this$all$iv3.length;
                            int i22 = 0;
                            while (true) {
                                if (i22 >= length15) {
                                    z6 = true;
                                    break;
                                } else {
                                    int element$iv6 = $this$all$iv3[i22];
                                    int i23 = length15;
                                    int it5 = element$iv6 < index$iv2 ? 1 : 0;
                                    if (it5 == 0) {
                                        z6 = false;
                                        break;
                                    } else {
                                        i22++;
                                        length15 = i23;
                                    }
                                }
                            }
                        default:
                            extraItemsBefore = extraItemsBefore2;
                            measuredItems = measuredItems2;
                            if (currentItemIndices[lane6] < index$iv2) {
                                z6 = true;
                                break;
                            } else {
                                z6 = false;
                                break;
                            }
                    }
                } else {
                    extraItemsBefore = extraItemsBefore2;
                    measuredItems = measuredItems2;
                    z6 = false;
                }
                if (z6) {
                    long spanRange$iv2 = $this$measure.m632getSpanRangelOCCd4c($this$measure.getItemProvider(), index$iv2, 0);
                    if (list2 == null) {
                        Object result$iv2 = new ArrayList();
                        list2 = (List) result$iv2;
                    }
                    LazyStaggeredGridMeasuredItem measuredItem$iv2 = $this$measure.getMeasuredItemProvider().m640getAndMeasurejy6DScQ(index$iv2, spanRange$iv2);
                    LazyStaggeredGridPositionedItem positionedItem = measuredItem$iv2.position(0, extraItemOffset5, 0, mainAxisLayoutSize);
                    extraItemOffset5 += measuredItem$iv2.getSizeWithSpacings();
                    list2.add(positionedItem);
                }
                $i$f$calculateExtraItems2++;
                pinnedItems$iv3 = pinnedItems$iv4;
                size3 = i21;
                $this$fastForEach$iv$iv3 = $this$fastForEach$iv$iv4;
                measuredItems2 = measuredItems;
                extraItemsBefore2 = extraItemsBefore;
                itemCount4 = $i$f$fastForEach;
                z9 = z10;
            }
            final List extraItemsBefore3 = extraItemsBefore2;
            int $i$f$fastForEach2 = itemCount4;
            if (list2 == null) {
                list2 = CollectionsKt.emptyList();
            }
            final List extraItemsAfter = list2;
            boolean canScrollBackward = firstItemIndices[0] != 0 || firstItemOffsets[0] > 0;
            int[] $this$any$iv4 = currentItemOffsets;
            int length16 = $this$any$iv4.length;
            int i24 = 0;
            while (true) {
                if (i24 < length16) {
                    int element$iv7 = $this$any$iv4[i24];
                    int it6 = element$iv7 > $this$measure.getMainAxisAvailableSize() ? 1 : 0;
                    if (it6 != 0) {
                        z4 = true;
                    } else {
                        i24++;
                    }
                } else {
                    z4 = false;
                }
            }
            if (!z4) {
                int[] $this$all$iv4 = currentItemIndices;
                int length17 = $this$all$iv4.length;
                int i25 = 0;
                while (true) {
                    if (i25 < length17) {
                        int element$iv8 = $this$all$iv4[i25];
                        int it7 = element$iv8 < $i$f$fastForEach2 + (-1) ? 1 : 0;
                        if (it7 == 0) {
                            z5 = false;
                        } else {
                            i25++;
                        }
                    } else {
                        z5 = true;
                    }
                }
                if (!z5) {
                    canScrollForward = false;
                    return new LazyStaggeredGridMeasureResult(firstItemIndices, firstItemOffsets, consumedScroll, MeasureScope.layout$default(scope$iv, layoutWidth4, layoutHeight4, null, new Function1<Placeable.PlacementScope, Unit>() { // from class: androidx.compose.foundation.lazy.staggeredgrid.LazyStaggeredGridMeasureKt$measure$1$29
                        /* JADX INFO: Access modifiers changed from: package-private */
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
                            List $this$fastForEach$iv = extraItemsBefore3;
                            LazyStaggeredGridMeasureContext lazyStaggeredGridMeasureContext3 = $this$measure;
                            int size4 = $this$fastForEach$iv.size();
                            for (int index$iv3 = 0; index$iv3 < size4; index$iv3++) {
                                Object item$iv3 = $this$fastForEach$iv.get(index$iv3);
                                LazyStaggeredGridPositionedItem item3 = (LazyStaggeredGridPositionedItem) item$iv3;
                                item3.place(layout, lazyStaggeredGridMeasureContext3);
                            }
                            List $this$fastForEach$iv2 = positionedItems;
                            LazyStaggeredGridMeasureContext lazyStaggeredGridMeasureContext4 = $this$measure;
                            int size5 = $this$fastForEach$iv2.size();
                            for (int index$iv4 = 0; index$iv4 < size5; index$iv4++) {
                                Object item$iv4 = $this$fastForEach$iv2.get(index$iv4);
                                LazyStaggeredGridPositionedItem item4 = (LazyStaggeredGridPositionedItem) item$iv4;
                                item4.place(layout, lazyStaggeredGridMeasureContext4);
                            }
                            List $this$fastForEach$iv3 = extraItemsAfter;
                            LazyStaggeredGridMeasureContext lazyStaggeredGridMeasureContext5 = $this$measure;
                            int size6 = $this$fastForEach$iv3.size();
                            for (int index$iv5 = 0; index$iv5 < size6; index$iv5++) {
                                Object item$iv5 = $this$fastForEach$iv3.get(index$iv5);
                                LazyStaggeredGridPositionedItem item5 = (LazyStaggeredGridPositionedItem) item$iv5;
                                item5.place(layout, lazyStaggeredGridMeasureContext5);
                            }
                        }
                    }, 4, null), canScrollForward, canScrollBackward, $this$measure.isVertical(), $i$f$fastForEach2, positionedItems, IntSizeKt.IntSize(layoutWidth4, layoutHeight4), minOffset3, maxOffset, $this$measure.getBeforeContentPadding(), $this$measure.getAfterContentPadding(), $this$measure.getMainAxisSpacing(), null);
                }
            }
            canScrollForward = true;
            return new LazyStaggeredGridMeasureResult(firstItemIndices, firstItemOffsets, consumedScroll, MeasureScope.layout$default(scope$iv, layoutWidth4, layoutHeight4, null, new Function1<Placeable.PlacementScope, Unit>() { // from class: androidx.compose.foundation.lazy.staggeredgrid.LazyStaggeredGridMeasureKt$measure$1$29
                /* JADX INFO: Access modifiers changed from: package-private */
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
                    List $this$fastForEach$iv = extraItemsBefore3;
                    LazyStaggeredGridMeasureContext lazyStaggeredGridMeasureContext3 = $this$measure;
                    int size4 = $this$fastForEach$iv.size();
                    for (int index$iv3 = 0; index$iv3 < size4; index$iv3++) {
                        Object item$iv3 = $this$fastForEach$iv.get(index$iv3);
                        LazyStaggeredGridPositionedItem item3 = (LazyStaggeredGridPositionedItem) item$iv3;
                        item3.place(layout, lazyStaggeredGridMeasureContext3);
                    }
                    List $this$fastForEach$iv2 = positionedItems;
                    LazyStaggeredGridMeasureContext lazyStaggeredGridMeasureContext4 = $this$measure;
                    int size5 = $this$fastForEach$iv2.size();
                    for (int index$iv4 = 0; index$iv4 < size5; index$iv4++) {
                        Object item$iv4 = $this$fastForEach$iv2.get(index$iv4);
                        LazyStaggeredGridPositionedItem item4 = (LazyStaggeredGridPositionedItem) item$iv4;
                        item4.place(layout, lazyStaggeredGridMeasureContext4);
                    }
                    List $this$fastForEach$iv3 = extraItemsAfter;
                    LazyStaggeredGridMeasureContext lazyStaggeredGridMeasureContext5 = $this$measure;
                    int size6 = $this$fastForEach$iv3.size();
                    for (int index$iv5 = 0; index$iv5 < size6; index$iv5++) {
                        Object item$iv5 = $this$fastForEach$iv3.get(index$iv5);
                        LazyStaggeredGridPositionedItem item5 = (LazyStaggeredGridPositionedItem) item$iv5;
                        item5.place(layout, lazyStaggeredGridMeasureContext5);
                    }
                }
            }, 4, null), canScrollForward, canScrollBackward, $this$measure.isVertical(), $i$f$fastForEach2, positionedItems, IntSizeKt.IntSize(layoutWidth4, layoutHeight4), minOffset3, maxOffset, $this$measure.getBeforeContentPadding(), $this$measure.getAfterContentPadding(), $this$measure.getMainAxisSpacing(), null);
        } else {
            itemCount = itemCount5;
        }
        return new LazyStaggeredGridMeasureResult(initialItemIndices, initialItemOffsets, 0.0f, MeasureScope.layout$default(scope$iv, Constraints.m5080getMinWidthimpl($this$measure.m629getConstraintsmsEJaDk()), Constraints.m5079getMinHeightimpl($this$measure.m629getConstraintsmsEJaDk()), null, new Function1<Placeable.PlacementScope, Unit>() { // from class: androidx.compose.foundation.lazy.staggeredgrid.LazyStaggeredGridMeasureKt$measure$1$1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Placeable.PlacementScope placementScope) {
                invoke2(placementScope);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke  reason: avoid collision after fix types in other method */
            public final void invoke2(Placeable.PlacementScope layout) {
                Intrinsics.checkNotNullParameter(layout, "$this$layout");
            }
        }, 4, null), false, false, $this$measure.isVertical(), itemCount, CollectionsKt.emptyList(), IntSizeKt.IntSize(Constraints.m5080getMinWidthimpl($this$measure.m629getConstraintsmsEJaDk()), Constraints.m5079getMinHeightimpl($this$measure.m629getConstraintsmsEJaDk())), -$this$measure.getBeforeContentPadding(), $this$measure.getMainAxisAvailableSize() + $this$measure.getAfterContentPadding(), $this$measure.getBeforeContentPadding(), $this$measure.getAfterContentPadding(), $this$measure.getMainAxisSpacing(), null);
    }

    private static final boolean measure$lambda$37$hasSpaceBeforeFirst(int[] firstItemIndices, int[] firstItemOffsets, LazyStaggeredGridMeasureContext $this_measure) {
        int length = firstItemIndices.length;
        for (int lane = 0; lane < length; lane++) {
            int itemIndex = firstItemIndices[lane];
            int itemOffset = firstItemOffsets[lane];
            if (itemOffset < Math.max(-$this_measure.getMainAxisSpacing(), 0) && itemIndex > 0) {
                return true;
            }
        }
        return false;
    }

    private static final boolean measure$lambda$37$misalignedStart(int[] firstItemIndices, LazyStaggeredGridMeasureContext $this_measure, int[] firstItemOffsets, int referenceLane) {
        int lane = 0;
        int length = firstItemIndices.length;
        while (true) {
            boolean z = false;
            if (lane < length) {
                if (findPreviousItemIndex($this_measure, firstItemIndices[lane], lane) == -1 && firstItemOffsets[lane] != firstItemOffsets[referenceLane]) {
                    z = true;
                }
                boolean misalignedOffsets = z;
                if (misalignedOffsets) {
                    return true;
                }
                lane++;
            } else {
                int length2 = firstItemIndices.length;
                for (int lane2 = 0; lane2 < length2; lane2++) {
                    boolean moreItemsInOtherLanes = findPreviousItemIndex($this_measure, firstItemIndices[lane2], lane2) != -1 && firstItemOffsets[lane2] >= firstItemOffsets[referenceLane];
                    if (moreItemsInOtherLanes) {
                        return true;
                    }
                }
                int firstItemLane = $this_measure.getLaneInfo().getLane(0);
                return (firstItemLane == 0 || firstItemLane == -1 || firstItemLane == -2) ? false : true;
            }
        }
    }

    private static final List<LazyStaggeredGridPositionedItem> calculatePositionedItems(LazyStaggeredGridMeasureContext $this$calculatePositionedItems, ArrayDeque<LazyStaggeredGridMeasuredItem>[] arrayDequeArr, int[] itemScrollOffsets, int mainAxisLayoutSize) {
        boolean z;
        int crossAxisOffset;
        int i = 0;
        for (ArrayDeque<LazyStaggeredGridMeasuredItem> arrayDeque : arrayDequeArr) {
            i += arrayDeque.size();
        }
        ArrayList positionedItems = new ArrayList(i);
        while (true) {
            int length = arrayDequeArr.length;
            int i2 = 0;
            while (true) {
                if (i2 < length) {
                    z = true;
                    if (!arrayDequeArr[i2].isEmpty()) {
                        break;
                    }
                    i2++;
                } else {
                    z = false;
                    break;
                }
            }
            if (!z) {
                return positionedItems;
            }
            int result$iv = -1;
            int min$iv = Integer.MAX_VALUE;
            int length2 = arrayDequeArr.length;
            for (int i$iv = 0; i$iv < length2; i$iv++) {
                LazyStaggeredGridMeasuredItem firstOrNull = arrayDequeArr[i$iv].firstOrNull();
                int value$iv = firstOrNull != null ? firstOrNull.getIndex() : Integer.MAX_VALUE;
                if (min$iv > value$iv) {
                    min$iv = value$iv;
                    result$iv = i$iv;
                }
            }
            int laneIndex = result$iv;
            LazyStaggeredGridMeasuredItem item = arrayDequeArr[laneIndex].removeFirst();
            if (item.getLane() == laneIndex) {
                long spanRange = SpanRange.m643constructorimpl(item.getLane(), item.getSpan());
                int mainAxisOffset = m635maxInRangejy6DScQ(itemScrollOffsets, spanRange);
                if (laneIndex == 0) {
                    crossAxisOffset = 0;
                } else {
                    crossAxisOffset = $this$calculatePositionedItems.getResolvedSlotSums()[laneIndex - 1] + ($this$calculatePositionedItems.getCrossAxisSpacing() * laneIndex);
                }
                if (!item.getPlaceables().isEmpty()) {
                    positionedItems.add(item.position(laneIndex, mainAxisOffset, crossAxisOffset, mainAxisLayoutSize));
                    int i$iv2 = (int) (spanRange >> 32);
                    int i3 = (int) (spanRange & 4294967295L);
                    for (int i$iv3 = i$iv2; i$iv3 < i3; i$iv3++) {
                        int lane = i$iv3;
                        itemScrollOffsets[lane] = mainAxisOffset + item.getSizeWithSpacings();
                    }
                }
            }
        }
    }

    private static final List<LazyStaggeredGridPositionedItem> calculateExtraItems(LazyStaggeredGridMeasureContext $this$calculateExtraItems, Function1<? super LazyStaggeredGridMeasuredItem, LazyStaggeredGridPositionedItem> function1, Function1<? super Integer, Boolean> function12) {
        boolean z;
        LazyLayoutPinnedItemList pinnedItems;
        List $this$fastForEach$iv;
        boolean z2 = false;
        ArrayList arrayList = null;
        LazyLayoutPinnedItemList pinnedItems2 = $this$calculateExtraItems.getState().getPinnedItems$foundation_release();
        LazyLayoutPinnedItemList $this$fastForEach$iv2 = pinnedItems2;
        int index$iv = 0;
        int size = $this$fastForEach$iv2.size();
        while (index$iv < size) {
            Object item$iv = $this$fastForEach$iv2.get(index$iv);
            LazyLayoutPinnedItemList.PinnedItem item = (LazyLayoutPinnedItemList.PinnedItem) item$iv;
            int index = LazyLayoutItemProviderKt.findIndexByKey($this$calculateExtraItems.getItemProvider(), item.getKey(), item.getIndex());
            if (function12.invoke(Integer.valueOf(index)).booleanValue()) {
                pinnedItems = pinnedItems2;
                $this$fastForEach$iv = $this$fastForEach$iv2;
                long spanRange = $this$calculateExtraItems.m632getSpanRangelOCCd4c($this$calculateExtraItems.getItemProvider(), index, 0);
                if (arrayList == null) {
                    Object result = new ArrayList();
                    arrayList = (List) result;
                }
                LazyStaggeredGridMeasuredItem measuredItem = $this$calculateExtraItems.getMeasuredItemProvider().m640getAndMeasurejy6DScQ(index, spanRange);
                z = z2;
                arrayList.add(function1.invoke(measuredItem));
            } else {
                z = z2;
                pinnedItems = pinnedItems2;
                $this$fastForEach$iv = $this$fastForEach$iv2;
            }
            index$iv++;
            pinnedItems2 = pinnedItems;
            $this$fastForEach$iv2 = $this$fastForEach$iv;
            z2 = z;
        }
        return arrayList == null ? CollectionsKt.emptyList() : arrayList;
    }

    /* renamed from: forEach-nIS5qE8  reason: not valid java name */
    private static final void m634forEachnIS5qE8(long $this$forEach_u2dnIS5qE8, Function1<? super Integer, Unit> function1) {
        int i = (int) (4294967295L & $this$forEach_u2dnIS5qE8);
        for (int i2 = (int) ($this$forEach_u2dnIS5qE8 >> 32); i2 < i; i2++) {
            function1.invoke(Integer.valueOf(i2));
        }
    }

    private static final void offsetBy(int[] $this$offsetBy, int delta) {
        int length = $this$offsetBy.length;
        for (int i = 0; i < length; i++) {
            $this$offsetBy[i] = $this$offsetBy[i] + delta;
        }
    }

    /* renamed from: maxInRange-jy6DScQ  reason: not valid java name */
    private static final int m635maxInRangejy6DScQ(int[] $this$maxInRange_u2djy6DScQ, long indexRange) {
        int max = Integer.MIN_VALUE;
        int i = (int) (4294967295L & indexRange);
        for (int i$iv = (int) (indexRange >> 32); i$iv < i; i$iv++) {
            int it = i$iv;
            max = Math.max(max, $this$maxInRange_u2djy6DScQ[it]);
        }
        return max;
    }

    public static /* synthetic */ int indexOfMinValue$default(int[] iArr, int i, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            i = Integer.MIN_VALUE;
        }
        return indexOfMinValue(iArr, i);
    }

    public static final int indexOfMinValue(int[] $this$indexOfMinValue, int minBound) {
        Intrinsics.checkNotNullParameter($this$indexOfMinValue, "<this>");
        int result = -1;
        int min = Integer.MAX_VALUE;
        int length = $this$indexOfMinValue.length;
        for (int i = 0; i < length; i++) {
            int i2 = minBound + 1;
            int i3 = $this$indexOfMinValue[i];
            boolean z = false;
            if (i2 <= i3 && i3 < min) {
                z = true;
            }
            if (z) {
                min = $this$indexOfMinValue[i];
                result = i;
            }
        }
        return result;
    }

    private static final <T> int indexOfMinBy(T[] tArr, Function1<? super T, Integer> function1) {
        int result = -1;
        int min = Integer.MAX_VALUE;
        int length = tArr.length;
        for (int i = 0; i < length; i++) {
            int value = function1.invoke(tArr[i]).intValue();
            if (min > value) {
                min = value;
                result = i;
            }
        }
        return result;
    }

    private static final int indexOfMaxValue(int[] $this$indexOfMaxValue) {
        int result = -1;
        int max = Integer.MIN_VALUE;
        int length = $this$indexOfMaxValue.length;
        for (int i = 0; i < length; i++) {
            if (max < $this$indexOfMaxValue[i]) {
                max = $this$indexOfMaxValue[i];
                result = i;
            }
        }
        return result;
    }

    private static final int[] transform(int[] $this$transform, Function1<? super Integer, Integer> function1) {
        int length = $this$transform.length;
        for (int i = 0; i < length; i++) {
            $this$transform[i] = function1.invoke(Integer.valueOf($this$transform[i])).intValue();
        }
        return $this$transform;
    }

    private static final void ensureIndicesInRange(LazyStaggeredGridMeasureContext $this$ensureIndicesInRange, int[] indices, int itemCount) {
        int length = indices.length - 1;
        if (length >= 0) {
            do {
                int i = length;
                length--;
                while (true) {
                    if (indices[i] < itemCount && $this$ensureIndicesInRange.getLaneInfo().assignedToLane(indices[i], i)) {
                        break;
                    }
                    indices[i] = findPreviousItemIndex($this$ensureIndicesInRange, indices[i], i);
                }
                if (indices[i] >= 0 && !$this$ensureIndicesInRange.isFullSpan($this$ensureIndicesInRange.getItemProvider(), indices[i])) {
                    $this$ensureIndicesInRange.getLaneInfo().setLane(indices[i], i);
                    continue;
                }
            } while (length >= 0);
        }
    }

    private static final int findPreviousItemIndex(LazyStaggeredGridMeasureContext $this$findPreviousItemIndex, int item, int lane) {
        return $this$findPreviousItemIndex.getLaneInfo().findPreviousItemIndex(item, lane);
    }
}
