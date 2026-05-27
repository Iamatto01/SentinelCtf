package androidx.compose.foundation.lazy;

import androidx.compose.foundation.layout.Arrangement;
import androidx.compose.foundation.lazy.layout.LazyLayoutItemProviderKt;
import androidx.compose.foundation.lazy.layout.LazyLayoutPinnedItemList;
import androidx.compose.ui.unit.Density;
import androidx.compose.ui.unit.LayoutDirection;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.TuplesKt;
import kotlin.collections.ArraysKt;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Ref;
import kotlin.ranges.IntRange;
import kotlin.ranges.RangesKt;
/* compiled from: LazyListMeasure.kt */
@Metadata(d1 = {"\u0000\u009e\u0001\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a\u008c\u0001\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\t0\b2\f\u0010\n\u001a\b\u0012\u0004\u0012\u00020\f0\u000b2\f\u0010\r\u001a\b\u0012\u0004\u0012\u00020\f0\u000b2\f\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\f0\u000b2\u0006\u0010\u000f\u001a\u00020\u00022\u0006\u0010\u0010\u001a\u00020\u00022\u0006\u0010\u0011\u001a\u00020\u00022\u0006\u0010\u0012\u001a\u00020\u00022\u0006\u0010\u0013\u001a\u00020\u00022\u0006\u0010\u0014\u001a\u00020\u00042\b\u0010\u0015\u001a\u0004\u0018\u00010\u00162\b\u0010\u0017\u001a\u0004\u0018\u00010\u00182\u0006\u0010\u0019\u001a\u00020\u00042\u0006\u0010\u001a\u001a\u00020\u001bH\u0002\u001aL\u0010\u001c\u001a\b\u0012\u0004\u0012\u00020\f0\u000b2\u0006\u0010\u001d\u001a\u00020\u001e2\f\u0010\u001f\u001a\b\u0012\u0004\u0012\u00020\f0\b2\u0006\u0010 \u001a\u00020!2\u0006\u0010\"\u001a\u00020#2\u0006\u0010$\u001a\u00020\u00022\u0006\u0010%\u001a\u00020\u00022\u0006\u0010&\u001a\u00020'H\u0002\u001aS\u0010(\u001a\b\u0012\u0004\u0012\u00020\f0\u000b2\u0006\u0010\u001d\u001a\u00020\u001e2\u0006\u0010)\u001a\u00020*2\u0006\u0010 \u001a\u00020!2\u0006\u0010\"\u001a\u00020#2\u0006\u0010$\u001a\u00020\u00022\u0006\u0010%\u001a\u00020\u00022\u0006\u0010&\u001a\u00020'H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b+\u0010,\u001aø\u0001\u0010-\u001a\u00020.2\u0006\u0010$\u001a\u00020\u00022\u0006\u0010\"\u001a\u00020#2\u0006\u0010 \u001a\u00020!2\u0006\u0010/\u001a\u00020\u00022\u0006\u00100\u001a\u00020\u00022\u0006\u00101\u001a\u00020\u00022\u0006\u00102\u001a\u00020\u00022\u0006\u00103\u001a\u00020*2\u0006\u00104\u001a\u00020\u00022\u0006\u00105\u001a\u0002062\u0006\u00107\u001a\u0002082\u0006\u0010\u0014\u001a\u00020\u00042\f\u00109\u001a\b\u0012\u0004\u0012\u00020\u00020\u000b2\b\u0010\u0015\u001a\u0004\u0018\u00010\u00162\b\u0010\u0017\u001a\u0004\u0018\u00010\u00182\u0006\u0010\u0019\u001a\u00020\u00042\u0006\u0010\u001a\u001a\u00020\u001b2\u0006\u0010:\u001a\u00020;2\u0006\u0010\u001d\u001a\u00020\u001e2\u0006\u0010%\u001a\u00020\u00022\u0006\u0010&\u001a\u00020'2/\u0010<\u001a+\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0002\u0012\u0015\u0012\u0013\u0012\u0004\u0012\u00020?\u0012\u0004\u0012\u00020@0>¢\u0006\u0002\bA\u0012\u0004\u0012\u00020B0=H\u0000ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\bC\u0010D\"\u001a\u0010\u0000\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00020\u0001X\u0082\u0004¢\u0006\u0002\n\u0000\"\u0018\u0010\u0003\u001a\u00020\u0004*\u00020\u00028BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u0005\u0010\u0006\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006E"}, d2 = {"EmptyRange", "Lkotlin/Pair;", "", "notInEmptyRange", "", "getNotInEmptyRange", "(I)Z", "calculateItemsOffsets", "", "Landroidx/compose/foundation/lazy/LazyListPositionedItem;", "items", "", "Landroidx/compose/foundation/lazy/LazyMeasuredItem;", "extraItemsBefore", "extraItemsAfter", "layoutWidth", "layoutHeight", "finalMainAxisOffset", "maxOffset", "itemsScrollOffset", "isVertical", "verticalArrangement", "Landroidx/compose/foundation/layout/Arrangement$Vertical;", "horizontalArrangement", "Landroidx/compose/foundation/layout/Arrangement$Horizontal;", "reverseLayout", "density", "Landroidx/compose/ui/unit/Density;", "createItemsAfterList", "beyondBoundsInfo", "Landroidx/compose/foundation/lazy/LazyListBeyondBoundsInfo;", "visibleItems", "measuredItemProvider", "Landroidx/compose/foundation/lazy/LazyMeasuredItemProvider;", "itemProvider", "Landroidx/compose/foundation/lazy/LazyListItemProvider;", "itemsCount", "beyondBoundsItemCount", "pinnedItems", "Landroidx/compose/foundation/lazy/layout/LazyLayoutPinnedItemList;", "createItemsBeforeList", "currentFirstItemIndex", "Landroidx/compose/foundation/lazy/DataIndex;", "createItemsBeforeList-tv8sHfA", "(Landroidx/compose/foundation/lazy/LazyListBeyondBoundsInfo;ILandroidx/compose/foundation/lazy/LazyMeasuredItemProvider;Landroidx/compose/foundation/lazy/LazyListItemProvider;IILandroidx/compose/foundation/lazy/layout/LazyLayoutPinnedItemList;)Ljava/util/List;", "measureLazyList", "Landroidx/compose/foundation/lazy/LazyListMeasureResult;", "mainAxisAvailableSize", "beforeContentPadding", "afterContentPadding", "spaceBetweenItems", "firstVisibleItemIndex", "firstVisibleItemScrollOffset", "scrollToBeConsumed", "", "constraints", "Landroidx/compose/ui/unit/Constraints;", "headerIndexes", "placementAnimator", "Landroidx/compose/foundation/lazy/LazyListItemPlacementAnimator;", "layout", "Lkotlin/Function3;", "Lkotlin/Function1;", "Landroidx/compose/ui/layout/Placeable$PlacementScope;", "", "Lkotlin/ExtensionFunctionType;", "Landroidx/compose/ui/layout/MeasureResult;", "measureLazyList-Hh3qtAg", "(ILandroidx/compose/foundation/lazy/LazyListItemProvider;Landroidx/compose/foundation/lazy/LazyMeasuredItemProvider;IIIIIIFJZLjava/util/List;Landroidx/compose/foundation/layout/Arrangement$Vertical;Landroidx/compose/foundation/layout/Arrangement$Horizontal;ZLandroidx/compose/ui/unit/Density;Landroidx/compose/foundation/lazy/LazyListItemPlacementAnimator;Landroidx/compose/foundation/lazy/LazyListBeyondBoundsInfo;ILandroidx/compose/foundation/lazy/layout/LazyLayoutPinnedItemList;Lkotlin/jvm/functions/Function3;)Landroidx/compose/foundation/lazy/LazyListMeasureResult;", "foundation_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LazyListMeasureKt {
    private static final Pair<Integer, Integer> EmptyRange = TuplesKt.to(Integer.MIN_VALUE, Integer.MIN_VALUE);

    /* JADX WARN: Code restructure failed: missing block: B:94:0x0290, code lost:
        r21 = r3;
     */
    /* renamed from: measureLazyList-Hh3qtAg  reason: not valid java name */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.foundation.lazy.LazyListMeasureResult m525measureLazyListHh3qtAg(int r48, androidx.compose.foundation.lazy.LazyListItemProvider r49, androidx.compose.foundation.lazy.LazyMeasuredItemProvider r50, int r51, int r52, int r53, int r54, int r55, int r56, float r57, long r58, boolean r60, java.util.List<java.lang.Integer> r61, androidx.compose.foundation.layout.Arrangement.Vertical r62, androidx.compose.foundation.layout.Arrangement.Horizontal r63, boolean r64, androidx.compose.ui.unit.Density r65, androidx.compose.foundation.lazy.LazyListItemPlacementAnimator r66, androidx.compose.foundation.lazy.LazyListBeyondBoundsInfo r67, int r68, androidx.compose.foundation.lazy.layout.LazyLayoutPinnedItemList r69, kotlin.jvm.functions.Function3<? super java.lang.Integer, ? super java.lang.Integer, ? super kotlin.jvm.functions.Function1<? super androidx.compose.ui.layout.Placeable.PlacementScope, kotlin.Unit>, ? extends androidx.compose.ui.layout.MeasureResult> r70) {
        /*
            Method dump skipped, instructions count: 1243
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.lazy.LazyListMeasureKt.m525measureLazyListHh3qtAg(int, androidx.compose.foundation.lazy.LazyListItemProvider, androidx.compose.foundation.lazy.LazyMeasuredItemProvider, int, int, int, int, int, int, float, long, boolean, java.util.List, androidx.compose.foundation.layout.Arrangement$Vertical, androidx.compose.foundation.layout.Arrangement$Horizontal, boolean, androidx.compose.ui.unit.Density, androidx.compose.foundation.lazy.LazyListItemPlacementAnimator, androidx.compose.foundation.lazy.LazyListBeyondBoundsInfo, int, androidx.compose.foundation.lazy.layout.LazyLayoutPinnedItemList, kotlin.jvm.functions.Function3):androidx.compose.foundation.lazy.LazyListMeasureResult");
    }

    private static final int createItemsAfterList$endIndex(LazyListBeyondBoundsInfo $this$createItemsAfterList_u24endIndex, int $itemsCount) {
        return Math.min($this$createItemsAfterList_u24endIndex.getEnd(), $itemsCount - 1);
    }

    private static final List<LazyMeasuredItem> createItemsAfterList(LazyListBeyondBoundsInfo beyondBoundsInfo, List<LazyMeasuredItem> list, LazyMeasuredItemProvider measuredItemProvider, LazyListItemProvider itemProvider, int itemsCount, int beyondBoundsItemCount, LazyLayoutPinnedItemList pinnedItems) {
        Ref.ObjectRef list2 = new Ref.ObjectRef();
        int end = ((LazyMeasuredItem) CollectionsKt.last((List<? extends Object>) list)).getIndex();
        if (beyondBoundsInfo.hasIntervals()) {
            end = Math.max(createItemsAfterList$endIndex(beyondBoundsInfo, itemsCount), end);
        }
        int end2 = Math.min(end + beyondBoundsItemCount, itemsCount - 1);
        int i = ((LazyMeasuredItem) CollectionsKt.last((List<? extends Object>) list)).getIndex() + 1;
        if (i <= end2) {
            while (true) {
                createItemsAfterList$addItem(list2, measuredItemProvider, i);
                if (i == end2) {
                    break;
                }
                i++;
            }
        }
        LazyLayoutPinnedItemList $this$fastForEach$iv = pinnedItems;
        int size = $this$fastForEach$iv.size();
        for (int index$iv = 0; index$iv < size; index$iv++) {
            Object item$iv = $this$fastForEach$iv.get(index$iv);
            LazyLayoutPinnedItemList.PinnedItem item = (LazyLayoutPinnedItemList.PinnedItem) item$iv;
            int index = LazyLayoutItemProviderKt.findIndexByKey(itemProvider, item.getKey(), item.getIndex());
            if (index > end2 && index < itemsCount) {
                createItemsAfterList$addItem(list2, measuredItemProvider, index);
            }
        }
        List<LazyMeasuredItem> list3 = (List) list2.element;
        return list3 == null ? CollectionsKt.emptyList() : list3;
    }

    /* JADX WARN: Type inference failed for: r0v5, types: [java.util.List, T] */
    private static final void createItemsAfterList$addItem(Ref.ObjectRef<List<LazyMeasuredItem>> objectRef, LazyMeasuredItemProvider $measuredItemProvider, int index) {
        if (objectRef.element == null) {
            objectRef.element = new ArrayList();
        }
        List<LazyMeasuredItem> list = objectRef.element;
        if (list != null) {
            list.add($measuredItemProvider.m535getAndMeasureZjPyQlc(DataIndex.m503constructorimpl(index)));
            return;
        }
        throw new IllegalArgumentException("Required value was null.".toString());
    }

    private static final int createItemsBeforeList_tv8sHfA$startIndex(LazyListBeyondBoundsInfo $this$createItemsBeforeList_tv8sHfA_u24startIndex, int $itemsCount) {
        return Math.min($this$createItemsBeforeList_tv8sHfA_u24startIndex.getStart(), $itemsCount - 1);
    }

    /* renamed from: createItemsBeforeList-tv8sHfA  reason: not valid java name */
    private static final List<LazyMeasuredItem> m524createItemsBeforeListtv8sHfA(LazyListBeyondBoundsInfo beyondBoundsInfo, int currentFirstItemIndex, LazyMeasuredItemProvider measuredItemProvider, LazyListItemProvider itemProvider, int itemsCount, int beyondBoundsItemCount, LazyLayoutPinnedItemList pinnedItems) {
        Ref.ObjectRef list = new Ref.ObjectRef();
        int start = currentFirstItemIndex;
        if (beyondBoundsInfo.hasIntervals()) {
            start = Math.min(createItemsBeforeList_tv8sHfA$startIndex(beyondBoundsInfo, itemsCount), start);
        }
        int start2 = Math.max(0, start - beyondBoundsItemCount);
        int i = currentFirstItemIndex - 1;
        if (start2 <= i) {
            while (true) {
                createItemsBeforeList_tv8sHfA$addItem$5(list, measuredItemProvider, i);
                if (i == start2) {
                    break;
                }
                i--;
            }
        }
        LazyLayoutPinnedItemList $this$fastForEach$iv = pinnedItems;
        int size = $this$fastForEach$iv.size();
        for (int index$iv = 0; index$iv < size; index$iv++) {
            Object item$iv = $this$fastForEach$iv.get(index$iv);
            LazyLayoutPinnedItemList.PinnedItem item = (LazyLayoutPinnedItemList.PinnedItem) item$iv;
            int index = LazyLayoutItemProviderKt.findIndexByKey(itemProvider, item.getKey(), item.getIndex());
            if (index < start2) {
                createItemsBeforeList_tv8sHfA$addItem$5(list, measuredItemProvider, index);
            }
        }
        List<LazyMeasuredItem> list2 = (List) list.element;
        return list2 == null ? CollectionsKt.emptyList() : list2;
    }

    /* JADX WARN: Type inference failed for: r0v5, types: [java.util.List, T] */
    private static final void createItemsBeforeList_tv8sHfA$addItem$5(Ref.ObjectRef<List<LazyMeasuredItem>> objectRef, LazyMeasuredItemProvider $measuredItemProvider, int index) {
        if (objectRef.element == null) {
            objectRef.element = new ArrayList();
        }
        List<LazyMeasuredItem> list = objectRef.element;
        if (list != null) {
            list.add($measuredItemProvider.m535getAndMeasureZjPyQlc(DataIndex.m503constructorimpl(index)));
            return;
        }
        throw new IllegalArgumentException("Required value was null.".toString());
    }

    private static final List<LazyListPositionedItem> calculateItemsOffsets(List<LazyMeasuredItem> list, List<LazyMeasuredItem> list2, List<LazyMeasuredItem> list3, int layoutWidth, int layoutHeight, int finalMainAxisOffset, int maxOffset, int itemsScrollOffset, boolean isVertical, Arrangement.Vertical verticalArrangement, Arrangement.Horizontal horizontalArrangement, boolean reverseLayout, Density density) {
        int[] offsets;
        int i;
        List<LazyMeasuredItem> list4 = list;
        boolean z = reverseLayout;
        int mainAxisLayoutSize = isVertical ? layoutHeight : layoutWidth;
        boolean z2 = true;
        boolean hasSpareSpace = finalMainAxisOffset < Math.min(mainAxisLayoutSize, maxOffset);
        if (hasSpareSpace) {
            if (!(itemsScrollOffset == 0)) {
                throw new IllegalStateException("Check failed.".toString());
            }
        }
        ArrayList positionedItems = new ArrayList(list.size() + list2.size() + list3.size());
        if (hasSpareSpace) {
            if (!((list2.isEmpty() && list3.isEmpty()) ? false : false)) {
                throw new IllegalArgumentException("Failed requirement.".toString());
            }
            int itemsCount = list.size();
            int[] sizes = new int[itemsCount];
            for (int i2 = 0; i2 < itemsCount; i2++) {
                sizes[i2] = list4.get(calculateItemsOffsets$reverseAware(i2, z, itemsCount)).getSize();
            }
            int[] offsets2 = new int[itemsCount];
            for (int i3 = 0; i3 < itemsCount; i3++) {
                offsets2[i3] = 0;
            }
            if (isVertical) {
                if (verticalArrangement == null) {
                    throw new IllegalArgumentException("Required value was null.".toString());
                }
                verticalArrangement.arrange(density, mainAxisLayoutSize, sizes, offsets2);
                offsets = offsets2;
            } else if (horizontalArrangement == null) {
                throw new IllegalArgumentException("Required value was null.".toString());
            } else {
                offsets = offsets2;
                horizontalArrangement.arrange(density, mainAxisLayoutSize, sizes, LayoutDirection.Ltr, offsets);
            }
            IntRange reverseAwareOffsetIndices = ArraysKt.getIndices(offsets);
            if (z) {
                reverseAwareOffsetIndices = RangesKt.reversed(reverseAwareOffsetIndices);
            }
            int index = reverseAwareOffsetIndices.getFirst();
            int last = reverseAwareOffsetIndices.getLast();
            int step = reverseAwareOffsetIndices.getStep();
            if ((step > 0 && index <= last) || (step < 0 && last <= index)) {
                while (true) {
                    int absoluteOffset = offsets[index];
                    LazyMeasuredItem item = list4.get(calculateItemsOffsets$reverseAware(index, z, itemsCount));
                    if (z) {
                        i = (mainAxisLayoutSize - absoluteOffset) - item.getSize();
                    } else {
                        i = absoluteOffset;
                    }
                    int relativeOffset = i;
                    positionedItems.add(item.position(relativeOffset, layoutWidth, layoutHeight));
                    if (index == last) {
                        break;
                    }
                    index += step;
                    list4 = list;
                    z = reverseLayout;
                }
            }
        } else {
            int currentMainAxis = itemsScrollOffset;
            int size = list2.size();
            for (int index$iv = 0; index$iv < size; index$iv++) {
                Object item$iv = list2.get(index$iv);
                LazyMeasuredItem it = (LazyMeasuredItem) item$iv;
                currentMainAxis -= it.getSizeWithSpacings();
                positionedItems.add(it.position(currentMainAxis, layoutWidth, layoutHeight));
            }
            int currentMainAxis2 = itemsScrollOffset;
            int size2 = list.size();
            for (int index$iv2 = 0; index$iv2 < size2; index$iv2++) {
                Object item$iv2 = list.get(index$iv2);
                LazyMeasuredItem it2 = (LazyMeasuredItem) item$iv2;
                positionedItems.add(it2.position(currentMainAxis2, layoutWidth, layoutHeight));
                currentMainAxis2 += it2.getSizeWithSpacings();
            }
            int size3 = list3.size();
            for (int index$iv3 = 0; index$iv3 < size3; index$iv3++) {
                Object item$iv3 = list3.get(index$iv3);
                LazyMeasuredItem it3 = (LazyMeasuredItem) item$iv3;
                positionedItems.add(it3.position(currentMainAxis2, layoutWidth, layoutHeight));
                currentMainAxis2 += it3.getSizeWithSpacings();
            }
        }
        return positionedItems;
    }

    private static final int calculateItemsOffsets$reverseAware(int $this$calculateItemsOffsets_u24reverseAware, boolean $reverseLayout, int itemsCount) {
        return !$reverseLayout ? $this$calculateItemsOffsets_u24reverseAware : (itemsCount - $this$calculateItemsOffsets_u24reverseAware) - 1;
    }

    private static final boolean getNotInEmptyRange(int $this$notInEmptyRange) {
        return $this$notInEmptyRange != Integer.MIN_VALUE;
    }
}
