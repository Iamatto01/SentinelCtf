package androidx.compose.foundation.lazy;

import androidx.compose.animation.core.FiniteAnimationSpec;
import androidx.compose.ui.unit.IntOffset;
import androidx.compose.ui.unit.IntOffsetKt;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.collections.MapsKt;
import kotlin.comparisons.ComparisonsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.BuildersKt;
import kotlinx.coroutines.CoroutineScope;
/* compiled from: LazyListItemPlacementAnimator.kt */
@Metadata(d1 = {"\u0000d\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010$\n\u0000\n\u0002\u0010%\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000e\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\t\b\u0000\u0018\u00002\u00020\u0001B\u0015\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005¢\u0006\u0002\u0010\u0006J\u001a\u0010\u001c\u001a\u00020\r2\u0006\u0010\u001d\u001a\u00020\u00162\b\b\u0002\u0010\u001e\u001a\u00020\bH\u0002J;\u0010\u001f\u001a\u00020\u00192\u0006\u0010 \u001a\u00020\u00012\u0006\u0010!\u001a\u00020\b2\u0006\u0010\"\u001a\u00020\b2\u0006\u0010#\u001a\u00020\b2\u0006\u0010$\u001a\u00020\u0019ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b%\u0010&J4\u0010'\u001a\u00020(2\u0006\u0010)\u001a\u00020\b2\u0006\u0010*\u001a\u00020\b2\u0006\u0010+\u001a\u00020\b2\f\u0010,\u001a\b\u0012\u0004\u0012\u00020\u00160\u00122\u0006\u0010-\u001a\u00020.J\u0006\u0010/\u001a\u00020(J\u0018\u00100\u001a\u00020(2\u0006\u0010\u001d\u001a\u00020\u00162\u0006\u00101\u001a\u00020\rH\u0002J\u0014\u00102\u001a\u00020\u0005*\u00020\r2\u0006\u00103\u001a\u00020\bH\u0002J\u001c\u00104\u001a\u00020\u0019*\u00020\bH\u0002ø\u0001\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b5\u00106R\u000e\u0010\u0007\u001a\u00020\bX\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000R\u001a\u0010\t\u001a\u000e\u0012\u0004\u0012\u00020\u0001\u0012\u0004\u0012\u00020\b0\nX\u0082\u000e¢\u0006\u0002\n\u0000R\u001a\u0010\u000b\u001a\u000e\u0012\u0004\u0012\u00020\u0001\u0012\u0004\u0012\u00020\r0\fX\u0082\u0004¢\u0006\u0002\n\u0000R\u001e\u0010\u000e\u001a\u0012\u0012\u0004\u0012\u00020\u00010\u000fj\b\u0012\u0004\u0012\u00020\u0001`\u0010X\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010\u0011\u001a\b\u0012\u0004\u0012\u00020\u00130\u0012X\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u00130\u0012X\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010\u0015\u001a\b\u0012\u0004\u0012\u00020\u00160\u0012X\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010\u0017\u001a\b\u0012\u0004\u0012\u00020\u00160\u0012X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u001b\u0010\u0018\u001a\u00020\b*\u00020\u00198BX\u0082\u0004ø\u0001\u0000¢\u0006\u0006\u001a\u0004\b\u001a\u0010\u001b\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u00067"}, d2 = {"Landroidx/compose/foundation/lazy/LazyListItemPlacementAnimator;", "", "scope", "Lkotlinx/coroutines/CoroutineScope;", "isVertical", "", "(Lkotlinx/coroutines/CoroutineScope;Z)V", "firstVisibleIndex", "", "keyToIndexMap", "", "keyToItemInfoMap", "", "Landroidx/compose/foundation/lazy/ItemInfo;", "movingAwayKeys", "Ljava/util/LinkedHashSet;", "Lkotlin/collections/LinkedHashSet;", "movingAwayToEndBound", "", "Landroidx/compose/foundation/lazy/LazyMeasuredItem;", "movingAwayToStartBound", "movingInFromEndBound", "Landroidx/compose/foundation/lazy/LazyListPositionedItem;", "movingInFromStartBound", "mainAxis", "Landroidx/compose/ui/unit/IntOffset;", "getMainAxis--gyyYBs", "(J)I", "createItemInfo", "item", "mainAxisOffset", "getAnimatedOffset", "key", "placeableIndex", "minOffset", "maxOffset", "rawOffset", "getAnimatedOffset-YT5a7pE", "(Ljava/lang/Object;IIIJ)J", "onMeasured", "", "consumedScroll", "layoutWidth", "layoutHeight", "positionedItems", "itemProvider", "Landroidx/compose/foundation/lazy/LazyMeasuredItemProvider;", "reset", "startAnimationsIfNeeded", "itemInfo", "isWithinBounds", "mainAxisLayoutSize", "toOffset", "toOffset-Bjo55l4", "(I)J", "foundation_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LazyListItemPlacementAnimator {
    private int firstVisibleIndex;
    private final boolean isVertical;
    private Map<Object, Integer> keyToIndexMap;
    private final Map<Object, ItemInfo> keyToItemInfoMap;
    private final LinkedHashSet<Object> movingAwayKeys;
    private final List<LazyMeasuredItem> movingAwayToEndBound;
    private final List<LazyMeasuredItem> movingAwayToStartBound;
    private final List<LazyListPositionedItem> movingInFromEndBound;
    private final List<LazyListPositionedItem> movingInFromStartBound;
    private final CoroutineScope scope;

    public LazyListItemPlacementAnimator(CoroutineScope scope, boolean isVertical) {
        Intrinsics.checkNotNullParameter(scope, "scope");
        this.scope = scope;
        this.isVertical = isVertical;
        this.keyToItemInfoMap = new LinkedHashMap();
        this.keyToIndexMap = MapsKt.emptyMap();
        this.movingAwayKeys = new LinkedHashSet<>();
        this.movingInFromStartBound = new ArrayList();
        this.movingInFromEndBound = new ArrayList();
        this.movingAwayToStartBound = new ArrayList();
        this.movingAwayToEndBound = new ArrayList();
    }

    public final void onMeasured(int consumedScroll, int layoutWidth, int layoutHeight, List<LazyListPositionedItem> positionedItems, LazyMeasuredItemProvider itemProvider) {
        boolean z;
        boolean inProgress;
        boolean z2;
        int previousFirstVisibleIndex;
        boolean z3;
        int i;
        Intrinsics.checkNotNullParameter(positionedItems, "positionedItems");
        Intrinsics.checkNotNullParameter(itemProvider, "itemProvider");
        int index$iv$iv = 0;
        int size = positionedItems.size();
        while (true) {
            if (index$iv$iv < size) {
                Object item$iv$iv = positionedItems.get(index$iv$iv);
                LazyListPositionedItem it = (LazyListPositionedItem) item$iv$iv;
                if (it.getHasAnimations()) {
                    z = true;
                    break;
                }
                index$iv$iv++;
            } else {
                z = false;
                break;
            }
        }
        if (!z && this.keyToItemInfoMap.isEmpty()) {
            reset();
            return;
        }
        int previousFirstVisibleIndex2 = this.firstVisibleIndex;
        LazyListPositionedItem lazyListPositionedItem = (LazyListPositionedItem) CollectionsKt.firstOrNull((List<? extends Object>) positionedItems);
        this.firstVisibleIndex = lazyListPositionedItem != null ? lazyListPositionedItem.getIndex() : 0;
        final Map previousKeyToIndexMap = this.keyToIndexMap;
        this.keyToIndexMap = itemProvider.getKeyToIndexMap();
        int mainAxisLayoutSize = this.isVertical ? layoutHeight : layoutWidth;
        long notAnimatableDelta = m518toOffsetBjo55l4(consumedScroll);
        this.movingAwayKeys.addAll(this.keyToItemInfoMap.keySet());
        List $this$fastForEach$iv = positionedItems;
        boolean z4 = false;
        int index$iv = 0;
        int size2 = $this$fastForEach$iv.size();
        while (index$iv < size2) {
            Object item$iv = $this$fastForEach$iv.get(index$iv);
            LazyListPositionedItem item = (LazyListPositionedItem) item$iv;
            List $this$fastForEach$iv2 = $this$fastForEach$iv;
            this.movingAwayKeys.remove(item.getKey());
            if (item.getHasAnimations()) {
                ItemInfo itemInfo = this.keyToItemInfoMap.get(item.getKey());
                if (itemInfo == null) {
                    Integer previousIndex = previousKeyToIndexMap.get(item.getKey());
                    if (previousIndex != null) {
                        z3 = z4;
                        int $i$f$fastForEach = item.getIndex();
                        i = size2;
                        if ($i$f$fastForEach != previousIndex.intValue()) {
                            if (previousIndex.intValue() < previousFirstVisibleIndex2) {
                                this.movingInFromStartBound.add(item);
                                previousFirstVisibleIndex = previousFirstVisibleIndex2;
                            } else {
                                this.movingInFromEndBound.add(item);
                                previousFirstVisibleIndex = previousFirstVisibleIndex2;
                            }
                        }
                    } else {
                        z3 = z4;
                        i = size2;
                    }
                    previousFirstVisibleIndex = previousFirstVisibleIndex2;
                    this.keyToItemInfoMap.put(item.getKey(), createItemInfo$default(this, item, 0, 2, null));
                } else {
                    previousFirstVisibleIndex = previousFirstVisibleIndex2;
                    z3 = z4;
                    i = size2;
                    long arg0$iv = itemInfo.m515getNotAnimatableDeltanOccac();
                    itemInfo.m516setNotAnimatableDeltagyyYBs(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(arg0$iv) + IntOffset.m5240getXimpl(notAnimatableDelta), IntOffset.m5241getYimpl(arg0$iv) + IntOffset.m5241getYimpl(notAnimatableDelta)));
                    startAnimationsIfNeeded(item, itemInfo);
                }
            } else {
                previousFirstVisibleIndex = previousFirstVisibleIndex2;
                z3 = z4;
                i = size2;
                this.keyToItemInfoMap.remove(item.getKey());
            }
            index$iv++;
            $this$fastForEach$iv = $this$fastForEach$iv2;
            z4 = z3;
            size2 = i;
            previousFirstVisibleIndex2 = previousFirstVisibleIndex;
        }
        int currentMainAxisOffset = 0;
        List $this$sortByDescending$iv = this.movingInFromStartBound;
        if ($this$sortByDescending$iv.size() > 1) {
            CollectionsKt.sortWith($this$sortByDescending$iv, new Comparator() { // from class: androidx.compose.foundation.lazy.LazyListItemPlacementAnimator$onMeasured$$inlined$sortByDescending$1
                @Override // java.util.Comparator
                public final int compare(T t, T t2) {
                    LazyListPositionedItem it2 = (LazyListPositionedItem) t2;
                    LazyListPositionedItem it3 = (LazyListPositionedItem) t;
                    return ComparisonsKt.compareValues((Integer) previousKeyToIndexMap.get(it2.getKey()), (Integer) previousKeyToIndexMap.get(it3.getKey()));
                }
            });
        }
        List $this$fastForEach$iv3 = this.movingInFromStartBound;
        boolean z5 = false;
        int index$iv2 = 0;
        int size3 = $this$fastForEach$iv3.size();
        while (index$iv2 < size3) {
            Object item$iv2 = $this$fastForEach$iv3.get(index$iv2);
            LazyListPositionedItem item2 = (LazyListPositionedItem) item$iv2;
            int mainAxisOffset = (0 - currentMainAxisOffset) - item2.getSize();
            int currentMainAxisOffset2 = currentMainAxisOffset + item2.getSize();
            ItemInfo itemInfo2 = createItemInfo(item2, mainAxisOffset);
            this.keyToItemInfoMap.put(item2.getKey(), itemInfo2);
            startAnimationsIfNeeded(item2, itemInfo2);
            index$iv2++;
            currentMainAxisOffset = currentMainAxisOffset2;
            $this$fastForEach$iv3 = $this$fastForEach$iv3;
            z5 = z5;
        }
        int currentMainAxisOffset3 = 0;
        List $this$sortBy$iv = this.movingInFromEndBound;
        if ($this$sortBy$iv.size() > 1) {
            CollectionsKt.sortWith($this$sortBy$iv, new Comparator() { // from class: androidx.compose.foundation.lazy.LazyListItemPlacementAnimator$onMeasured$$inlined$sortBy$1
                @Override // java.util.Comparator
                public final int compare(T t, T t2) {
                    LazyListPositionedItem it2 = (LazyListPositionedItem) t;
                    LazyListPositionedItem it3 = (LazyListPositionedItem) t2;
                    return ComparisonsKt.compareValues((Integer) previousKeyToIndexMap.get(it2.getKey()), (Integer) previousKeyToIndexMap.get(it3.getKey()));
                }
            });
        }
        List $this$fastForEach$iv4 = this.movingInFromEndBound;
        boolean z6 = false;
        int index$iv3 = 0;
        int size4 = $this$fastForEach$iv4.size();
        while (index$iv3 < size4) {
            Object item$iv3 = $this$fastForEach$iv4.get(index$iv3);
            LazyListPositionedItem item3 = (LazyListPositionedItem) item$iv3;
            int mainAxisOffset2 = mainAxisLayoutSize + currentMainAxisOffset3;
            int currentMainAxisOffset4 = currentMainAxisOffset3 + item3.getSize();
            ItemInfo itemInfo3 = createItemInfo(item3, mainAxisOffset2);
            this.keyToItemInfoMap.put(item3.getKey(), itemInfo3);
            startAnimationsIfNeeded(item3, itemInfo3);
            index$iv3++;
            currentMainAxisOffset3 = currentMainAxisOffset4;
            $this$fastForEach$iv4 = $this$fastForEach$iv4;
            z6 = z6;
        }
        Iterable $this$forEach$iv = this.movingAwayKeys;
        boolean z7 = false;
        for (Object element$iv : $this$forEach$iv) {
            ItemInfo itemInfo4 = (ItemInfo) MapsKt.getValue(this.keyToItemInfoMap, element$iv);
            Integer newIndex = this.keyToIndexMap.get(element$iv);
            List $this$fastForEach$iv$iv = itemInfo4.getPlaceables();
            int currentMainAxisOffset5 = currentMainAxisOffset3;
            int currentMainAxisOffset6 = $this$fastForEach$iv$iv.size();
            Iterable $this$forEach$iv2 = $this$forEach$iv;
            int index$iv$iv2 = 0;
            while (true) {
                if (index$iv$iv2 < currentMainAxisOffset6) {
                    int i2 = currentMainAxisOffset6;
                    List $this$fastForEach$iv$iv2 = $this$fastForEach$iv$iv;
                    Object item$iv$iv2 = $this$fastForEach$iv$iv2.get(index$iv$iv2);
                    PlaceableInfo it2 = (PlaceableInfo) item$iv$iv2;
                    if (it2.getInProgress()) {
                        inProgress = true;
                        break;
                    }
                    index$iv$iv2++;
                    $this$fastForEach$iv$iv = $this$fastForEach$iv$iv2;
                    currentMainAxisOffset6 = i2;
                } else {
                    inProgress = false;
                    break;
                }
            }
            if (itemInfo4.getPlaceables().isEmpty()) {
                z2 = z7;
            } else if (newIndex == null) {
                z2 = z7;
            } else if (!inProgress && Intrinsics.areEqual(newIndex, previousKeyToIndexMap.get(element$iv))) {
                z2 = z7;
            } else if (inProgress || isWithinBounds(itemInfo4, mainAxisLayoutSize)) {
                LazyMeasuredItem item4 = itemProvider.m535getAndMeasureZjPyQlc(DataIndex.m503constructorimpl(newIndex.intValue()));
                int intValue = newIndex.intValue();
                z2 = z7;
                int $i$f$forEach = this.firstVisibleIndex;
                if (intValue < $i$f$forEach) {
                    this.movingAwayToStartBound.add(item4);
                } else {
                    this.movingAwayToEndBound.add(item4);
                }
                z7 = z2;
                currentMainAxisOffset3 = currentMainAxisOffset5;
                $this$forEach$iv = $this$forEach$iv2;
            } else {
                z2 = z7;
            }
            this.keyToItemInfoMap.remove(element$iv);
            z7 = z2;
            currentMainAxisOffset3 = currentMainAxisOffset5;
            $this$forEach$iv = $this$forEach$iv2;
        }
        int currentMainAxisOffset7 = 0;
        List $this$sortByDescending$iv2 = this.movingAwayToStartBound;
        if ($this$sortByDescending$iv2.size() > 1) {
            CollectionsKt.sortWith($this$sortByDescending$iv2, new Comparator() { // from class: androidx.compose.foundation.lazy.LazyListItemPlacementAnimator$onMeasured$$inlined$sortByDescending$2
                @Override // java.util.Comparator
                public final int compare(T t, T t2) {
                    Map map;
                    Map map2;
                    LazyMeasuredItem it3 = (LazyMeasuredItem) t2;
                    map = LazyListItemPlacementAnimator.this.keyToIndexMap;
                    LazyMeasuredItem it4 = (LazyMeasuredItem) t;
                    map2 = LazyListItemPlacementAnimator.this.keyToIndexMap;
                    return ComparisonsKt.compareValues((Integer) map.get(it3.getKey()), (Integer) map2.get(it4.getKey()));
                }
            });
        }
        List $this$fastForEach$iv5 = this.movingAwayToStartBound;
        boolean z8 = false;
        int index$iv4 = 0;
        int size5 = $this$fastForEach$iv5.size();
        while (index$iv4 < size5) {
            Object item$iv4 = $this$fastForEach$iv5.get(index$iv4);
            LazyMeasuredItem item5 = (LazyMeasuredItem) item$iv4;
            int mainAxisOffset3 = (0 - currentMainAxisOffset7) - item5.getSize();
            int currentMainAxisOffset8 = currentMainAxisOffset7 + item5.getSize();
            List $this$fastForEach$iv6 = $this$fastForEach$iv5;
            ItemInfo itemInfo5 = (ItemInfo) MapsKt.getValue(this.keyToItemInfoMap, item5.getKey());
            LazyListPositionedItem positionedItem = item5.position(mainAxisOffset3, layoutWidth, layoutHeight);
            positionedItems.add(positionedItem);
            startAnimationsIfNeeded(positionedItem, itemInfo5);
            index$iv4++;
            currentMainAxisOffset7 = currentMainAxisOffset8;
            $this$fastForEach$iv5 = $this$fastForEach$iv6;
            z8 = z8;
        }
        int currentMainAxisOffset9 = 0;
        List $this$sortBy$iv2 = this.movingAwayToEndBound;
        if ($this$sortBy$iv2.size() > 1) {
            CollectionsKt.sortWith($this$sortBy$iv2, new Comparator() { // from class: androidx.compose.foundation.lazy.LazyListItemPlacementAnimator$onMeasured$$inlined$sortBy$2
                @Override // java.util.Comparator
                public final int compare(T t, T t2) {
                    Map map;
                    Map map2;
                    LazyMeasuredItem it3 = (LazyMeasuredItem) t;
                    map = LazyListItemPlacementAnimator.this.keyToIndexMap;
                    LazyMeasuredItem it4 = (LazyMeasuredItem) t2;
                    map2 = LazyListItemPlacementAnimator.this.keyToIndexMap;
                    return ComparisonsKt.compareValues((Integer) map.get(it3.getKey()), (Integer) map2.get(it4.getKey()));
                }
            });
        }
        List $this$fastForEach$iv7 = this.movingAwayToEndBound;
        int index$iv5 = 0;
        int size6 = $this$fastForEach$iv7.size();
        while (index$iv5 < size6) {
            Object item$iv5 = $this$fastForEach$iv7.get(index$iv5);
            LazyMeasuredItem item6 = (LazyMeasuredItem) item$iv5;
            List $this$fastForEach$iv8 = $this$fastForEach$iv7;
            int mainAxisOffset4 = mainAxisLayoutSize + currentMainAxisOffset9;
            int currentMainAxisOffset10 = currentMainAxisOffset9 + item6.getSize();
            Map previousKeyToIndexMap2 = previousKeyToIndexMap;
            ItemInfo itemInfo6 = (ItemInfo) MapsKt.getValue(this.keyToItemInfoMap, item6.getKey());
            LazyListPositionedItem positionedItem2 = item6.position(mainAxisOffset4, layoutWidth, layoutHeight);
            positionedItems.add(positionedItem2);
            startAnimationsIfNeeded(positionedItem2, itemInfo6);
            index$iv5++;
            $this$fastForEach$iv7 = $this$fastForEach$iv8;
            currentMainAxisOffset9 = currentMainAxisOffset10;
            previousKeyToIndexMap = previousKeyToIndexMap2;
        }
        this.movingInFromStartBound.clear();
        this.movingInFromEndBound.clear();
        this.movingAwayToStartBound.clear();
        this.movingAwayToEndBound.clear();
        this.movingAwayKeys.clear();
    }

    /* renamed from: getAnimatedOffset-YT5a7pE  reason: not valid java name */
    public final long m519getAnimatedOffsetYT5a7pE(Object key, int placeableIndex, int minOffset, int maxOffset, long rawOffset) {
        Intrinsics.checkNotNullParameter(key, "key");
        ItemInfo itemInfo = this.keyToItemInfoMap.get(key);
        if (itemInfo == null) {
            return rawOffset;
        }
        PlaceableInfo item = itemInfo.getPlaceables().get(placeableIndex);
        long arg0$iv = item.getAnimatedOffset().getValue().m5249unboximpl();
        long other$iv = itemInfo.m515getNotAnimatableDeltanOccac();
        long arg0$iv2 = IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(arg0$iv) + IntOffset.m5240getXimpl(other$iv), IntOffset.m5241getYimpl(arg0$iv) + IntOffset.m5241getYimpl(other$iv));
        long arg0$iv3 = item.m537getTargetOffsetnOccac();
        long other$iv2 = itemInfo.m515getNotAnimatableDeltanOccac();
        long arg0$iv4 = IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(arg0$iv3) + IntOffset.m5240getXimpl(other$iv2), IntOffset.m5241getYimpl(arg0$iv3) + IntOffset.m5241getYimpl(other$iv2));
        if (item.getInProgress() && ((m517getMainAxisgyyYBs(arg0$iv4) <= minOffset && m517getMainAxisgyyYBs(arg0$iv2) <= minOffset) || (m517getMainAxisgyyYBs(arg0$iv4) >= maxOffset && m517getMainAxisgyyYBs(arg0$iv2) >= maxOffset))) {
            BuildersKt.launch$default(this.scope, null, null, new LazyListItemPlacementAnimator$getAnimatedOffset$1(item, null), 3, null);
        }
        return arg0$iv2;
    }

    public final void reset() {
        this.keyToItemInfoMap.clear();
        this.keyToIndexMap = MapsKt.emptyMap();
        this.firstVisibleIndex = -1;
    }

    static /* synthetic */ ItemInfo createItemInfo$default(LazyListItemPlacementAnimator lazyListItemPlacementAnimator, LazyListPositionedItem lazyListPositionedItem, int i, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            i = lazyListItemPlacementAnimator.m517getMainAxisgyyYBs(lazyListPositionedItem.m528getOffsetBjo55l4(0));
        }
        return lazyListItemPlacementAnimator.createItemInfo(lazyListPositionedItem, i);
    }

    private final ItemInfo createItemInfo(LazyListPositionedItem item, int mainAxisOffset) {
        long targetFirstPlaceableOffset;
        ItemInfo newItemInfo = new ItemInfo();
        int i = 0;
        long firstPlaceableOffset = item.m528getOffsetBjo55l4(0);
        if (this.isVertical) {
            targetFirstPlaceableOffset = IntOffset.m5236copyiSbpLlY$default(firstPlaceableOffset, 0, mainAxisOffset, 1, null);
        } else {
            targetFirstPlaceableOffset = IntOffset.m5236copyiSbpLlY$default(firstPlaceableOffset, mainAxisOffset, 0, 2, null);
        }
        int placeablesCount = item.getPlaceablesCount();
        while (i < placeablesCount) {
            int placeableIndex = i;
            long arg0$iv = item.m528getOffsetBjo55l4(placeableIndex);
            long arg0$iv2 = IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(arg0$iv) - IntOffset.m5240getXimpl(firstPlaceableOffset), IntOffset.m5241getYimpl(arg0$iv) - IntOffset.m5241getYimpl(firstPlaceableOffset));
            newItemInfo.getPlaceables().add(new PlaceableInfo(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(targetFirstPlaceableOffset) + IntOffset.m5240getXimpl(arg0$iv2), IntOffset.m5241getYimpl(targetFirstPlaceableOffset) + IntOffset.m5241getYimpl(arg0$iv2)), item.getMainAxisSize(placeableIndex), null));
            i++;
            placeablesCount = placeablesCount;
            targetFirstPlaceableOffset = targetFirstPlaceableOffset;
        }
        return newItemInfo;
    }

    private final void startAnimationsIfNeeded(LazyListPositionedItem item, ItemInfo itemInfo) {
        Object obj;
        List $this$fastForEachIndexed$iv;
        LazyListPositionedItem lazyListPositionedItem = item;
        while (itemInfo.getPlaceables().size() > item.getPlaceablesCount()) {
            CollectionsKt.removeLast(itemInfo.getPlaceables());
        }
        while (itemInfo.getPlaceables().size() < item.getPlaceablesCount()) {
            int newPlaceableInfoIndex = itemInfo.getPlaceables().size();
            long rawOffset = lazyListPositionedItem.m528getOffsetBjo55l4(newPlaceableInfoIndex);
            List<PlaceableInfo> placeables = itemInfo.getPlaceables();
            long other$iv = itemInfo.m515getNotAnimatableDeltanOccac();
            placeables.add(new PlaceableInfo(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(rawOffset) - IntOffset.m5240getXimpl(other$iv), IntOffset.m5241getYimpl(rawOffset) - IntOffset.m5241getYimpl(other$iv)), lazyListPositionedItem.getMainAxisSize(newPlaceableInfoIndex), null));
        }
        List $this$fastForEachIndexed$iv2 = itemInfo.getPlaceables();
        int index$iv = 0;
        int size = $this$fastForEachIndexed$iv2.size();
        while (index$iv < size) {
            Object item$iv = $this$fastForEachIndexed$iv2.get(index$iv);
            PlaceableInfo placeableInfo = (PlaceableInfo) item$iv;
            int index = index$iv;
            long arg0$iv = placeableInfo.m537getTargetOffsetnOccac();
            long other$iv2 = itemInfo.m515getNotAnimatableDeltanOccac();
            long arg0$iv2 = IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(arg0$iv) + IntOffset.m5240getXimpl(other$iv2), IntOffset.m5241getYimpl(arg0$iv) + IntOffset.m5241getYimpl(other$iv2));
            long currentOffset = lazyListPositionedItem.m528getOffsetBjo55l4(index);
            placeableInfo.setMainAxisSize(lazyListPositionedItem.getMainAxisSize(index));
            FiniteAnimationSpec animationSpec = lazyListPositionedItem.getAnimationSpec(index);
            if (IntOffset.m5239equalsimpl0(arg0$iv2, currentOffset)) {
                obj = null;
                $this$fastForEachIndexed$iv = $this$fastForEachIndexed$iv2;
            } else {
                long other$iv3 = itemInfo.m515getNotAnimatableDeltanOccac();
                $this$fastForEachIndexed$iv = $this$fastForEachIndexed$iv2;
                placeableInfo.m538setTargetOffsetgyyYBs(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(currentOffset) - IntOffset.m5240getXimpl(other$iv3), IntOffset.m5241getYimpl(currentOffset) - IntOffset.m5241getYimpl(other$iv3)));
                if (animationSpec == null) {
                    obj = null;
                } else {
                    placeableInfo.setInProgress(true);
                    obj = null;
                    BuildersKt.launch$default(this.scope, null, null, new LazyListItemPlacementAnimator$startAnimationsIfNeeded$1$1(placeableInfo, animationSpec, null), 3, null);
                }
            }
            index$iv++;
            lazyListPositionedItem = item;
            $this$fastForEachIndexed$iv2 = $this$fastForEachIndexed$iv;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0060 A[LOOP:0: B:3:0x0010->B:14:0x0060, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:18:0x006c A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final boolean isWithinBounds(androidx.compose.foundation.lazy.ItemInfo r23, int r24) {
        /*
            r22 = this;
            r0 = r22
            java.util.List r1 = r23.getPlaceables()
            r2 = 0
            r3 = r1
            r4 = 0
            r5 = 0
            int r6 = r3.size()
        L10:
            if (r5 >= r6) goto L66
            java.lang.Object r8 = r3.get(r5)
            r9 = r8
            r10 = 0
            r11 = r9
            androidx.compose.foundation.lazy.PlaceableInfo r11 = (androidx.compose.foundation.lazy.PlaceableInfo) r11
            r12 = 0
            long r13 = r11.m537getTargetOffsetnOccac()
            long r15 = r23.m515getNotAnimatableDeltanOccac()
            r17 = 0
            int r18 = androidx.compose.ui.unit.IntOffset.m5240getXimpl(r13)
            int r19 = androidx.compose.ui.unit.IntOffset.m5240getXimpl(r15)
            int r7 = r18 + r19
            int r18 = androidx.compose.ui.unit.IntOffset.m5241getYimpl(r13)
            int r19 = androidx.compose.ui.unit.IntOffset.m5241getYimpl(r15)
            r21 = r1
            int r1 = r18 + r19
            long r13 = androidx.compose.ui.unit.IntOffsetKt.IntOffset(r7, r1)
            int r1 = r0.m517getMainAxisgyyYBs(r13)
            int r7 = r11.getMainAxisSize()
            int r1 = r1 + r7
            r7 = 1
            if (r1 <= 0) goto L58
            int r1 = r0.m517getMainAxisgyyYBs(r13)
            r15 = r24
            if (r1 >= r15) goto L5a
            r20 = r7
            goto L5c
        L58:
            r15 = r24
        L5a:
            r20 = 0
        L5c:
            if (r20 == 0) goto L60
            goto L6c
        L60:
            int r5 = r5 + 1
            r1 = r21
            goto L10
        L66:
            r15 = r24
            r21 = r1
            r7 = 0
        L6c:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.lazy.LazyListItemPlacementAnimator.isWithinBounds(androidx.compose.foundation.lazy.ItemInfo, int):boolean");
    }

    /* renamed from: toOffset-Bjo55l4  reason: not valid java name */
    private final long m518toOffsetBjo55l4(int $this$toOffset_u2dBjo55l4) {
        boolean z = this.isVertical;
        return IntOffsetKt.IntOffset(z ? 0 : $this$toOffset_u2dBjo55l4, z ? $this$toOffset_u2dBjo55l4 : 0);
    }

    /* renamed from: getMainAxis--gyyYBs  reason: not valid java name */
    private final int m517getMainAxisgyyYBs(long $this$mainAxis) {
        return this.isVertical ? IntOffset.m5241getYimpl($this$mainAxis) : IntOffset.m5240getXimpl($this$mainAxis);
    }
}
