package androidx.compose.foundation.lazy.grid;

import androidx.compose.animation.core.FiniteAnimationSpec;
import androidx.compose.ui.layout.Placeable;
import androidx.compose.ui.unit.IntOffset;
import androidx.compose.ui.unit.IntOffsetKt;
import androidx.compose.ui.unit.IntSize;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: LazyGridMeasuredItem.kt */
@Metadata(d1 = {"\u0000\\\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0017\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\b\u0000\u0018\u00002\u00020\u0001B~\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u0012\u0006\u0010\b\u001a\u00020\u0005\u0012\u0006\u0010\t\u001a\u00020\u0005\u0012\u0006\u0010\n\u001a\u00020\u000b\u0012\u0006\u0010\f\u001a\u00020\u0005\u0012\u0006\u0010\r\u001a\u00020\u0005\u0012\u0006\u0010\u000e\u001a\u00020\u000f\u0012\f\u0010\u0010\u001a\b\u0012\u0004\u0012\u00020\u00120\u0011\u0012\u0006\u0010\u0013\u001a\u00020\u0014\u0012\u0006\u0010\u0015\u001a\u00020\u0003\u0012\u0006\u0010\u0016\u001a\u00020\u0005\u0012\u0006\u0010\u0017\u001a\u00020\u000fø\u0001\u0000¢\u0006\u0002\u0010\u0018J\u0019\u0010+\u001a\n\u0012\u0004\u0012\u00020\u0003\u0018\u00010,2\u0006\u0010\u0004\u001a\u00020\u0005ø\u0001\u0000J\u0006\u0010-\u001a\u00020\u0005J\u0006\u0010.\u001a\u00020\u0005J\u0006\u0010)\u001a\u00020\u0005J\u000e\u0010)\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0005J\u000e\u0010/\u001a\u0002002\u0006\u00101\u001a\u000202J.\u00103\u001a\u00020\u0003*\u00020\u00032\u0012\u00104\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u000505H\u0082\bø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b6\u00107R\u0014\u0010\t\u001a\u00020\u0005X\u0096\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0019\u0010\u001aR\u0011\u0010\u001b\u001a\u00020\u000f¢\u0006\b\n\u0000\u001a\u0004\b\u001c\u0010\u001dR\u0014\u0010\u0004\u001a\u00020\u0005X\u0096\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u001e\u0010\u001aR\u000e\u0010\u000e\u001a\u00020\u000fX\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010\u0006\u001a\u00020\u0007X\u0096\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u001f\u0010 R\u000e\u0010\u0016\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\r\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\f\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000R\u001f\u0010\u0002\u001a\u00020\u0003X\u0096\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010#\u001a\u0004\b!\u0010\"R\u0014\u0010\u0010\u001a\b\u0012\u0004\u0012\u00020\u00120\u0011X\u0082\u0004¢\u0006\u0002\n\u0000R\u0011\u0010$\u001a\u00020\u00058F¢\u0006\u0006\u001a\u0004\b%\u0010\u001aR\u000e\u0010\u0013\u001a\u00020\u0014X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0017\u001a\u00020\u000fX\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010\b\u001a\u00020\u0005X\u0096\u0004¢\u0006\b\n\u0000\u001a\u0004\b&\u0010\u001aR\u001f\u0010\n\u001a\u00020\u000bX\u0096\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010#\u001a\u0004\b'\u0010\"R\u0019\u0010\u0015\u001a\u00020\u0003X\u0082\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\n\u0002\u0010#R\u0018\u0010(\u001a\u00020\u0005*\u00020\u00128BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b)\u0010*\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u00068"}, d2 = {"Landroidx/compose/foundation/lazy/grid/LazyGridPositionedItem;", "Landroidx/compose/foundation/lazy/grid/LazyGridItemInfo;", "offset", "Landroidx/compose/ui/unit/IntOffset;", "index", "", "key", "", "row", "column", "size", "Landroidx/compose/ui/unit/IntSize;", "minMainAxisOffset", "maxMainAxisOffset", "isVertical", "", "placeables", "", "Landroidx/compose/ui/layout/Placeable;", "placementAnimator", "Landroidx/compose/foundation/lazy/grid/LazyGridItemPlacementAnimator;", "visualOffset", "mainAxisLayoutSize", "reverseLayout", "(JILjava/lang/Object;IIJIIZLjava/util/List;Landroidx/compose/foundation/lazy/grid/LazyGridItemPlacementAnimator;JIZLkotlin/jvm/internal/DefaultConstructorMarker;)V", "getColumn", "()I", "hasAnimations", "getHasAnimations", "()Z", "getIndex", "getKey", "()Ljava/lang/Object;", "getOffset-nOcc-ac", "()J", "J", "placeablesCount", "getPlaceablesCount", "getRow", "getSize-YbymL2g", "mainAxisSize", "getMainAxisSize", "(Landroidx/compose/ui/layout/Placeable;)I", "getAnimationSpec", "Landroidx/compose/animation/core/FiniteAnimationSpec;", "getCrossAxisOffset", "getCrossAxisSize", "place", "", "scope", "Landroidx/compose/ui/layout/Placeable$PlacementScope;", "copy", "mainAxisMap", "Lkotlin/Function1;", "copy-4Tuh3kE", "(JLkotlin/jvm/functions/Function1;)J", "foundation_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LazyGridPositionedItem implements LazyGridItemInfo {
    private final int column;
    private final boolean hasAnimations;
    private final int index;
    private final boolean isVertical;
    private final Object key;
    private final int mainAxisLayoutSize;
    private final int maxMainAxisOffset;
    private final int minMainAxisOffset;
    private final long offset;
    private final List<Placeable> placeables;
    private final LazyGridItemPlacementAnimator placementAnimator;
    private final boolean reverseLayout;
    private final int row;
    private final long size;
    private final long visualOffset;

    public /* synthetic */ LazyGridPositionedItem(long j, int i, Object obj, int i2, int i3, long j2, int i4, int i5, boolean z, List list, LazyGridItemPlacementAnimator lazyGridItemPlacementAnimator, long j3, int i6, boolean z2, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, i, obj, i2, i3, j2, i4, i5, z, list, lazyGridItemPlacementAnimator, j3, i6, z2);
    }

    /* JADX WARN: Multi-variable type inference failed */
    private LazyGridPositionedItem(long offset, int index, Object key, int row, int column, long size, int minMainAxisOffset, int maxMainAxisOffset, boolean isVertical, List<? extends Placeable> list, LazyGridItemPlacementAnimator placementAnimator, long visualOffset, int mainAxisLayoutSize, boolean reverseLayout) {
        boolean z;
        this.offset = offset;
        this.index = index;
        this.key = key;
        this.row = row;
        this.column = column;
        this.size = size;
        this.minMainAxisOffset = minMainAxisOffset;
        this.maxMainAxisOffset = maxMainAxisOffset;
        this.isVertical = isVertical;
        this.placeables = list;
        this.placementAnimator = placementAnimator;
        this.visualOffset = visualOffset;
        this.mainAxisLayoutSize = mainAxisLayoutSize;
        this.reverseLayout = reverseLayout;
        LazyGridPositionedItem $this$hasAnimations_u24lambda_u241 = this;
        int placeablesCount = $this$hasAnimations_u24lambda_u241.getPlaceablesCount();
        int i = 0;
        while (true) {
            if (i < placeablesCount) {
                int index2 = i;
                int i2 = placeablesCount;
                if ($this$hasAnimations_u24lambda_u241.getAnimationSpec(index2) == null) {
                    i++;
                    placeablesCount = i2;
                } else {
                    z = true;
                    break;
                }
            } else {
                z = false;
                break;
            }
        }
        this.hasAnimations = z;
    }

    @Override // androidx.compose.foundation.lazy.grid.LazyGridItemInfo
    /* renamed from: getOffset-nOcc-ac */
    public long mo569getOffsetnOccac() {
        return this.offset;
    }

    @Override // androidx.compose.foundation.lazy.grid.LazyGridItemInfo
    public int getIndex() {
        return this.index;
    }

    @Override // androidx.compose.foundation.lazy.grid.LazyGridItemInfo
    public Object getKey() {
        return this.key;
    }

    @Override // androidx.compose.foundation.lazy.grid.LazyGridItemInfo
    public int getRow() {
        return this.row;
    }

    @Override // androidx.compose.foundation.lazy.grid.LazyGridItemInfo
    public int getColumn() {
        return this.column;
    }

    @Override // androidx.compose.foundation.lazy.grid.LazyGridItemInfo
    /* renamed from: getSize-YbymL2g */
    public long mo570getSizeYbymL2g() {
        return this.size;
    }

    public final int getPlaceablesCount() {
        return this.placeables.size();
    }

    public final int getMainAxisSize(int index) {
        return getMainAxisSize(this.placeables.get(index));
    }

    public final int getMainAxisSize() {
        return this.isVertical ? IntSize.m5281getHeightimpl(mo570getSizeYbymL2g()) : IntSize.m5282getWidthimpl(mo570getSizeYbymL2g());
    }

    public final int getCrossAxisSize() {
        return this.isVertical ? IntSize.m5282getWidthimpl(mo570getSizeYbymL2g()) : IntSize.m5281getHeightimpl(mo570getSizeYbymL2g());
    }

    public final int getCrossAxisOffset() {
        return this.isVertical ? IntOffset.m5240getXimpl(mo569getOffsetnOccac()) : IntOffset.m5241getYimpl(mo569getOffsetnOccac());
    }

    public final FiniteAnimationSpec<IntOffset> getAnimationSpec(int index) {
        Object parentData = this.placeables.get(index).getParentData();
        if (parentData instanceof FiniteAnimationSpec) {
            return (FiniteAnimationSpec) parentData;
        }
        return null;
    }

    public final boolean getHasAnimations() {
        return this.hasAnimations;
    }

    public final void place(Placeable.PlacementScope scope) {
        int i;
        long $this$copy_u2d4Tuh3kE$iv;
        int mainAxisOffset;
        int m5241getYimpl;
        Intrinsics.checkNotNullParameter(scope, "scope");
        int i2 = 0;
        int placeablesCount = getPlaceablesCount();
        int i3 = 0;
        while (i3 < placeablesCount) {
            int index = i3;
            Placeable placeable = this.placeables.get(index);
            int minOffset = this.minMainAxisOffset - getMainAxisSize(placeable);
            int maxOffset = this.maxMainAxisOffset;
            long offset = getAnimationSpec(index) != null ? this.placementAnimator.m573getAnimatedOffsetYT5a7pE(getKey(), index, minOffset, maxOffset, mo569getOffsetnOccac()) : mo569getOffsetnOccac();
            if (!this.reverseLayout) {
                i = i2;
                $this$copy_u2d4Tuh3kE$iv = offset;
            } else {
                if (this.isVertical) {
                    mainAxisOffset = IntOffset.m5240getXimpl(offset);
                } else {
                    int mainAxisOffset2 = IntOffset.m5240getXimpl(offset);
                    mainAxisOffset = (this.mainAxisLayoutSize - mainAxisOffset2) - getMainAxisSize(placeable);
                }
                if (this.isVertical) {
                    int mainAxisOffset3 = IntOffset.m5241getYimpl(offset);
                    i = i2;
                    m5241getYimpl = (this.mainAxisLayoutSize - mainAxisOffset3) - getMainAxisSize(placeable);
                } else {
                    i = i2;
                    m5241getYimpl = IntOffset.m5241getYimpl(offset);
                }
                $this$copy_u2d4Tuh3kE$iv = IntOffsetKt.IntOffset(mainAxisOffset, m5241getYimpl);
            }
            long reverseLayoutAwareOffset = $this$copy_u2d4Tuh3kE$iv;
            if (this.isVertical) {
                long other$iv = this.visualOffset;
                Placeable.PlacementScope.m4176placeWithLayeraW9wM$default(scope, placeable, IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(reverseLayoutAwareOffset) + IntOffset.m5240getXimpl(other$iv), IntOffset.m5241getYimpl(reverseLayoutAwareOffset) + IntOffset.m5241getYimpl(other$iv)), 0.0f, null, 6, null);
            } else {
                long other$iv2 = this.visualOffset;
                Placeable.PlacementScope.m4175placeRelativeWithLayeraW9wM$default(scope, placeable, IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(reverseLayoutAwareOffset) + IntOffset.m5240getXimpl(other$iv2), IntOffset.m5241getYimpl(reverseLayoutAwareOffset) + IntOffset.m5241getYimpl(other$iv2)), 0.0f, null, 6, null);
            }
            i3++;
            i2 = i;
        }
    }

    private final int getMainAxisSize(Placeable $this$mainAxisSize) {
        return this.isVertical ? $this$mainAxisSize.getHeight() : $this$mainAxisSize.getWidth();
    }

    /* renamed from: copy-4Tuh3kE  reason: not valid java name */
    private final long m582copy4Tuh3kE(long $this$copy_u2d4Tuh3kE, Function1<? super Integer, Integer> function1) {
        return IntOffsetKt.IntOffset(this.isVertical ? IntOffset.m5240getXimpl($this$copy_u2d4Tuh3kE) : function1.invoke(Integer.valueOf(IntOffset.m5240getXimpl($this$copy_u2d4Tuh3kE))).intValue(), this.isVertical ? function1.invoke(Integer.valueOf(IntOffset.m5241getYimpl($this$copy_u2d4Tuh3kE))).intValue() : IntOffset.m5241getYimpl($this$copy_u2d4Tuh3kE));
    }
}
