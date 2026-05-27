package androidx.compose.foundation.lazy.layout;

import androidx.compose.foundation.gestures.Orientation;
import androidx.compose.foundation.lazy.LazyListBeyondBoundsInfo;
import androidx.compose.ui.layout.BeyondBoundsLayout;
import androidx.compose.ui.layout.BeyondBoundsLayoutKt;
import androidx.compose.ui.modifier.ModifierLocalProvider;
import androidx.compose.ui.modifier.ProvidableModifierLocal;
import androidx.compose.ui.unit.LayoutDirection;
import kotlin.KotlinNothingValueException;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Ref;
/* compiled from: LazyLayoutBeyondBoundsModifierLocal.kt */
@Metadata(d1 = {"\u0000V\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\n\b\u0000\u0018\u0000 *2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u00012\u00020\u0002:\u0001*B-\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\u0006\u0010\u0007\u001a\u00020\b\u0012\u0006\u0010\t\u001a\u00020\n\u0012\u0006\u0010\u000b\u001a\u00020\f¢\u0006\u0002\u0010\rJ%\u0010\u0015\u001a\u00020\u00162\u0006\u0010\u0017\u001a\u00020\u00162\u0006\u0010\u0018\u001a\u00020\u0019H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001a\u0010\u001bJ@\u0010\u001c\u001a\u0004\u0018\u0001H\u001d\"\u0004\b\u0000\u0010\u001d2\u0006\u0010\u0018\u001a\u00020\u00192\u0019\u0010\u001e\u001a\u0015\u0012\u0004\u0012\u00020 \u0012\u0006\u0012\u0004\u0018\u0001H\u001d0\u001f¢\u0006\u0002\b!H\u0016ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\"\u0010#J!\u0010$\u001a\u00020\b*\u00020\u00162\u0006\u0010\u0018\u001a\u00020\u0019H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b%\u0010&J\u0019\u0010'\u001a\u00020\b*\u00020\u0019H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b(\u0010)R\u000e\u0010\u0005\u001a\u00020\u0006X\u0082\u0004¢\u0006\u0002\n\u0000R\u001c\u0010\u000e\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u000f8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0010\u0010\u0011R\u000e\u0010\t\u001a\u00020\nX\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u000b\u001a\u00020\fX\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\bX\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010\u0012\u001a\u00020\u00028VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0013\u0010\u0014\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006+"}, d2 = {"Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierLocal;", "Landroidx/compose/ui/modifier/ModifierLocalProvider;", "Landroidx/compose/ui/layout/BeyondBoundsLayout;", "state", "Landroidx/compose/foundation/lazy/layout/BeyondBoundsState;", "beyondBoundsInfo", "Landroidx/compose/foundation/lazy/LazyListBeyondBoundsInfo;", "reverseLayout", "", "layoutDirection", "Landroidx/compose/ui/unit/LayoutDirection;", "orientation", "Landroidx/compose/foundation/gestures/Orientation;", "(Landroidx/compose/foundation/lazy/layout/BeyondBoundsState;Landroidx/compose/foundation/lazy/LazyListBeyondBoundsInfo;ZLandroidx/compose/ui/unit/LayoutDirection;Landroidx/compose/foundation/gestures/Orientation;)V", "key", "Landroidx/compose/ui/modifier/ProvidableModifierLocal;", "getKey", "()Landroidx/compose/ui/modifier/ProvidableModifierLocal;", "value", "getValue", "()Landroidx/compose/ui/layout/BeyondBoundsLayout;", "addNextInterval", "Landroidx/compose/foundation/lazy/LazyListBeyondBoundsInfo$Interval;", "currentInterval", "direction", "Landroidx/compose/ui/layout/BeyondBoundsLayout$LayoutDirection;", "addNextInterval-FR3nfPY", "(Landroidx/compose/foundation/lazy/LazyListBeyondBoundsInfo$Interval;I)Landroidx/compose/foundation/lazy/LazyListBeyondBoundsInfo$Interval;", "layout", "T", "block", "Lkotlin/Function1;", "Landroidx/compose/ui/layout/BeyondBoundsLayout$BeyondBoundsScope;", "Lkotlin/ExtensionFunctionType;", "layout-o7g1Pn8", "(ILkotlin/jvm/functions/Function1;)Ljava/lang/Object;", "hasMoreContent", "hasMoreContent-FR3nfPY", "(Landroidx/compose/foundation/lazy/LazyListBeyondBoundsInfo$Interval;I)Z", "isOppositeToOrientation", "isOppositeToOrientation-4vf7U8o", "(I)Z", "Companion", "foundation_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LazyLayoutBeyondBoundsModifierLocal implements ModifierLocalProvider<BeyondBoundsLayout>, BeyondBoundsLayout {
    public static final Companion Companion = new Companion(null);
    private static final LazyLayoutBeyondBoundsModifierLocal$Companion$emptyBeyondBoundsScope$1 emptyBeyondBoundsScope = new BeyondBoundsLayout.BeyondBoundsScope() { // from class: androidx.compose.foundation.lazy.layout.LazyLayoutBeyondBoundsModifierLocal$Companion$emptyBeyondBoundsScope$1
        private final boolean hasMoreContent;

        @Override // androidx.compose.ui.layout.BeyondBoundsLayout.BeyondBoundsScope
        public boolean getHasMoreContent() {
            return this.hasMoreContent;
        }
    };
    private final LazyListBeyondBoundsInfo beyondBoundsInfo;
    private final LayoutDirection layoutDirection;
    private final Orientation orientation;
    private final boolean reverseLayout;
    private final BeyondBoundsState state;

    /* compiled from: LazyLayoutBeyondBoundsModifierLocal.kt */
    @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[LayoutDirection.values().length];
            try {
                iArr[LayoutDirection.Ltr.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                iArr[LayoutDirection.Rtl.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            $EnumSwitchMapping$0 = iArr;
        }
    }

    public LazyLayoutBeyondBoundsModifierLocal(BeyondBoundsState state, LazyListBeyondBoundsInfo beyondBoundsInfo, boolean reverseLayout, LayoutDirection layoutDirection, Orientation orientation) {
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(beyondBoundsInfo, "beyondBoundsInfo");
        Intrinsics.checkNotNullParameter(layoutDirection, "layoutDirection");
        Intrinsics.checkNotNullParameter(orientation, "orientation");
        this.state = state;
        this.beyondBoundsInfo = beyondBoundsInfo;
        this.reverseLayout = reverseLayout;
        this.layoutDirection = layoutDirection;
        this.orientation = orientation;
    }

    @Override // androidx.compose.ui.modifier.ModifierLocalProvider
    public ProvidableModifierLocal<BeyondBoundsLayout> getKey() {
        return BeyondBoundsLayoutKt.getModifierLocalBeyondBoundsLayout();
    }

    /* compiled from: LazyLayoutBeyondBoundsModifierLocal.kt */
    @Metadata(d1 = {"\u0000\u0013\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\b\u0003*\u0001\u0004\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u0010\u0010\u0003\u001a\u00020\u0004X\u0082\u0004¢\u0006\u0004\n\u0002\u0010\u0005¨\u0006\u0006"}, d2 = {"Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierLocal$Companion;", "", "()V", "emptyBeyondBoundsScope", "androidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierLocal$Companion$emptyBeyondBoundsScope$1", "Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierLocal$Companion$emptyBeyondBoundsScope$1;", "foundation_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // androidx.compose.ui.modifier.ModifierLocalProvider
    public BeyondBoundsLayout getValue() {
        return this;
    }

    @Override // androidx.compose.ui.layout.BeyondBoundsLayout
    /* renamed from: layout-o7g1Pn8  reason: not valid java name */
    public <T> T mo615layouto7g1Pn8(final int direction, Function1<? super BeyondBoundsLayout.BeyondBoundsScope, ? extends T> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        if (this.state.getItemCount() <= 0 || !this.state.getHasVisibleItems()) {
            return block.invoke(emptyBeyondBoundsScope);
        }
        final Ref.ObjectRef interval = new Ref.ObjectRef();
        interval.element = (T) this.beyondBoundsInfo.addInterval(this.state.getFirstVisibleIndex(), this.state.getLastVisibleIndex());
        T t = null;
        while (t == null && m613hasMoreContentFR3nfPY((LazyListBeyondBoundsInfo.Interval) interval.element, direction)) {
            this.beyondBoundsInfo.removeInterval((LazyListBeyondBoundsInfo.Interval) interval.element);
            interval.element = (T) m612addNextIntervalFR3nfPY((LazyListBeyondBoundsInfo.Interval) interval.element, direction);
            this.state.remeasure();
            t = block.invoke(new BeyondBoundsLayout.BeyondBoundsScope() { // from class: androidx.compose.foundation.lazy.layout.LazyLayoutBeyondBoundsModifierLocal$layout$2
                @Override // androidx.compose.ui.layout.BeyondBoundsLayout.BeyondBoundsScope
                public boolean getHasMoreContent() {
                    boolean m613hasMoreContentFR3nfPY;
                    m613hasMoreContentFR3nfPY = LazyLayoutBeyondBoundsModifierLocal.this.m613hasMoreContentFR3nfPY(interval.element, direction);
                    return m613hasMoreContentFR3nfPY;
                }
            });
        }
        this.beyondBoundsInfo.removeInterval((LazyListBeyondBoundsInfo.Interval) interval.element);
        this.state.remeasure();
        return t;
    }

    /* renamed from: addNextInterval-FR3nfPY  reason: not valid java name */
    private final LazyListBeyondBoundsInfo.Interval m612addNextIntervalFR3nfPY(LazyListBeyondBoundsInfo.Interval currentInterval, int direction) {
        int start = currentInterval.getStart();
        int end = currentInterval.getEnd();
        if (BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0(direction, BeyondBoundsLayout.LayoutDirection.Companion.m4111getBeforehoxUOeE())) {
            start--;
        } else if (BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0(direction, BeyondBoundsLayout.LayoutDirection.Companion.m4110getAfterhoxUOeE())) {
            end++;
        } else if (BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0(direction, BeyondBoundsLayout.LayoutDirection.Companion.m4109getAbovehoxUOeE())) {
            if (this.reverseLayout) {
                end++;
            } else {
                start--;
            }
        } else if (BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0(direction, BeyondBoundsLayout.LayoutDirection.Companion.m4112getBelowhoxUOeE())) {
            if (this.reverseLayout) {
                start--;
            } else {
                end++;
            }
        } else if (BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0(direction, BeyondBoundsLayout.LayoutDirection.Companion.m4113getLefthoxUOeE())) {
            switch (WhenMappings.$EnumSwitchMapping$0[this.layoutDirection.ordinal()]) {
                case 1:
                    if (!this.reverseLayout) {
                        start--;
                        break;
                    } else {
                        end++;
                        break;
                    }
                case 2:
                    if (!this.reverseLayout) {
                        end++;
                        break;
                    } else {
                        start--;
                        break;
                    }
            }
        } else if (!BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0(direction, BeyondBoundsLayout.LayoutDirection.Companion.m4114getRighthoxUOeE())) {
            LazyLayoutBeyondBoundsModifierLocalKt.unsupportedDirection();
            throw new KotlinNothingValueException();
        } else {
            switch (WhenMappings.$EnumSwitchMapping$0[this.layoutDirection.ordinal()]) {
                case 1:
                    if (!this.reverseLayout) {
                        end++;
                        break;
                    } else {
                        start--;
                        break;
                    }
                case 2:
                    if (!this.reverseLayout) {
                        start--;
                        break;
                    } else {
                        end++;
                        break;
                    }
            }
        }
        return this.beyondBoundsInfo.addInterval(start, end);
    }

    private static final boolean hasMoreContent_FR3nfPY$hasMoreItemsBefore(LazyListBeyondBoundsInfo.Interval $this_hasMoreContent) {
        return $this_hasMoreContent.getStart() > 0;
    }

    private static final boolean hasMoreContent_FR3nfPY$hasMoreItemsAfter(LazyListBeyondBoundsInfo.Interval $this_hasMoreContent, LazyLayoutBeyondBoundsModifierLocal this$0) {
        return $this_hasMoreContent.getEnd() < this$0.state.getItemCount() - 1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: hasMoreContent-FR3nfPY  reason: not valid java name */
    public final boolean m613hasMoreContentFR3nfPY(LazyListBeyondBoundsInfo.Interval $this$hasMoreContent_u2dFR3nfPY, int direction) {
        if (m614isOppositeToOrientation4vf7U8o(direction)) {
            return false;
        }
        if (BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0(direction, BeyondBoundsLayout.LayoutDirection.Companion.m4111getBeforehoxUOeE())) {
            return hasMoreContent_FR3nfPY$hasMoreItemsBefore($this$hasMoreContent_u2dFR3nfPY);
        }
        if (BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0(direction, BeyondBoundsLayout.LayoutDirection.Companion.m4110getAfterhoxUOeE())) {
            return hasMoreContent_FR3nfPY$hasMoreItemsAfter($this$hasMoreContent_u2dFR3nfPY, this);
        }
        if (BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0(direction, BeyondBoundsLayout.LayoutDirection.Companion.m4109getAbovehoxUOeE())) {
            return this.reverseLayout ? hasMoreContent_FR3nfPY$hasMoreItemsAfter($this$hasMoreContent_u2dFR3nfPY, this) : hasMoreContent_FR3nfPY$hasMoreItemsBefore($this$hasMoreContent_u2dFR3nfPY);
        } else if (BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0(direction, BeyondBoundsLayout.LayoutDirection.Companion.m4112getBelowhoxUOeE())) {
            return this.reverseLayout ? hasMoreContent_FR3nfPY$hasMoreItemsBefore($this$hasMoreContent_u2dFR3nfPY) : hasMoreContent_FR3nfPY$hasMoreItemsAfter($this$hasMoreContent_u2dFR3nfPY, this);
        } else if (BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0(direction, BeyondBoundsLayout.LayoutDirection.Companion.m4113getLefthoxUOeE())) {
            switch (WhenMappings.$EnumSwitchMapping$0[this.layoutDirection.ordinal()]) {
                case 1:
                    return this.reverseLayout ? hasMoreContent_FR3nfPY$hasMoreItemsAfter($this$hasMoreContent_u2dFR3nfPY, this) : hasMoreContent_FR3nfPY$hasMoreItemsBefore($this$hasMoreContent_u2dFR3nfPY);
                case 2:
                    return this.reverseLayout ? hasMoreContent_FR3nfPY$hasMoreItemsBefore($this$hasMoreContent_u2dFR3nfPY) : hasMoreContent_FR3nfPY$hasMoreItemsAfter($this$hasMoreContent_u2dFR3nfPY, this);
                default:
                    throw new NoWhenBranchMatchedException();
            }
        } else if (!BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0(direction, BeyondBoundsLayout.LayoutDirection.Companion.m4114getRighthoxUOeE())) {
            LazyLayoutBeyondBoundsModifierLocalKt.unsupportedDirection();
            throw new KotlinNothingValueException();
        } else {
            switch (WhenMappings.$EnumSwitchMapping$0[this.layoutDirection.ordinal()]) {
                case 1:
                    return this.reverseLayout ? hasMoreContent_FR3nfPY$hasMoreItemsBefore($this$hasMoreContent_u2dFR3nfPY) : hasMoreContent_FR3nfPY$hasMoreItemsAfter($this$hasMoreContent_u2dFR3nfPY, this);
                case 2:
                    return this.reverseLayout ? hasMoreContent_FR3nfPY$hasMoreItemsAfter($this$hasMoreContent_u2dFR3nfPY, this) : hasMoreContent_FR3nfPY$hasMoreItemsBefore($this$hasMoreContent_u2dFR3nfPY);
                default:
                    throw new NoWhenBranchMatchedException();
            }
        }
    }

    /* renamed from: isOppositeToOrientation-4vf7U8o  reason: not valid java name */
    private final boolean m614isOppositeToOrientation4vf7U8o(int $this$isOppositeToOrientation_u2d4vf7U8o) {
        if (BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0($this$isOppositeToOrientation_u2d4vf7U8o, BeyondBoundsLayout.LayoutDirection.Companion.m4109getAbovehoxUOeE()) ? true : BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0($this$isOppositeToOrientation_u2d4vf7U8o, BeyondBoundsLayout.LayoutDirection.Companion.m4112getBelowhoxUOeE())) {
            return this.orientation == Orientation.Horizontal;
        }
        if (BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0($this$isOppositeToOrientation_u2d4vf7U8o, BeyondBoundsLayout.LayoutDirection.Companion.m4113getLefthoxUOeE()) ? true : BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0($this$isOppositeToOrientation_u2d4vf7U8o, BeyondBoundsLayout.LayoutDirection.Companion.m4114getRighthoxUOeE())) {
            return this.orientation == Orientation.Vertical;
        }
        if (BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0($this$isOppositeToOrientation_u2d4vf7U8o, BeyondBoundsLayout.LayoutDirection.Companion.m4111getBeforehoxUOeE()) ? true : BeyondBoundsLayout.LayoutDirection.m4105equalsimpl0($this$isOppositeToOrientation_u2d4vf7U8o, BeyondBoundsLayout.LayoutDirection.Companion.m4110getAfterhoxUOeE())) {
            return false;
        }
        LazyLayoutBeyondBoundsModifierLocalKt.unsupportedDirection();
        throw new KotlinNothingValueException();
    }
}
