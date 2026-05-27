package androidx.compose.foundation.layout;

import androidx.compose.ui.layout.IntrinsicMeasurable;
import androidx.compose.ui.layout.IntrinsicMeasureScope;
import androidx.compose.ui.layout.LayoutModifier;
import androidx.compose.ui.layout.Measurable;
import androidx.compose.ui.layout.MeasureResult;
import androidx.compose.ui.layout.MeasureScope;
import androidx.compose.ui.layout.Placeable;
import androidx.compose.ui.platform.InspectorInfo;
import androidx.compose.ui.platform.InspectorValueInfo;
import androidx.compose.ui.unit.Constraints;
import androidx.compose.ui.unit.ConstraintsKt;
import androidx.compose.ui.unit.IntSize;
import androidx.compose.ui.unit.IntSizeKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.math.MathKt;
/* compiled from: AspectRatio.kt */
@Metadata(d1 = {"\u0000j\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0010\b\u0002\u0018\u00002\u00020\u00012\u00020\u0002B.\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\u0017\u0010\u0007\u001a\u0013\u0012\u0004\u0012\u00020\t\u0012\u0004\u0012\u00020\n0\b¢\u0006\u0002\b\u000b¢\u0006\u0002\u0010\fJ\u0013\u0010\u0011\u001a\u00020\u00062\b\u0010\u0012\u001a\u0004\u0018\u00010\u0013H\u0096\u0002J\b\u0010\u0014\u001a\u00020\u0015H\u0016J\b\u0010\u0016\u001a\u00020\u0017H\u0016J\u0019\u0010\u0018\u001a\u00020\u0019*\u00020\u001aH\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001b\u0010\u001cJ\u001c\u0010\u001d\u001a\u00020\u0015*\u00020\u001e2\u0006\u0010\u001f\u001a\u00020 2\u0006\u0010!\u001a\u00020\u0015H\u0016J\u001c\u0010\"\u001a\u00020\u0015*\u00020\u001e2\u0006\u0010\u001f\u001a\u00020 2\u0006\u0010#\u001a\u00020\u0015H\u0016J)\u0010$\u001a\u00020%*\u00020&2\u0006\u0010\u001f\u001a\u00020'2\u0006\u0010(\u001a\u00020\u001aH\u0016ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b)\u0010*J\u001c\u0010+\u001a\u00020\u0015*\u00020\u001e2\u0006\u0010\u001f\u001a\u00020 2\u0006\u0010!\u001a\u00020\u0015H\u0016J\u001c\u0010,\u001a\u00020\u0015*\u00020\u001e2\u0006\u0010\u001f\u001a\u00020 2\u0006\u0010#\u001a\u00020\u0015H\u0016J#\u0010-\u001a\u00020\u0019*\u00020\u001a2\b\b\u0002\u0010.\u001a\u00020\u0006H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b/\u00100J#\u00101\u001a\u00020\u0019*\u00020\u001a2\b\b\u0002\u0010.\u001a\u00020\u0006H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b2\u00100J#\u00103\u001a\u00020\u0019*\u00020\u001a2\b\b\u0002\u0010.\u001a\u00020\u0006H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b4\u00100J#\u00105\u001a\u00020\u0019*\u00020\u001a2\b\b\u0002\u0010.\u001a\u00020\u0006H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b6\u00100R\u0011\u0010\u0003\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\r\u0010\u000eR\u0011\u0010\u0005\u001a\u00020\u0006¢\u0006\b\n\u0000\u001a\u0004\b\u000f\u0010\u0010\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u00067"}, d2 = {"Landroidx/compose/foundation/layout/AspectRatioModifier;", "Landroidx/compose/ui/layout/LayoutModifier;", "Landroidx/compose/ui/platform/InspectorValueInfo;", "aspectRatio", "", "matchHeightConstraintsFirst", "", "inspectorInfo", "Lkotlin/Function1;", "Landroidx/compose/ui/platform/InspectorInfo;", "", "Lkotlin/ExtensionFunctionType;", "(FZLkotlin/jvm/functions/Function1;)V", "getAspectRatio", "()F", "getMatchHeightConstraintsFirst", "()Z", "equals", "other", "", "hashCode", "", "toString", "", "findSize", "Landroidx/compose/ui/unit/IntSize;", "Landroidx/compose/ui/unit/Constraints;", "findSize-ToXhtMw", "(J)J", "maxIntrinsicHeight", "Landroidx/compose/ui/layout/IntrinsicMeasureScope;", "measurable", "Landroidx/compose/ui/layout/IntrinsicMeasurable;", "width", "maxIntrinsicWidth", "height", "measure", "Landroidx/compose/ui/layout/MeasureResult;", "Landroidx/compose/ui/layout/MeasureScope;", "Landroidx/compose/ui/layout/Measurable;", "constraints", "measure-3p2s80s", "(Landroidx/compose/ui/layout/MeasureScope;Landroidx/compose/ui/layout/Measurable;J)Landroidx/compose/ui/layout/MeasureResult;", "minIntrinsicHeight", "minIntrinsicWidth", "tryMaxHeight", "enforceConstraints", "tryMaxHeight-JN-0ABg", "(JZ)J", "tryMaxWidth", "tryMaxWidth-JN-0ABg", "tryMinHeight", "tryMinHeight-JN-0ABg", "tryMinWidth", "tryMinWidth-JN-0ABg", "foundation-layout_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
final class AspectRatioModifier extends InspectorValueInfo implements LayoutModifier {
    private final float aspectRatio;
    private final boolean matchHeightConstraintsFirst;

    public final float getAspectRatio() {
        return this.aspectRatio;
    }

    public final boolean getMatchHeightConstraintsFirst() {
        return this.matchHeightConstraintsFirst;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AspectRatioModifier(float aspectRatio, boolean matchHeightConstraintsFirst, Function1<? super InspectorInfo, Unit> inspectorInfo) {
        super(inspectorInfo);
        Intrinsics.checkNotNullParameter(inspectorInfo, "inspectorInfo");
        this.aspectRatio = aspectRatio;
        this.matchHeightConstraintsFirst = matchHeightConstraintsFirst;
        if (aspectRatio > 0.0f) {
            return;
        }
        throw new IllegalArgumentException(("aspectRatio " + aspectRatio + " must be > 0").toString());
    }

    @Override // androidx.compose.ui.layout.LayoutModifier
    /* renamed from: measure-3p2s80s */
    public MeasureResult mo24measure3p2s80s(MeasureScope measure, Measurable measurable, long constraints) {
        long j;
        Intrinsics.checkNotNullParameter(measure, "$this$measure");
        Intrinsics.checkNotNullParameter(measurable, "measurable");
        long size = m375findSizeToXhtMw(constraints);
        if (!IntSize.m5280equalsimpl0(size, IntSize.Companion.m5287getZeroYbymL2g())) {
            j = Constraints.Companion.m5086fixedJhjzzOo(IntSize.m5282getWidthimpl(size), IntSize.m5281getHeightimpl(size));
        } else {
            j = constraints;
        }
        long wrappedConstraints = j;
        final Placeable placeable = measurable.mo4125measureBRTryo0(wrappedConstraints);
        return MeasureScope.layout$default(measure, placeable.getWidth(), placeable.getHeight(), null, new Function1<Placeable.PlacementScope, Unit>() { // from class: androidx.compose.foundation.layout.AspectRatioModifier$measure$1
            /* JADX INFO: Access modifiers changed from: package-private */
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
                Placeable.PlacementScope.placeRelative$default(layout, Placeable.this, 0, 0, 0.0f, 4, null);
            }
        }, 4, null);
    }

    @Override // androidx.compose.ui.layout.LayoutModifier
    public int minIntrinsicWidth(IntrinsicMeasureScope $this$minIntrinsicWidth, IntrinsicMeasurable measurable, int height) {
        Intrinsics.checkNotNullParameter($this$minIntrinsicWidth, "<this>");
        Intrinsics.checkNotNullParameter(measurable, "measurable");
        if (height != Integer.MAX_VALUE) {
            return MathKt.roundToInt(height * this.aspectRatio);
        }
        return measurable.minIntrinsicWidth(height);
    }

    @Override // androidx.compose.ui.layout.LayoutModifier
    public int maxIntrinsicWidth(IntrinsicMeasureScope $this$maxIntrinsicWidth, IntrinsicMeasurable measurable, int height) {
        Intrinsics.checkNotNullParameter($this$maxIntrinsicWidth, "<this>");
        Intrinsics.checkNotNullParameter(measurable, "measurable");
        if (height != Integer.MAX_VALUE) {
            return MathKt.roundToInt(height * this.aspectRatio);
        }
        return measurable.maxIntrinsicWidth(height);
    }

    @Override // androidx.compose.ui.layout.LayoutModifier
    public int minIntrinsicHeight(IntrinsicMeasureScope $this$minIntrinsicHeight, IntrinsicMeasurable measurable, int width) {
        Intrinsics.checkNotNullParameter($this$minIntrinsicHeight, "<this>");
        Intrinsics.checkNotNullParameter(measurable, "measurable");
        if (width != Integer.MAX_VALUE) {
            return MathKt.roundToInt(width / this.aspectRatio);
        }
        return measurable.minIntrinsicHeight(width);
    }

    @Override // androidx.compose.ui.layout.LayoutModifier
    public int maxIntrinsicHeight(IntrinsicMeasureScope $this$maxIntrinsicHeight, IntrinsicMeasurable measurable, int width) {
        Intrinsics.checkNotNullParameter($this$maxIntrinsicHeight, "<this>");
        Intrinsics.checkNotNullParameter(measurable, "measurable");
        if (width != Integer.MAX_VALUE) {
            return MathKt.roundToInt(width / this.aspectRatio);
        }
        return measurable.maxIntrinsicHeight(width);
    }

    /* renamed from: findSize-ToXhtMw  reason: not valid java name */
    private final long m375findSizeToXhtMw(long $this$findSize_u2dToXhtMw) {
        if (this.matchHeightConstraintsFirst) {
            long it = m377tryMaxHeightJN0ABg$default(this, $this$findSize_u2dToXhtMw, false, 1, null);
            if (!IntSize.m5280equalsimpl0(it, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it;
            }
            long it2 = m379tryMaxWidthJN0ABg$default(this, $this$findSize_u2dToXhtMw, false, 1, null);
            if (!IntSize.m5280equalsimpl0(it2, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it2;
            }
            long it3 = m381tryMinHeightJN0ABg$default(this, $this$findSize_u2dToXhtMw, false, 1, null);
            if (!IntSize.m5280equalsimpl0(it3, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it3;
            }
            long it4 = m383tryMinWidthJN0ABg$default(this, $this$findSize_u2dToXhtMw, false, 1, null);
            if (!IntSize.m5280equalsimpl0(it4, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it4;
            }
            long it5 = m376tryMaxHeightJN0ABg($this$findSize_u2dToXhtMw, false);
            if (!IntSize.m5280equalsimpl0(it5, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it5;
            }
            long it6 = m378tryMaxWidthJN0ABg($this$findSize_u2dToXhtMw, false);
            if (!IntSize.m5280equalsimpl0(it6, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it6;
            }
            long it7 = m380tryMinHeightJN0ABg($this$findSize_u2dToXhtMw, false);
            if (!IntSize.m5280equalsimpl0(it7, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it7;
            }
            long it8 = m382tryMinWidthJN0ABg($this$findSize_u2dToXhtMw, false);
            if (!IntSize.m5280equalsimpl0(it8, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it8;
            }
        } else {
            long it9 = m379tryMaxWidthJN0ABg$default(this, $this$findSize_u2dToXhtMw, false, 1, null);
            if (!IntSize.m5280equalsimpl0(it9, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it9;
            }
            long it10 = m377tryMaxHeightJN0ABg$default(this, $this$findSize_u2dToXhtMw, false, 1, null);
            if (!IntSize.m5280equalsimpl0(it10, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it10;
            }
            long it11 = m383tryMinWidthJN0ABg$default(this, $this$findSize_u2dToXhtMw, false, 1, null);
            if (!IntSize.m5280equalsimpl0(it11, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it11;
            }
            long it12 = m381tryMinHeightJN0ABg$default(this, $this$findSize_u2dToXhtMw, false, 1, null);
            if (!IntSize.m5280equalsimpl0(it12, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it12;
            }
            long it13 = m378tryMaxWidthJN0ABg($this$findSize_u2dToXhtMw, false);
            if (!IntSize.m5280equalsimpl0(it13, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it13;
            }
            long it14 = m376tryMaxHeightJN0ABg($this$findSize_u2dToXhtMw, false);
            if (!IntSize.m5280equalsimpl0(it14, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it14;
            }
            long it15 = m382tryMinWidthJN0ABg($this$findSize_u2dToXhtMw, false);
            if (!IntSize.m5280equalsimpl0(it15, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it15;
            }
            long it16 = m380tryMinHeightJN0ABg($this$findSize_u2dToXhtMw, false);
            if (!IntSize.m5280equalsimpl0(it16, IntSize.Companion.m5287getZeroYbymL2g())) {
                return it16;
            }
        }
        return IntSize.Companion.m5287getZeroYbymL2g();
    }

    /* renamed from: tryMaxWidth-JN-0ABg$default  reason: not valid java name */
    static /* synthetic */ long m379tryMaxWidthJN0ABg$default(AspectRatioModifier aspectRatioModifier, long j, boolean z, int i, Object obj) {
        if ((i & 1) != 0) {
            z = true;
        }
        return aspectRatioModifier.m378tryMaxWidthJN0ABg(j, z);
    }

    /* renamed from: tryMaxWidth-JN-0ABg  reason: not valid java name */
    private final long m378tryMaxWidthJN0ABg(long $this$tryMaxWidth_u2dJN_u2d0ABg, boolean enforceConstraints) {
        int height;
        int maxWidth = Constraints.m5078getMaxWidthimpl($this$tryMaxWidth_u2dJN_u2d0ABg);
        if (maxWidth != Integer.MAX_VALUE && (height = MathKt.roundToInt(maxWidth / this.aspectRatio)) > 0) {
            long size = IntSizeKt.IntSize(maxWidth, height);
            if (!enforceConstraints || ConstraintsKt.m5093isSatisfiedBy4WqzIAM($this$tryMaxWidth_u2dJN_u2d0ABg, size)) {
                return size;
            }
        }
        return IntSize.Companion.m5287getZeroYbymL2g();
    }

    /* renamed from: tryMaxHeight-JN-0ABg$default  reason: not valid java name */
    static /* synthetic */ long m377tryMaxHeightJN0ABg$default(AspectRatioModifier aspectRatioModifier, long j, boolean z, int i, Object obj) {
        if ((i & 1) != 0) {
            z = true;
        }
        return aspectRatioModifier.m376tryMaxHeightJN0ABg(j, z);
    }

    /* renamed from: tryMaxHeight-JN-0ABg  reason: not valid java name */
    private final long m376tryMaxHeightJN0ABg(long $this$tryMaxHeight_u2dJN_u2d0ABg, boolean enforceConstraints) {
        int width;
        int maxHeight = Constraints.m5077getMaxHeightimpl($this$tryMaxHeight_u2dJN_u2d0ABg);
        if (maxHeight != Integer.MAX_VALUE && (width = MathKt.roundToInt(maxHeight * this.aspectRatio)) > 0) {
            long size = IntSizeKt.IntSize(width, maxHeight);
            if (!enforceConstraints || ConstraintsKt.m5093isSatisfiedBy4WqzIAM($this$tryMaxHeight_u2dJN_u2d0ABg, size)) {
                return size;
            }
        }
        return IntSize.Companion.m5287getZeroYbymL2g();
    }

    /* renamed from: tryMinWidth-JN-0ABg$default  reason: not valid java name */
    static /* synthetic */ long m383tryMinWidthJN0ABg$default(AspectRatioModifier aspectRatioModifier, long j, boolean z, int i, Object obj) {
        if ((i & 1) != 0) {
            z = true;
        }
        return aspectRatioModifier.m382tryMinWidthJN0ABg(j, z);
    }

    /* renamed from: tryMinWidth-JN-0ABg  reason: not valid java name */
    private final long m382tryMinWidthJN0ABg(long $this$tryMinWidth_u2dJN_u2d0ABg, boolean enforceConstraints) {
        int minWidth = Constraints.m5080getMinWidthimpl($this$tryMinWidth_u2dJN_u2d0ABg);
        int height = MathKt.roundToInt(minWidth / this.aspectRatio);
        if (height > 0) {
            long size = IntSizeKt.IntSize(minWidth, height);
            if (!enforceConstraints || ConstraintsKt.m5093isSatisfiedBy4WqzIAM($this$tryMinWidth_u2dJN_u2d0ABg, size)) {
                return size;
            }
        }
        return IntSize.Companion.m5287getZeroYbymL2g();
    }

    /* renamed from: tryMinHeight-JN-0ABg$default  reason: not valid java name */
    static /* synthetic */ long m381tryMinHeightJN0ABg$default(AspectRatioModifier aspectRatioModifier, long j, boolean z, int i, Object obj) {
        if ((i & 1) != 0) {
            z = true;
        }
        return aspectRatioModifier.m380tryMinHeightJN0ABg(j, z);
    }

    /* renamed from: tryMinHeight-JN-0ABg  reason: not valid java name */
    private final long m380tryMinHeightJN0ABg(long $this$tryMinHeight_u2dJN_u2d0ABg, boolean enforceConstraints) {
        int minHeight = Constraints.m5079getMinHeightimpl($this$tryMinHeight_u2dJN_u2d0ABg);
        int width = MathKt.roundToInt(minHeight * this.aspectRatio);
        if (width > 0) {
            long size = IntSizeKt.IntSize(width, minHeight);
            if (!enforceConstraints || ConstraintsKt.m5093isSatisfiedBy4WqzIAM($this$tryMinHeight_u2dJN_u2d0ABg, size)) {
                return size;
            }
        }
        return IntSize.Companion.m5287getZeroYbymL2g();
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        AspectRatioModifier otherModifier = other instanceof AspectRatioModifier ? (AspectRatioModifier) other : null;
        if (otherModifier == null) {
            return false;
        }
        return ((this.aspectRatio > otherModifier.aspectRatio ? 1 : (this.aspectRatio == otherModifier.aspectRatio ? 0 : -1)) == 0) && this.matchHeightConstraintsFirst == ((AspectRatioModifier) other).matchHeightConstraintsFirst;
    }

    public int hashCode() {
        return (Float.hashCode(this.aspectRatio) * 31) + Boolean.hashCode(this.matchHeightConstraintsFirst);
    }

    public String toString() {
        return "AspectRatioModifier(aspectRatio=" + this.aspectRatio + ')';
    }
}
