package androidx.compose.ui.layout;

import androidx.compose.ui.graphics.GraphicsLayerScope;
import androidx.compose.ui.node.LayoutNodeLayoutDelegate;
import androidx.compose.ui.node.LookaheadCapablePlaceable;
import androidx.compose.ui.unit.Constraints;
import androidx.compose.ui.unit.IntOffset;
import androidx.compose.ui.unit.IntOffsetKt;
import androidx.compose.ui.unit.IntSize;
import androidx.compose.ui.unit.IntSizeKt;
import androidx.compose.ui.unit.LayoutDirection;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt;
/* compiled from: Placeable.kt */
@Metadata(d1 = {"\u0000J\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\b'\u0018\u00002\u00020\u0001:\u0001)B\u0005¢\u0006\u0002\u0010\u0002J@\u0010\u001d\u001a\u00020\u001e2\u0006\u0010\u001f\u001a\u00020\u00042\u0006\u0010 \u001a\u00020!2\u0019\u0010\"\u001a\u0015\u0012\u0004\u0012\u00020$\u0012\u0004\u0012\u00020\u001e\u0018\u00010#¢\u0006\u0002\b%H$ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b&\u0010'J\b\u0010(\u001a\u00020\u001eH\u0002R\u001d\u0010\u0003\u001a\u00020\u00048DX\u0084\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0006\u001a\u0004\b\u0005\u0010\u0006R\u001e\u0010\t\u001a\u00020\b2\u0006\u0010\u0007\u001a\u00020\b@BX\u0086\u000e¢\u0006\b\n\u0000\u001a\u0004\b\n\u0010\u000bR\u0014\u0010\f\u001a\u00020\b8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\r\u0010\u000bR/\u0010\u0010\u001a\u00020\u000f2\u0006\u0010\u000e\u001a\u00020\u000f@DX\u0084\u000eø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0010\n\u0002\u0010\u0014\u001a\u0004\b\u0011\u0010\u0006\"\u0004\b\u0012\u0010\u0013R\u0014\u0010\u0015\u001a\u00020\b8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0016\u0010\u000bR/\u0010\u0018\u001a\u00020\u00172\u0006\u0010\u000e\u001a\u00020\u0017@DX\u0084\u000eø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0010\n\u0002\u0010\u0014\u001a\u0004\b\u0019\u0010\u0006\"\u0004\b\u001a\u0010\u0013R\u001e\u0010\u001b\u001a\u00020\b2\u0006\u0010\u0007\u001a\u00020\b@BX\u0086\u000e¢\u0006\b\n\u0000\u001a\u0004\b\u001c\u0010\u000b\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u0006*"}, d2 = {"Landroidx/compose/ui/layout/Placeable;", "Landroidx/compose/ui/layout/Measured;", "()V", "apparentToRealOffset", "Landroidx/compose/ui/unit/IntOffset;", "getApparentToRealOffset-nOcc-ac", "()J", "<set-?>", "", "height", "getHeight", "()I", "measuredHeight", "getMeasuredHeight", "value", "Landroidx/compose/ui/unit/IntSize;", "measuredSize", "getMeasuredSize-YbymL2g", "setMeasuredSize-ozmzZPI", "(J)V", "J", "measuredWidth", "getMeasuredWidth", "Landroidx/compose/ui/unit/Constraints;", "measurementConstraints", "getMeasurementConstraints-msEJaDk", "setMeasurementConstraints-BRTryo0", "width", "getWidth", "placeAt", "", "position", "zIndex", "", "layerBlock", "Lkotlin/Function1;", "Landroidx/compose/ui/graphics/GraphicsLayerScope;", "Lkotlin/ExtensionFunctionType;", "placeAt-f8xVGno", "(JFLkotlin/jvm/functions/Function1;)V", "recalculateWidthAndHeight", "PlacementScope", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public abstract class Placeable implements Measured {
    public static final int $stable = 8;
    private int height;
    private long measuredSize = IntSizeKt.IntSize(0, 0);
    private long measurementConstraints = PlaceableKt.access$getDefaultConstraints$p();
    private int width;

    /* renamed from: placeAt-f8xVGno */
    public abstract void mo4126placeAtf8xVGno(long j, float f, Function1<? super GraphicsLayerScope, Unit> function1);

    public final int getWidth() {
        return this.width;
    }

    public final int getHeight() {
        return this.height;
    }

    @Override // androidx.compose.ui.layout.Measured
    public int getMeasuredWidth() {
        return IntSize.m5282getWidthimpl(this.measuredSize);
    }

    @Override // androidx.compose.ui.layout.Measured
    public int getMeasuredHeight() {
        return IntSize.m5281getHeightimpl(this.measuredSize);
    }

    /* renamed from: getMeasuredSize-YbymL2g */
    public final long m4169getMeasuredSizeYbymL2g() {
        return this.measuredSize;
    }

    /* renamed from: setMeasuredSize-ozmzZPI */
    public final void m4171setMeasuredSizeozmzZPI(long value) {
        if (!IntSize.m5280equalsimpl0(this.measuredSize, value)) {
            this.measuredSize = value;
            recalculateWidthAndHeight();
        }
    }

    private final void recalculateWidthAndHeight() {
        this.width = RangesKt.coerceIn(IntSize.m5282getWidthimpl(this.measuredSize), Constraints.m5080getMinWidthimpl(this.measurementConstraints), Constraints.m5078getMaxWidthimpl(this.measurementConstraints));
        this.height = RangesKt.coerceIn(IntSize.m5281getHeightimpl(this.measuredSize), Constraints.m5079getMinHeightimpl(this.measurementConstraints), Constraints.m5077getMaxHeightimpl(this.measurementConstraints));
    }

    /* renamed from: getMeasurementConstraints-msEJaDk */
    public final long m4170getMeasurementConstraintsmsEJaDk() {
        return this.measurementConstraints;
    }

    /* renamed from: setMeasurementConstraints-BRTryo0 */
    public final void m4172setMeasurementConstraintsBRTryo0(long value) {
        if (!Constraints.m5071equalsimpl0(this.measurementConstraints, value)) {
            this.measurementConstraints = value;
            recalculateWidthAndHeight();
        }
    }

    /* renamed from: getApparentToRealOffset-nOcc-ac */
    public final long m4168getApparentToRealOffsetnOccac() {
        return IntOffsetKt.IntOffset((this.width - IntSize.m5282getWidthimpl(this.measuredSize)) / 2, (this.height - IntSize.m5281getHeightimpl(this.measuredSize)) / 2);
    }

    /* compiled from: Placeable.kt */
    @Metadata(d1 = {"\u0000L\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\f\b'\u0018\u0000 *2\u00020\u0001:\u0001*B\u0005¢\u0006\u0002\u0010\u0002J)\u0010\u0010\u001a\u00020\u0011*\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00142\b\b\u0002\u0010\u0015\u001a\u00020\u0016ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0017\u0010\u0018J$\u0010\u0010\u001a\u00020\u0011*\u00020\u00122\u0006\u0010\u0019\u001a\u00020\r2\u0006\u0010\u001a\u001a\u00020\r2\b\b\u0002\u0010\u0015\u001a\u00020\u0016JJ\u0010\u001b\u001a\u00020\u0011*\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\u00162\u001b\b\b\u0010\u001c\u001a\u0015\u0012\u0004\u0012\u00020\u001e\u0012\u0004\u0012\u00020\u0011\u0018\u00010\u001d¢\u0006\u0002\b\u001fH\u0080\bø\u0001\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b \u0010!JJ\u0010\"\u001a\u00020\u0011*\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\u00162\u001b\b\b\u0010\u001c\u001a\u0015\u0012\u0004\u0012\u00020\u001e\u0012\u0004\u0012\u00020\u0011\u0018\u00010\u001d¢\u0006\u0002\b\u001fH\u0080\bø\u0001\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b#\u0010!J)\u0010$\u001a\u00020\u0011*\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00142\b\b\u0002\u0010\u0015\u001a\u00020\u0016ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b%\u0010\u0018J$\u0010$\u001a\u00020\u0011*\u00020\u00122\u0006\u0010\u0019\u001a\u00020\r2\u0006\u0010\u001a\u001a\u00020\r2\b\b\u0002\u0010\u0015\u001a\u00020\u0016JD\u0010&\u001a\u00020\u0011*\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00142\b\b\u0002\u0010\u0015\u001a\u00020\u00162\u0019\b\u0002\u0010\u001c\u001a\u0013\u0012\u0004\u0012\u00020\u001e\u0012\u0004\u0012\u00020\u00110\u001d¢\u0006\u0002\b\u001fø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b'\u0010!J?\u0010&\u001a\u00020\u0011*\u00020\u00122\u0006\u0010\u0019\u001a\u00020\r2\u0006\u0010\u001a\u001a\u00020\r2\b\b\u0002\u0010\u0015\u001a\u00020\u00162\u0019\b\u0002\u0010\u001c\u001a\u0013\u0012\u0004\u0012\u00020\u001e\u0012\u0004\u0012\u00020\u00110\u001d¢\u0006\u0002\b\u001fJD\u0010(\u001a\u00020\u0011*\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00142\b\b\u0002\u0010\u0015\u001a\u00020\u00162\u0019\b\u0002\u0010\u001c\u001a\u0013\u0012\u0004\u0012\u00020\u001e\u0012\u0004\u0012\u00020\u00110\u001d¢\u0006\u0002\b\u001fø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b)\u0010!J?\u0010(\u001a\u00020\u0011*\u00020\u00122\u0006\u0010\u0019\u001a\u00020\r2\u0006\u0010\u001a\u001a\u00020\r2\b\b\u0002\u0010\u0015\u001a\u00020\u00162\u0019\b\u0002\u0010\u001c\u001a\u0013\u0012\u0004\u0012\u00020\u001e\u0012\u0004\u0012\u00020\u00110\u001d¢\u0006\u0002\b\u001fR\u001c\u0010\u0003\u001a\u0004\u0018\u00010\u00048WX\u0097\u0004¢\u0006\f\u0012\u0004\b\u0005\u0010\u0002\u001a\u0004\b\u0006\u0010\u0007R\u0012\u0010\b\u001a\u00020\tX¤\u0004¢\u0006\u0006\u001a\u0004\b\n\u0010\u000bR\u0012\u0010\f\u001a\u00020\rX¤\u0004¢\u0006\u0006\u001a\u0004\b\u000e\u0010\u000f\u0082\u0002\u0012\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019\n\u0005\b\u009920\u0001¨\u0006+"}, d2 = {"Landroidx/compose/ui/layout/Placeable$PlacementScope;", "", "()V", "coordinates", "Landroidx/compose/ui/layout/LayoutCoordinates;", "getCoordinates$annotations", "getCoordinates", "()Landroidx/compose/ui/layout/LayoutCoordinates;", "parentLayoutDirection", "Landroidx/compose/ui/unit/LayoutDirection;", "getParentLayoutDirection", "()Landroidx/compose/ui/unit/LayoutDirection;", "parentWidth", "", "getParentWidth", "()I", "place", "", "Landroidx/compose/ui/layout/Placeable;", "position", "Landroidx/compose/ui/unit/IntOffset;", "zIndex", "", "place-70tqf50", "(Landroidx/compose/ui/layout/Placeable;JF)V", "x", "y", "placeApparentToRealOffset", "layerBlock", "Lkotlin/Function1;", "Landroidx/compose/ui/graphics/GraphicsLayerScope;", "Lkotlin/ExtensionFunctionType;", "placeApparentToRealOffset-aW-9-wM$ui_release", "(Landroidx/compose/ui/layout/Placeable;JFLkotlin/jvm/functions/Function1;)V", "placeAutoMirrored", "placeAutoMirrored-aW-9-wM$ui_release", "placeRelative", "placeRelative-70tqf50", "placeRelativeWithLayer", "placeRelativeWithLayer-aW-9-wM", "placeWithLayer", "placeWithLayer-aW-9-wM", "Companion", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static abstract class PlacementScope {
        public static final int $stable = 0;
        private static LayoutCoordinates _coordinates;
        private static LayoutNodeLayoutDelegate layoutDelegate;
        private static int parentWidth;
        public static final Companion Companion = new Companion(null);
        private static LayoutDirection parentLayoutDirection = LayoutDirection.Ltr;

        public static /* synthetic */ void getCoordinates$annotations() {
        }

        public abstract LayoutDirection getParentLayoutDirection();

        public abstract int getParentWidth();

        public LayoutCoordinates getCoordinates() {
            return null;
        }

        /* renamed from: placeRelative-70tqf50$default */
        public static /* synthetic */ void m4174placeRelative70tqf50$default(PlacementScope placementScope, Placeable placeable, long j, float f, int i, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: placeRelative-70tqf50");
            }
            if ((i & 2) != 0) {
                f = 0.0f;
            }
            placementScope.m4180placeRelative70tqf50(placeable, j, f);
        }

        /* renamed from: placeRelative-70tqf50 */
        public final void m4180placeRelative70tqf50(Placeable placeRelative, long position, float zIndex) {
            Intrinsics.checkNotNullParameter(placeRelative, "$this$placeRelative");
            if (getParentLayoutDirection() == LayoutDirection.Ltr || getParentWidth() == 0) {
                long other$iv$iv$iv = placeRelative.m4168getApparentToRealOffsetnOccac();
                placeRelative.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position) + IntOffset.m5240getXimpl(other$iv$iv$iv), IntOffset.m5241getYimpl(position) + IntOffset.m5241getYimpl(other$iv$iv$iv)), zIndex, null);
                return;
            }
            long position$iv$iv = IntOffsetKt.IntOffset((getParentWidth() - placeRelative.getWidth()) - IntOffset.m5240getXimpl(position), IntOffset.m5241getYimpl(position));
            long other$iv$iv$iv2 = placeRelative.m4168getApparentToRealOffsetnOccac();
            placeRelative.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position$iv$iv) + IntOffset.m5240getXimpl(other$iv$iv$iv2), IntOffset.m5241getYimpl(position$iv$iv) + IntOffset.m5241getYimpl(other$iv$iv$iv2)), zIndex, null);
        }

        public static /* synthetic */ void placeRelative$default(PlacementScope placementScope, Placeable placeable, int i, int i2, float f, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: placeRelative");
            }
            if ((i3 & 4) != 0) {
                f = 0.0f;
            }
            placementScope.placeRelative(placeable, i, i2, f);
        }

        public final void placeRelative(Placeable $this$placeRelative, int x, int y, float zIndex) {
            Intrinsics.checkNotNullParameter($this$placeRelative, "<this>");
            long position$iv = IntOffsetKt.IntOffset(x, y);
            if (getParentLayoutDirection() != LayoutDirection.Ltr && getParentWidth() != 0) {
                long position$iv$iv = IntOffsetKt.IntOffset((getParentWidth() - $this$placeRelative.getWidth()) - IntOffset.m5240getXimpl(position$iv), IntOffset.m5241getYimpl(position$iv));
                long other$iv$iv$iv = $this$placeRelative.m4168getApparentToRealOffsetnOccac();
                $this$placeRelative.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position$iv$iv) + IntOffset.m5240getXimpl(other$iv$iv$iv), IntOffset.m5241getYimpl(position$iv$iv) + IntOffset.m5241getYimpl(other$iv$iv$iv)), zIndex, null);
                return;
            }
            long other$iv$iv$iv2 = $this$placeRelative.m4168getApparentToRealOffsetnOccac();
            $this$placeRelative.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position$iv) + IntOffset.m5240getXimpl(other$iv$iv$iv2), IntOffset.m5241getYimpl(position$iv) + IntOffset.m5241getYimpl(other$iv$iv$iv2)), zIndex, null);
        }

        public static /* synthetic */ void place$default(PlacementScope placementScope, Placeable placeable, int i, int i2, float f, int i3, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: place");
            }
            if ((i3 & 4) != 0) {
                f = 0.0f;
            }
            placementScope.place(placeable, i, i2, f);
        }

        public final void place(Placeable $this$place, int x, int y, float zIndex) {
            Intrinsics.checkNotNullParameter($this$place, "<this>");
            long position$iv = IntOffsetKt.IntOffset(x, y);
            long other$iv$iv = $this$place.m4168getApparentToRealOffsetnOccac();
            $this$place.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position$iv) + IntOffset.m5240getXimpl(other$iv$iv), IntOffset.m5241getYimpl(position$iv) + IntOffset.m5241getYimpl(other$iv$iv)), zIndex, null);
        }

        /* renamed from: place-70tqf50$default */
        public static /* synthetic */ void m4173place70tqf50$default(PlacementScope placementScope, Placeable placeable, long j, float f, int i, Object obj) {
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: place-70tqf50");
            }
            if ((i & 2) != 0) {
                f = 0.0f;
            }
            placementScope.m4177place70tqf50(placeable, j, f);
        }

        /* renamed from: place-70tqf50 */
        public final void m4177place70tqf50(Placeable place, long position, float zIndex) {
            Intrinsics.checkNotNullParameter(place, "$this$place");
            long other$iv$iv = place.m4168getApparentToRealOffsetnOccac();
            place.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position) + IntOffset.m5240getXimpl(other$iv$iv), IntOffset.m5241getYimpl(position) + IntOffset.m5241getYimpl(other$iv$iv)), zIndex, null);
        }

        /* renamed from: placeRelativeWithLayer-aW-9-wM$default */
        public static /* synthetic */ void m4175placeRelativeWithLayeraW9wM$default(PlacementScope placementScope, Placeable placeable, long j, float f, Function1 function1, int i, Object obj) {
            float f2;
            Function1 function12;
            Function1 function13;
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: placeRelativeWithLayer-aW-9-wM");
            }
            if ((i & 2) == 0) {
                f2 = f;
            } else {
                f2 = 0.0f;
            }
            if ((i & 4) != 0) {
                function13 = PlaceableKt.DefaultLayerBlock;
                function12 = function13;
            } else {
                function12 = function1;
            }
            placementScope.m4181placeRelativeWithLayeraW9wM(placeable, j, f2, function12);
        }

        /* renamed from: placeRelativeWithLayer-aW-9-wM */
        public final void m4181placeRelativeWithLayeraW9wM(Placeable placeRelativeWithLayer, long position, float zIndex, Function1<? super GraphicsLayerScope, Unit> layerBlock) {
            Intrinsics.checkNotNullParameter(placeRelativeWithLayer, "$this$placeRelativeWithLayer");
            Intrinsics.checkNotNullParameter(layerBlock, "layerBlock");
            if (getParentLayoutDirection() == LayoutDirection.Ltr || getParentWidth() == 0) {
                long other$iv$iv$iv = placeRelativeWithLayer.m4168getApparentToRealOffsetnOccac();
                placeRelativeWithLayer.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position) + IntOffset.m5240getXimpl(other$iv$iv$iv), IntOffset.m5241getYimpl(position) + IntOffset.m5241getYimpl(other$iv$iv$iv)), zIndex, layerBlock);
                return;
            }
            long position$iv$iv = IntOffsetKt.IntOffset((getParentWidth() - placeRelativeWithLayer.getWidth()) - IntOffset.m5240getXimpl(position), IntOffset.m5241getYimpl(position));
            long other$iv$iv$iv2 = placeRelativeWithLayer.m4168getApparentToRealOffsetnOccac();
            placeRelativeWithLayer.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position$iv$iv) + IntOffset.m5240getXimpl(other$iv$iv$iv2), IntOffset.m5241getYimpl(position$iv$iv) + IntOffset.m5241getYimpl(other$iv$iv$iv2)), zIndex, layerBlock);
        }

        public static /* synthetic */ void placeRelativeWithLayer$default(PlacementScope placementScope, Placeable placeable, int i, int i2, float f, Function1 function1, int i3, Object obj) {
            float f2;
            Function1 function12;
            Function1 function13;
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: placeRelativeWithLayer");
            }
            if ((i3 & 4) == 0) {
                f2 = f;
            } else {
                f2 = 0.0f;
            }
            if ((i3 & 8) != 0) {
                function13 = PlaceableKt.DefaultLayerBlock;
                function12 = function13;
            } else {
                function12 = function1;
            }
            placementScope.placeRelativeWithLayer(placeable, i, i2, f2, function12);
        }

        public final void placeRelativeWithLayer(Placeable $this$placeRelativeWithLayer, int x, int y, float zIndex, Function1<? super GraphicsLayerScope, Unit> layerBlock) {
            Intrinsics.checkNotNullParameter($this$placeRelativeWithLayer, "<this>");
            Intrinsics.checkNotNullParameter(layerBlock, "layerBlock");
            long position$iv = IntOffsetKt.IntOffset(x, y);
            if (getParentLayoutDirection() != LayoutDirection.Ltr && getParentWidth() != 0) {
                long position$iv$iv = IntOffsetKt.IntOffset((getParentWidth() - $this$placeRelativeWithLayer.getWidth()) - IntOffset.m5240getXimpl(position$iv), IntOffset.m5241getYimpl(position$iv));
                long other$iv$iv$iv = $this$placeRelativeWithLayer.m4168getApparentToRealOffsetnOccac();
                $this$placeRelativeWithLayer.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position$iv$iv) + IntOffset.m5240getXimpl(other$iv$iv$iv), IntOffset.m5241getYimpl(position$iv$iv) + IntOffset.m5241getYimpl(other$iv$iv$iv)), zIndex, layerBlock);
                return;
            }
            long other$iv$iv$iv2 = $this$placeRelativeWithLayer.m4168getApparentToRealOffsetnOccac();
            $this$placeRelativeWithLayer.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position$iv) + IntOffset.m5240getXimpl(other$iv$iv$iv2), IntOffset.m5241getYimpl(position$iv) + IntOffset.m5241getYimpl(other$iv$iv$iv2)), zIndex, layerBlock);
        }

        public static /* synthetic */ void placeWithLayer$default(PlacementScope placementScope, Placeable placeable, int i, int i2, float f, Function1 function1, int i3, Object obj) {
            float f2;
            Function1 function12;
            Function1 function13;
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: placeWithLayer");
            }
            if ((i3 & 4) == 0) {
                f2 = f;
            } else {
                f2 = 0.0f;
            }
            if ((i3 & 8) != 0) {
                function13 = PlaceableKt.DefaultLayerBlock;
                function12 = function13;
            } else {
                function12 = function1;
            }
            placementScope.placeWithLayer(placeable, i, i2, f2, function12);
        }

        public final void placeWithLayer(Placeable $this$placeWithLayer, int x, int y, float zIndex, Function1<? super GraphicsLayerScope, Unit> layerBlock) {
            Intrinsics.checkNotNullParameter($this$placeWithLayer, "<this>");
            Intrinsics.checkNotNullParameter(layerBlock, "layerBlock");
            long position$iv = IntOffsetKt.IntOffset(x, y);
            long other$iv$iv = $this$placeWithLayer.m4168getApparentToRealOffsetnOccac();
            $this$placeWithLayer.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position$iv) + IntOffset.m5240getXimpl(other$iv$iv), IntOffset.m5241getYimpl(position$iv) + IntOffset.m5241getYimpl(other$iv$iv)), zIndex, layerBlock);
        }

        /* renamed from: placeWithLayer-aW-9-wM$default */
        public static /* synthetic */ void m4176placeWithLayeraW9wM$default(PlacementScope placementScope, Placeable placeable, long j, float f, Function1 function1, int i, Object obj) {
            float f2;
            Function1 function12;
            Function1 function13;
            if (obj != null) {
                throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: placeWithLayer-aW-9-wM");
            }
            if ((i & 2) == 0) {
                f2 = f;
            } else {
                f2 = 0.0f;
            }
            if ((i & 4) != 0) {
                function13 = PlaceableKt.DefaultLayerBlock;
                function12 = function13;
            } else {
                function12 = function1;
            }
            placementScope.m4182placeWithLayeraW9wM(placeable, j, f2, function12);
        }

        /* renamed from: placeWithLayer-aW-9-wM */
        public final void m4182placeWithLayeraW9wM(Placeable placeWithLayer, long position, float zIndex, Function1<? super GraphicsLayerScope, Unit> layerBlock) {
            Intrinsics.checkNotNullParameter(placeWithLayer, "$this$placeWithLayer");
            Intrinsics.checkNotNullParameter(layerBlock, "layerBlock");
            long other$iv$iv = placeWithLayer.m4168getApparentToRealOffsetnOccac();
            placeWithLayer.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position) + IntOffset.m5240getXimpl(other$iv$iv), IntOffset.m5241getYimpl(position) + IntOffset.m5241getYimpl(other$iv$iv)), zIndex, layerBlock);
        }

        /* renamed from: placeAutoMirrored-aW-9-wM$ui_release */
        public final void m4179placeAutoMirroredaW9wM$ui_release(Placeable placeAutoMirrored, long position, float zIndex, Function1<? super GraphicsLayerScope, Unit> function1) {
            Intrinsics.checkNotNullParameter(placeAutoMirrored, "$this$placeAutoMirrored");
            if (getParentLayoutDirection() == LayoutDirection.Ltr || getParentWidth() == 0) {
                long other$iv$iv = placeAutoMirrored.m4168getApparentToRealOffsetnOccac();
                placeAutoMirrored.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position) + IntOffset.m5240getXimpl(other$iv$iv), IntOffset.m5241getYimpl(position) + IntOffset.m5241getYimpl(other$iv$iv)), zIndex, function1);
                return;
            }
            long position$iv = IntOffsetKt.IntOffset((getParentWidth() - placeAutoMirrored.getWidth()) - IntOffset.m5240getXimpl(position), IntOffset.m5241getYimpl(position));
            long other$iv$iv2 = placeAutoMirrored.m4168getApparentToRealOffsetnOccac();
            placeAutoMirrored.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position$iv) + IntOffset.m5240getXimpl(other$iv$iv2), IntOffset.m5241getYimpl(position$iv) + IntOffset.m5241getYimpl(other$iv$iv2)), zIndex, function1);
        }

        /* renamed from: placeApparentToRealOffset-aW-9-wM$ui_release */
        public final void m4178placeApparentToRealOffsetaW9wM$ui_release(Placeable placeApparentToRealOffset, long position, float zIndex, Function1<? super GraphicsLayerScope, Unit> function1) {
            Intrinsics.checkNotNullParameter(placeApparentToRealOffset, "$this$placeApparentToRealOffset");
            long other$iv = placeApparentToRealOffset.m4168getApparentToRealOffsetnOccac();
            placeApparentToRealOffset.mo4126placeAtf8xVGno(IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(position) + IntOffset.m5240getXimpl(other$iv), IntOffset.m5241getYimpl(position) + IntOffset.m5241getYimpl(other$iv)), zIndex, function1);
        }

        /* compiled from: Placeable.kt */
        @Metadata(d1 = {"\u0000H\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\b\u0080\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J\u0012\u0010\u0014\u001a\u00020\u00152\b\u0010\u0016\u001a\u0004\u0018\u00010\u0017H\u0002JA\u0010\u0018\u001a\u00020\u00192\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\r\u001a\u00020\f2\b\u0010\u001a\u001a\u0004\u0018\u00010\u00172\u0019\b\u0004\u0010\u001b\u001a\u0013\u0012\u0004\u0012\u00020\u0001\u0012\u0004\u0012\u00020\u00190\u001c¢\u0006\u0002\b\u001dH\u0086\bø\u0001\u0000R\u0010\u0010\u0003\u001a\u0004\u0018\u00010\u0004X\u0082\u000e¢\u0006\u0002\n\u0000R\u001c\u0010\u0005\u001a\u0004\u0018\u00010\u00048VX\u0097\u0004¢\u0006\f\u0012\u0004\b\u0006\u0010\u0002\u001a\u0004\b\u0007\u0010\bR\u0010\u0010\t\u001a\u0004\u0018\u00010\nX\u0082\u000e¢\u0006\u0002\n\u0000R\u001e\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\f@RX\u0094\u000e¢\u0006\b\n\u0000\u001a\u0004\b\u000e\u0010\u000fR\u001e\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u000b\u001a\u00020\u0010@RX\u0094\u000e¢\u0006\b\n\u0000\u001a\u0004\b\u0012\u0010\u0013\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006\u001e"}, d2 = {"Landroidx/compose/ui/layout/Placeable$PlacementScope$Companion;", "Landroidx/compose/ui/layout/Placeable$PlacementScope;", "()V", "_coordinates", "Landroidx/compose/ui/layout/LayoutCoordinates;", "coordinates", "getCoordinates$annotations", "getCoordinates", "()Landroidx/compose/ui/layout/LayoutCoordinates;", "layoutDelegate", "Landroidx/compose/ui/node/LayoutNodeLayoutDelegate;", "<set-?>", "Landroidx/compose/ui/unit/LayoutDirection;", "parentLayoutDirection", "getParentLayoutDirection", "()Landroidx/compose/ui/unit/LayoutDirection;", "", "parentWidth", "getParentWidth", "()I", "configureForPlacingForAlignment", "", "scope", "Landroidx/compose/ui/node/LookaheadCapablePlaceable;", "executeWithRtlMirroringValues", "", "lookaheadCapablePlaceable", "block", "Lkotlin/Function1;", "Lkotlin/ExtensionFunctionType;", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
        /* loaded from: classes.dex */
        public static final class Companion extends PlacementScope {
            public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }

            public static /* synthetic */ void getCoordinates$annotations() {
            }

            private Companion() {
            }

            @Override // androidx.compose.ui.layout.Placeable.PlacementScope
            public LayoutDirection getParentLayoutDirection() {
                return PlacementScope.parentLayoutDirection;
            }

            @Override // androidx.compose.ui.layout.Placeable.PlacementScope
            public int getParentWidth() {
                return PlacementScope.parentWidth;
            }

            @Override // androidx.compose.ui.layout.Placeable.PlacementScope
            public LayoutCoordinates getCoordinates() {
                LayoutNodeLayoutDelegate layoutNodeLayoutDelegate = PlacementScope.layoutDelegate;
                if (layoutNodeLayoutDelegate != null) {
                    layoutNodeLayoutDelegate.setCoordinatesAccessedDuringPlacement(true);
                }
                return PlacementScope._coordinates;
            }

            public final void executeWithRtlMirroringValues(int parentWidth, LayoutDirection parentLayoutDirection, LookaheadCapablePlaceable lookaheadCapablePlaceable, Function1<? super PlacementScope, Unit> block) {
                Intrinsics.checkNotNullParameter(parentLayoutDirection, "parentLayoutDirection");
                Intrinsics.checkNotNullParameter(block, "block");
                LayoutCoordinates previousLayoutCoordinates = PlacementScope._coordinates;
                int previousParentWidth = PlacementScope.Companion.getParentWidth();
                LayoutDirection previousParentLayoutDirection = PlacementScope.Companion.getParentLayoutDirection();
                LayoutNodeLayoutDelegate previousLayoutDelegate = PlacementScope.layoutDelegate;
                Companion companion = PlacementScope.Companion;
                PlacementScope.parentWidth = parentWidth;
                Companion companion2 = PlacementScope.Companion;
                PlacementScope.parentLayoutDirection = parentLayoutDirection;
                boolean wasPlacingForAlignment = configureForPlacingForAlignment(lookaheadCapablePlaceable);
                block.invoke(this);
                if (lookaheadCapablePlaceable != null) {
                    lookaheadCapablePlaceable.setPlacingForAlignment$ui_release(wasPlacingForAlignment);
                }
                Companion companion3 = PlacementScope.Companion;
                PlacementScope.parentWidth = previousParentWidth;
                Companion companion4 = PlacementScope.Companion;
                PlacementScope.parentLayoutDirection = previousParentLayoutDirection;
                PlacementScope._coordinates = previousLayoutCoordinates;
                PlacementScope.layoutDelegate = previousLayoutDelegate;
            }

            public final boolean configureForPlacingForAlignment(LookaheadCapablePlaceable scope) {
                if (scope == null) {
                    PlacementScope._coordinates = null;
                    PlacementScope.layoutDelegate = null;
                    return false;
                }
                boolean wasPlacingForAlignment = scope.isPlacingForAlignment$ui_release();
                LookaheadCapablePlaceable parent = scope.getParent();
                boolean z = false;
                if (parent != null && parent.isPlacingForAlignment$ui_release()) {
                    z = true;
                }
                if (z) {
                    scope.setPlacingForAlignment$ui_release(true);
                }
                PlacementScope.layoutDelegate = scope.getLayoutNode().getLayoutDelegate$ui_release();
                if (scope.isPlacingForAlignment$ui_release() || scope.isShallowPlacing$ui_release()) {
                    PlacementScope._coordinates = null;
                    return wasPlacingForAlignment;
                }
                PlacementScope._coordinates = scope.getCoordinates();
                return wasPlacingForAlignment;
            }
        }
    }
}
