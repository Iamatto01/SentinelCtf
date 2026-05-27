package androidx.compose.ui.layout;

import androidx.compose.ui.geometry.Offset;
import androidx.compose.ui.geometry.OffsetKt;
import androidx.compose.ui.geometry.Rect;
import androidx.compose.ui.node.NodeCoordinator;
import androidx.compose.ui.unit.IntSize;
import kotlin.Metadata;
import kotlin.comparisons.ComparisonsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt;
/* compiled from: LayoutCoordinates.kt */
@Metadata(d1 = {"\u0000\u0016\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\u001a\n\u0010\u0000\u001a\u00020\u0001*\u00020\u0002\u001a\n\u0010\u0003\u001a\u00020\u0001*\u00020\u0002\u001a\n\u0010\u0004\u001a\u00020\u0001*\u00020\u0002\u001a\n\u0010\u0005\u001a\u00020\u0002*\u00020\u0002\u001a\u0012\u0010\u0006\u001a\u00020\u0007*\u00020\u0002ø\u0001\u0000¢\u0006\u0002\u0010\b\u001a\u0012\u0010\t\u001a\u00020\u0007*\u00020\u0002ø\u0001\u0000¢\u0006\u0002\u0010\b\u001a\u0012\u0010\n\u001a\u00020\u0007*\u00020\u0002ø\u0001\u0000¢\u0006\u0002\u0010\b\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\u000b"}, d2 = {"boundsInParent", "Landroidx/compose/ui/geometry/Rect;", "Landroidx/compose/ui/layout/LayoutCoordinates;", "boundsInRoot", "boundsInWindow", "findRootCoordinates", "positionInParent", "Landroidx/compose/ui/geometry/Offset;", "(Landroidx/compose/ui/layout/LayoutCoordinates;)J", "positionInRoot", "positionInWindow", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LayoutCoordinatesKt {
    public static final long positionInRoot(LayoutCoordinates $this$positionInRoot) {
        Intrinsics.checkNotNullParameter($this$positionInRoot, "<this>");
        return $this$positionInRoot.mo4132localToRootMKHz9U(Offset.Companion.m2384getZeroF1C5BW0());
    }

    public static final long positionInWindow(LayoutCoordinates $this$positionInWindow) {
        Intrinsics.checkNotNullParameter($this$positionInWindow, "<this>");
        return $this$positionInWindow.mo4133localToWindowMKHz9U(Offset.Companion.m2384getZeroF1C5BW0());
    }

    public static final Rect boundsInRoot(LayoutCoordinates $this$boundsInRoot) {
        Intrinsics.checkNotNullParameter($this$boundsInRoot, "<this>");
        return LayoutCoordinates.localBoundingBoxOf$default(findRootCoordinates($this$boundsInRoot), $this$boundsInRoot, false, 2, null);
    }

    public static final Rect boundsInWindow(LayoutCoordinates $this$boundsInWindow) {
        Intrinsics.checkNotNullParameter($this$boundsInWindow, "<this>");
        LayoutCoordinates root = findRootCoordinates($this$boundsInWindow);
        Rect bounds = boundsInRoot($this$boundsInWindow);
        float rootWidth = IntSize.m5282getWidthimpl(root.mo4130getSizeYbymL2g());
        float rootHeight = IntSize.m5281getHeightimpl(root.mo4130getSizeYbymL2g());
        float boundsLeft = RangesKt.coerceIn(bounds.getLeft(), 0.0f, rootWidth);
        float boundsTop = RangesKt.coerceIn(bounds.getTop(), 0.0f, rootHeight);
        float boundsRight = RangesKt.coerceIn(bounds.getRight(), 0.0f, rootWidth);
        float boundsBottom = RangesKt.coerceIn(bounds.getBottom(), 0.0f, rootHeight);
        if (!(boundsLeft == boundsRight)) {
            if (!(boundsTop == boundsBottom)) {
                long topLeft = root.mo4133localToWindowMKHz9U(OffsetKt.Offset(boundsLeft, boundsTop));
                long topRight = root.mo4133localToWindowMKHz9U(OffsetKt.Offset(boundsRight, boundsTop));
                long bottomRight = root.mo4133localToWindowMKHz9U(OffsetKt.Offset(boundsRight, boundsBottom));
                long bottomLeft = root.mo4133localToWindowMKHz9U(OffsetKt.Offset(boundsLeft, boundsBottom));
                float left = ComparisonsKt.minOf(Offset.m2368getXimpl(topLeft), Offset.m2368getXimpl(topRight), Offset.m2368getXimpl(bottomLeft), Offset.m2368getXimpl(bottomRight));
                float top = ComparisonsKt.minOf(Offset.m2369getYimpl(topLeft), Offset.m2369getYimpl(topRight), Offset.m2369getYimpl(bottomLeft), Offset.m2369getYimpl(bottomRight));
                float right = ComparisonsKt.maxOf(Offset.m2368getXimpl(topLeft), Offset.m2368getXimpl(topRight), Offset.m2368getXimpl(bottomLeft), Offset.m2368getXimpl(bottomRight));
                float bottom = ComparisonsKt.maxOf(Offset.m2369getYimpl(topLeft), Offset.m2369getYimpl(topRight), Offset.m2369getYimpl(bottomLeft), Offset.m2369getYimpl(bottomRight));
                return new Rect(left, top, right, bottom);
            }
        }
        return Rect.Companion.getZero();
    }

    public static final long positionInParent(LayoutCoordinates $this$positionInParent) {
        Intrinsics.checkNotNullParameter($this$positionInParent, "<this>");
        LayoutCoordinates parentLayoutCoordinates = $this$positionInParent.getParentLayoutCoordinates();
        return parentLayoutCoordinates != null ? parentLayoutCoordinates.mo4131localPositionOfR5De75A($this$positionInParent, Offset.Companion.m2384getZeroF1C5BW0()) : Offset.Companion.m2384getZeroF1C5BW0();
    }

    public static final Rect boundsInParent(LayoutCoordinates $this$boundsInParent) {
        Rect localBoundingBoxOf$default;
        Intrinsics.checkNotNullParameter($this$boundsInParent, "<this>");
        LayoutCoordinates parentLayoutCoordinates = $this$boundsInParent.getParentLayoutCoordinates();
        return (parentLayoutCoordinates == null || (localBoundingBoxOf$default = LayoutCoordinates.localBoundingBoxOf$default(parentLayoutCoordinates, $this$boundsInParent, false, 2, null)) == null) ? new Rect(0.0f, 0.0f, IntSize.m5282getWidthimpl($this$boundsInParent.mo4130getSizeYbymL2g()), IntSize.m5281getHeightimpl($this$boundsInParent.mo4130getSizeYbymL2g())) : localBoundingBoxOf$default;
    }

    public static final LayoutCoordinates findRootCoordinates(LayoutCoordinates $this$findRootCoordinates) {
        Intrinsics.checkNotNullParameter($this$findRootCoordinates, "<this>");
        LayoutCoordinates root = $this$findRootCoordinates;
        LayoutCoordinates parent = root.getParentLayoutCoordinates();
        while (parent != null) {
            root = parent;
            parent = root.getParentLayoutCoordinates();
        }
        NodeCoordinator rootCoordinator = root instanceof NodeCoordinator ? (NodeCoordinator) root : null;
        if (rootCoordinator == null) {
            return root;
        }
        for (NodeCoordinator parentCoordinator = rootCoordinator.getWrappedBy$ui_release(); parentCoordinator != null; parentCoordinator = parentCoordinator.getWrappedBy$ui_release()) {
            rootCoordinator = parentCoordinator;
        }
        return rootCoordinator;
    }
}
