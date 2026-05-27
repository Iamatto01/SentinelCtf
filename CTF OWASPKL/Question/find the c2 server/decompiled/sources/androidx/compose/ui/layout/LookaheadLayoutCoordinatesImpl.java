package androidx.compose.ui.layout;

import androidx.compose.ui.geometry.Offset;
import androidx.compose.ui.geometry.OffsetKt;
import androidx.compose.ui.geometry.Rect;
import androidx.compose.ui.node.LookaheadDelegate;
import androidx.compose.ui.node.NodeCoordinator;
import androidx.compose.ui.unit.IntOffset;
import androidx.compose.ui.unit.IntOffsetKt;
import java.util.Set;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.math.MathKt;
/* compiled from: LookaheadLayoutCoordinates.kt */
@Metadata(d1 = {"\u0000d\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\b\u0000\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0011\u0010\u001d\u001a\u00020\u001e2\u0006\u0010\u001f\u001a\u00020\u0016H\u0096\u0002J\u0018\u0010 \u001a\u00020!2\u0006\u0010\"\u001a\u00020\u000f2\u0006\u0010#\u001a\u00020\nH\u0016J%\u0010$\u001a\u00020%2\u0006\u0010\"\u001a\u00020\u00012\u0006\u0010&\u001a\u00020%H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b'\u0010(J%\u0010)\u001a\u00020%2\u0006\u0010\"\u001a\u00020\u000f2\u0006\u0010&\u001a\u00020%H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b*\u0010+J\u001d\u0010,\u001a\u00020%2\u0006\u0010-\u001a\u00020%H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b.\u0010/J\u001d\u00100\u001a\u00020%2\u0006\u0010-\u001a\u00020%H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b1\u0010/J%\u00102\u001a\u0002032\u0006\u0010\"\u001a\u00020\u000f2\u0006\u00104\u001a\u000205H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b6\u00107J\u001d\u00108\u001a\u00020%2\u0006\u00109\u001a\u00020%H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b:\u0010/R\u0011\u0010\u0005\u001a\u00020\u00068F¢\u0006\u0006\u001a\u0004\b\u0007\u0010\bR\u0014\u0010\t\u001a\u00020\n8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\t\u0010\u000bR\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\f\u0010\rR\u0016\u0010\u000e\u001a\u0004\u0018\u00010\u000f8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0010\u0010\u0011R\u0016\u0010\u0012\u001a\u0004\u0018\u00010\u000f8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0013\u0010\u0011R\u001a\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u00160\u00158VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0017\u0010\u0018R\u001d\u0010\u0019\u001a\u00020\u001a8VX\u0096\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0006\u001a\u0004\b\u001b\u0010\u001c\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u0006;"}, d2 = {"Landroidx/compose/ui/layout/LookaheadLayoutCoordinatesImpl;", "Landroidx/compose/ui/layout/LookaheadLayoutCoordinates;", "lookaheadDelegate", "Landroidx/compose/ui/node/LookaheadDelegate;", "(Landroidx/compose/ui/node/LookaheadDelegate;)V", "coordinator", "Landroidx/compose/ui/node/NodeCoordinator;", "getCoordinator", "()Landroidx/compose/ui/node/NodeCoordinator;", "isAttached", "", "()Z", "getLookaheadDelegate", "()Landroidx/compose/ui/node/LookaheadDelegate;", "parentCoordinates", "Landroidx/compose/ui/layout/LayoutCoordinates;", "getParentCoordinates", "()Landroidx/compose/ui/layout/LayoutCoordinates;", "parentLayoutCoordinates", "getParentLayoutCoordinates", "providedAlignmentLines", "", "Landroidx/compose/ui/layout/AlignmentLine;", "getProvidedAlignmentLines", "()Ljava/util/Set;", "size", "Landroidx/compose/ui/unit/IntSize;", "getSize-YbymL2g", "()J", "get", "", "alignmentLine", "localBoundingBoxOf", "Landroidx/compose/ui/geometry/Rect;", "sourceCoordinates", "clipBounds", "localLookaheadPositionOf", "Landroidx/compose/ui/geometry/Offset;", "relativeToSource", "localLookaheadPositionOf-R5De75A", "(Landroidx/compose/ui/layout/LookaheadLayoutCoordinates;J)J", "localPositionOf", "localPositionOf-R5De75A", "(Landroidx/compose/ui/layout/LayoutCoordinates;J)J", "localToRoot", "relativeToLocal", "localToRoot-MK-Hz9U", "(J)J", "localToWindow", "localToWindow-MK-Hz9U", "transformFrom", "", "matrix", "Landroidx/compose/ui/graphics/Matrix;", "transformFrom-EL8BTi8", "(Landroidx/compose/ui/layout/LayoutCoordinates;[F)V", "windowToLocal", "relativeToWindow", "windowToLocal-MK-Hz9U", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LookaheadLayoutCoordinatesImpl implements LookaheadLayoutCoordinates {
    private final LookaheadDelegate lookaheadDelegate;

    public LookaheadLayoutCoordinatesImpl(LookaheadDelegate lookaheadDelegate) {
        Intrinsics.checkNotNullParameter(lookaheadDelegate, "lookaheadDelegate");
        this.lookaheadDelegate = lookaheadDelegate;
    }

    public final LookaheadDelegate getLookaheadDelegate() {
        return this.lookaheadDelegate;
    }

    public final NodeCoordinator getCoordinator() {
        return this.lookaheadDelegate.getCoordinator();
    }

    @Override // androidx.compose.ui.layout.LookaheadLayoutCoordinates
    /* renamed from: localLookaheadPositionOf-R5De75A */
    public long mo4140localLookaheadPositionOfR5De75A(LookaheadLayoutCoordinates sourceCoordinates, long relativeToSource) {
        Intrinsics.checkNotNullParameter(sourceCoordinates, "sourceCoordinates");
        LookaheadDelegate source = ((LookaheadLayoutCoordinatesImpl) sourceCoordinates).lookaheadDelegate;
        NodeCoordinator commonAncestor = getCoordinator().findCommonAncestor$ui_release(source.getCoordinator());
        LookaheadDelegate ancestor = commonAncestor.getLookaheadDelegate$ui_release();
        if (ancestor != null) {
            long arg0$iv = source.m4279positionInBjo55l4$ui_release(ancestor);
            long $this$round_u2dk_u2d4lQ0M$iv = IntOffsetKt.IntOffset(MathKt.roundToInt(Offset.m2368getXimpl(relativeToSource)), MathKt.roundToInt(Offset.m2369getYimpl(relativeToSource)));
            long arg0$iv2 = IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(arg0$iv) + IntOffset.m5240getXimpl($this$round_u2dk_u2d4lQ0M$iv), IntOffset.m5241getYimpl(arg0$iv) + IntOffset.m5241getYimpl($this$round_u2dk_u2d4lQ0M$iv));
            long other$iv = this.lookaheadDelegate.m4279positionInBjo55l4$ui_release(ancestor);
            long arg0$iv3 = IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(arg0$iv2) - IntOffset.m5240getXimpl(other$iv), IntOffset.m5241getYimpl(arg0$iv2) - IntOffset.m5241getYimpl(other$iv));
            long $this$toOffset_u2d_u2dgyyYBs$iv = OffsetKt.Offset(IntOffset.m5240getXimpl(arg0$iv3), IntOffset.m5241getYimpl(arg0$iv3));
            return $this$toOffset_u2d_u2dgyyYBs$iv;
        }
        LookaheadDelegate sourceRoot = LookaheadLayoutCoordinatesKt.access$getRootLookaheadDelegate(source);
        long arg0$iv4 = source.m4279positionInBjo55l4$ui_release(sourceRoot);
        long other$iv2 = sourceRoot.mo4276getPositionnOccac();
        long arg0$iv5 = IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(arg0$iv4) + IntOffset.m5240getXimpl(other$iv2), IntOffset.m5241getYimpl(arg0$iv4) + IntOffset.m5241getYimpl(other$iv2));
        long $this$round_u2dk_u2d4lQ0M$iv2 = IntOffsetKt.IntOffset(MathKt.roundToInt(Offset.m2368getXimpl(relativeToSource)), MathKt.roundToInt(Offset.m2369getYimpl(relativeToSource)));
        long arg0$iv6 = IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(arg0$iv5) + IntOffset.m5240getXimpl($this$round_u2dk_u2d4lQ0M$iv2), IntOffset.m5241getYimpl(arg0$iv5) + IntOffset.m5241getYimpl($this$round_u2dk_u2d4lQ0M$iv2));
        LookaheadDelegate $this$localLookaheadPositionOf_R5De75A_u24lambda_u242_u24lambda_u241 = this.lookaheadDelegate;
        long arg0$iv7 = $this$localLookaheadPositionOf_R5De75A_u24lambda_u242_u24lambda_u241.m4279positionInBjo55l4$ui_release(LookaheadLayoutCoordinatesKt.access$getRootLookaheadDelegate($this$localLookaheadPositionOf_R5De75A_u24lambda_u242_u24lambda_u241));
        long other$iv3 = LookaheadLayoutCoordinatesKt.access$getRootLookaheadDelegate($this$localLookaheadPositionOf_R5De75A_u24lambda_u242_u24lambda_u241).mo4276getPositionnOccac();
        long other$iv4 = IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(arg0$iv7) + IntOffset.m5240getXimpl(other$iv3), IntOffset.m5241getYimpl(arg0$iv7) + IntOffset.m5241getYimpl(other$iv3));
        long other$iv5 = IntOffsetKt.IntOffset(IntOffset.m5240getXimpl(arg0$iv6) - IntOffset.m5240getXimpl(other$iv4), IntOffset.m5241getYimpl(arg0$iv6) - IntOffset.m5241getYimpl(other$iv4));
        NodeCoordinator wrappedBy$ui_release = LookaheadLayoutCoordinatesKt.access$getRootLookaheadDelegate(this.lookaheadDelegate).getCoordinator().getWrappedBy$ui_release();
        Intrinsics.checkNotNull(wrappedBy$ui_release);
        NodeCoordinator wrappedBy$ui_release2 = sourceRoot.getCoordinator().getWrappedBy$ui_release();
        Intrinsics.checkNotNull(wrappedBy$ui_release2);
        long $this$toOffset_u2d_u2dgyyYBs$iv2 = OffsetKt.Offset(IntOffset.m5240getXimpl(other$iv5), IntOffset.m5241getYimpl(other$iv5));
        return wrappedBy$ui_release.mo4131localPositionOfR5De75A(wrappedBy$ui_release2, $this$toOffset_u2d_u2dgyyYBs$iv2);
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    /* renamed from: getSize-YbymL2g */
    public long mo4130getSizeYbymL2g() {
        return getCoordinator().mo4130getSizeYbymL2g();
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    public Set<AlignmentLine> getProvidedAlignmentLines() {
        return getCoordinator().getProvidedAlignmentLines();
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    public LayoutCoordinates getParentLayoutCoordinates() {
        return getCoordinator().getParentLayoutCoordinates();
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    public LayoutCoordinates getParentCoordinates() {
        return getCoordinator().getParentCoordinates();
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    public boolean isAttached() {
        return getCoordinator().isAttached();
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    /* renamed from: windowToLocal-MK-Hz9U */
    public long mo4135windowToLocalMKHz9U(long relativeToWindow) {
        return getCoordinator().mo4135windowToLocalMKHz9U(relativeToWindow);
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    /* renamed from: localToWindow-MK-Hz9U */
    public long mo4133localToWindowMKHz9U(long relativeToLocal) {
        return getCoordinator().mo4133localToWindowMKHz9U(relativeToLocal);
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    /* renamed from: localToRoot-MK-Hz9U */
    public long mo4132localToRootMKHz9U(long relativeToLocal) {
        return getCoordinator().mo4132localToRootMKHz9U(relativeToLocal);
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    /* renamed from: localPositionOf-R5De75A */
    public long mo4131localPositionOfR5De75A(LayoutCoordinates sourceCoordinates, long relativeToSource) {
        Intrinsics.checkNotNullParameter(sourceCoordinates, "sourceCoordinates");
        return getCoordinator().mo4131localPositionOfR5De75A(sourceCoordinates, relativeToSource);
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    public Rect localBoundingBoxOf(LayoutCoordinates sourceCoordinates, boolean clipBounds) {
        Intrinsics.checkNotNullParameter(sourceCoordinates, "sourceCoordinates");
        return getCoordinator().localBoundingBoxOf(sourceCoordinates, clipBounds);
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    /* renamed from: transformFrom-EL8BTi8 */
    public void mo4134transformFromEL8BTi8(LayoutCoordinates sourceCoordinates, float[] matrix) {
        Intrinsics.checkNotNullParameter(sourceCoordinates, "sourceCoordinates");
        Intrinsics.checkNotNullParameter(matrix, "matrix");
        getCoordinator().mo4134transformFromEL8BTi8(sourceCoordinates, matrix);
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    public int get(AlignmentLine alignmentLine) {
        Intrinsics.checkNotNullParameter(alignmentLine, "alignmentLine");
        return getCoordinator().get(alignmentLine);
    }
}
