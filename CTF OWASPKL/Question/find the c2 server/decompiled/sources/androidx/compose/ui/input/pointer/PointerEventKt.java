package androidx.compose.ui.input.pointer;

import androidx.compose.ui.geometry.Offset;
import androidx.compose.ui.geometry.Size;
import androidx.compose.ui.unit.IntSize;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.ReplaceWith;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: PointerEvent.kt */
@Metadata(d1 = {"\u0000.\n\u0000\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\t\u001a\f\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0007\u001a\n\u0010\u0003\u001a\u00020\u0001*\u00020\u0002\u001a\n\u0010\u0004\u001a\u00020\u0001*\u00020\u0002\u001a\n\u0010\u0005\u001a\u00020\u0001*\u00020\u0002\u001a\n\u0010\u0006\u001a\u00020\u0001*\u00020\u0002\u001a\f\u0010\u0007\u001a\u00020\b*\u00020\u0002H\u0007\u001a\f\u0010\t\u001a\u00020\b*\u00020\u0002H\u0007\u001a\f\u0010\n\u001a\u00020\b*\u00020\u0002H\u0007\u001a!\u0010\u000b\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\f\u001a\u00020\rH\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u000e\u0010\u000f\u001a'\u0010\u000b\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\f\u001a\u00020\r2\u0006\u0010\u0010\u001a\u00020\u0011ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0012\u0010\u0013\u001a\u0012\u0010\u0014\u001a\u00020\u0015*\u00020\u0002ø\u0001\u0001¢\u0006\u0002\u0010\u0016\u001a\f\u0010\u0017\u001a\u00020\u0001*\u00020\u0002H\u0007\u001a\u0012\u0010\u0018\u001a\u00020\u0015*\u00020\u0002ø\u0001\u0001¢\u0006\u0002\u0010\u0016\u001a\u001e\u0010\u0019\u001a\u00020\u0015*\u00020\u00022\b\b\u0002\u0010\u001a\u001a\u00020\u0001H\u0002ø\u0001\u0001¢\u0006\u0002\u0010\u001b\u001a\n\u0010\u001c\u001a\u00020\u0001*\u00020\u0002\u001a\n\u0010\u001d\u001a\u00020\u0001*\u00020\u0002\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006\u001e"}, d2 = {"anyChangeConsumed", "", "Landroidx/compose/ui/input/pointer/PointerInputChange;", "changedToDown", "changedToDownIgnoreConsumed", "changedToUp", "changedToUpIgnoreConsumed", "consumeAllChanges", "", "consumeDownChange", "consumePositionChange", "isOutOfBounds", "size", "Landroidx/compose/ui/unit/IntSize;", "isOutOfBounds-O0kMr_c", "(Landroidx/compose/ui/input/pointer/PointerInputChange;J)Z", "extendedTouchPadding", "Landroidx/compose/ui/geometry/Size;", "isOutOfBounds-jwHxaWs", "(Landroidx/compose/ui/input/pointer/PointerInputChange;JJ)Z", "positionChange", "Landroidx/compose/ui/geometry/Offset;", "(Landroidx/compose/ui/input/pointer/PointerInputChange;)J", "positionChangeConsumed", "positionChangeIgnoreConsumed", "positionChangeInternal", "ignoreConsumed", "(Landroidx/compose/ui/input/pointer/PointerInputChange;Z)J", "positionChanged", "positionChangedIgnoreConsumed", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class PointerEventKt {
    public static final boolean changedToDown(PointerInputChange $this$changedToDown) {
        Intrinsics.checkNotNullParameter($this$changedToDown, "<this>");
        return ($this$changedToDown.isConsumed() || $this$changedToDown.getPreviousPressed() || !$this$changedToDown.getPressed()) ? false : true;
    }

    public static final boolean changedToDownIgnoreConsumed(PointerInputChange $this$changedToDownIgnoreConsumed) {
        Intrinsics.checkNotNullParameter($this$changedToDownIgnoreConsumed, "<this>");
        return !$this$changedToDownIgnoreConsumed.getPreviousPressed() && $this$changedToDownIgnoreConsumed.getPressed();
    }

    public static final boolean changedToUp(PointerInputChange $this$changedToUp) {
        Intrinsics.checkNotNullParameter($this$changedToUp, "<this>");
        return ($this$changedToUp.isConsumed() || !$this$changedToUp.getPreviousPressed() || $this$changedToUp.getPressed()) ? false : true;
    }

    public static final boolean changedToUpIgnoreConsumed(PointerInputChange $this$changedToUpIgnoreConsumed) {
        Intrinsics.checkNotNullParameter($this$changedToUpIgnoreConsumed, "<this>");
        return $this$changedToUpIgnoreConsumed.getPreviousPressed() && !$this$changedToUpIgnoreConsumed.getPressed();
    }

    public static final boolean positionChanged(PointerInputChange $this$positionChanged) {
        Intrinsics.checkNotNullParameter($this$positionChanged, "<this>");
        return !Offset.m2365equalsimpl0(positionChangeInternal($this$positionChanged, false), Offset.Companion.m2384getZeroF1C5BW0());
    }

    public static final boolean positionChangedIgnoreConsumed(PointerInputChange $this$positionChangedIgnoreConsumed) {
        Intrinsics.checkNotNullParameter($this$positionChangedIgnoreConsumed, "<this>");
        return true ^ Offset.m2365equalsimpl0(positionChangeInternal($this$positionChangedIgnoreConsumed, true), Offset.Companion.m2384getZeroF1C5BW0());
    }

    public static final long positionChange(PointerInputChange $this$positionChange) {
        Intrinsics.checkNotNullParameter($this$positionChange, "<this>");
        return positionChangeInternal($this$positionChange, false);
    }

    public static final long positionChangeIgnoreConsumed(PointerInputChange $this$positionChangeIgnoreConsumed) {
        Intrinsics.checkNotNullParameter($this$positionChangeIgnoreConsumed, "<this>");
        return positionChangeInternal($this$positionChangeIgnoreConsumed, true);
    }

    static /* synthetic */ long positionChangeInternal$default(PointerInputChange pointerInputChange, boolean z, int i, Object obj) {
        if ((i & 1) != 0) {
            z = false;
        }
        return positionChangeInternal(pointerInputChange, z);
    }

    private static final long positionChangeInternal(PointerInputChange $this$positionChangeInternal, boolean ignoreConsumed) {
        long previousPosition = $this$positionChangeInternal.m4008getPreviousPositionF1C5BW0();
        long currentPosition = $this$positionChangeInternal.m4007getPositionF1C5BW0();
        long offset = Offset.m2372minusMKHz9U(currentPosition, previousPosition);
        return (ignoreConsumed || !$this$positionChangeInternal.isConsumed()) ? offset : Offset.Companion.m2384getZeroF1C5BW0();
    }

    @Deprecated(message = "Partial consumption has been deprecated. Use isConsumed instead", replaceWith = @ReplaceWith(expression = "isConsumed", imports = {}))
    public static final boolean positionChangeConsumed(PointerInputChange $this$positionChangeConsumed) {
        Intrinsics.checkNotNullParameter($this$positionChangeConsumed, "<this>");
        return $this$positionChangeConsumed.isConsumed();
    }

    @Deprecated(message = "Partial consumption has been deprecated. Use isConsumed instead", replaceWith = @ReplaceWith(expression = "isConsumed", imports = {}))
    public static final boolean anyChangeConsumed(PointerInputChange $this$anyChangeConsumed) {
        Intrinsics.checkNotNullParameter($this$anyChangeConsumed, "<this>");
        return $this$anyChangeConsumed.isConsumed();
    }

    @Deprecated(message = "Partial consumption has been deprecated. Use consume() instead.", replaceWith = @ReplaceWith(expression = "if (pressed != previousPressed) consume()", imports = {}))
    public static final void consumeDownChange(PointerInputChange $this$consumeDownChange) {
        Intrinsics.checkNotNullParameter($this$consumeDownChange, "<this>");
        if ($this$consumeDownChange.getPressed() != $this$consumeDownChange.getPreviousPressed()) {
            $this$consumeDownChange.consume();
        }
    }

    @Deprecated(message = "Partial consumption has been deprecated. Use consume() instead.", replaceWith = @ReplaceWith(expression = "if (positionChange() != Offset.Zero) consume()", imports = {}))
    public static final void consumePositionChange(PointerInputChange $this$consumePositionChange) {
        Intrinsics.checkNotNullParameter($this$consumePositionChange, "<this>");
        if (!Offset.m2365equalsimpl0(positionChange($this$consumePositionChange), Offset.Companion.m2384getZeroF1C5BW0())) {
            $this$consumePositionChange.consume();
        }
    }

    @Deprecated(message = "Use consume() instead", replaceWith = @ReplaceWith(expression = "consume()", imports = {}))
    public static final void consumeAllChanges(PointerInputChange $this$consumeAllChanges) {
        Intrinsics.checkNotNullParameter($this$consumeAllChanges, "<this>");
        $this$consumeAllChanges.consume();
    }

    @Deprecated(message = "Use isOutOfBounds() that supports minimum touch target", replaceWith = @ReplaceWith(expression = "this.isOutOfBounds(size, extendedTouchPadding)", imports = {}))
    /* renamed from: isOutOfBounds-O0kMr_c  reason: not valid java name */
    public static final boolean m3954isOutOfBoundsO0kMr_c(PointerInputChange isOutOfBounds, long size) {
        Intrinsics.checkNotNullParameter(isOutOfBounds, "$this$isOutOfBounds");
        long position = isOutOfBounds.m4007getPositionF1C5BW0();
        float x = Offset.m2368getXimpl(position);
        float y = Offset.m2369getYimpl(position);
        int width = IntSize.m5282getWidthimpl(size);
        int height = IntSize.m5281getHeightimpl(size);
        return x < 0.0f || x > ((float) width) || y < 0.0f || y > ((float) height);
    }

    /* renamed from: isOutOfBounds-jwHxaWs  reason: not valid java name */
    public static final boolean m3955isOutOfBoundsjwHxaWs(PointerInputChange isOutOfBounds, long size, long extendedTouchPadding) {
        Intrinsics.checkNotNullParameter(isOutOfBounds, "$this$isOutOfBounds");
        if (!PointerType.m4078equalsimpl0(isOutOfBounds.m4010getTypeT8wyACA(), PointerType.Companion.m4085getTouchT8wyACA())) {
            return m3954isOutOfBoundsO0kMr_c(isOutOfBounds, size);
        }
        long position = isOutOfBounds.m4007getPositionF1C5BW0();
        float x = Offset.m2368getXimpl(position);
        float y = Offset.m2369getYimpl(position);
        float minX = -Size.m2437getWidthimpl(extendedTouchPadding);
        float maxX = IntSize.m5282getWidthimpl(size) + Size.m2437getWidthimpl(extendedTouchPadding);
        float minY = -Size.m2434getHeightimpl(extendedTouchPadding);
        float maxY = IntSize.m5281getHeightimpl(size) + Size.m2434getHeightimpl(extendedTouchPadding);
        return x < minX || x > maxX || y < minY || y > maxY;
    }
}
