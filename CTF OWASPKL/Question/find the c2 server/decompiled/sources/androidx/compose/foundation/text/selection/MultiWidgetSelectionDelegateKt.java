package androidx.compose.foundation.text.selection;

import androidx.compose.foundation.text.selection.Selection;
import androidx.compose.ui.geometry.Offset;
import androidx.compose.ui.geometry.Rect;
import androidx.compose.ui.text.TextLayoutResult;
import androidx.compose.ui.text.TextRange;
import androidx.compose.ui.text.TextRangeKt;
import androidx.compose.ui.unit.IntSize;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt;
/* compiled from: MultiWidgetSelectionDelegate.kt */
@Metadata(d1 = {"\u0000F\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\u001a5\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\n\u0010\u000b\u001a-\u0010\f\u001a\u00020\r2\u0006\u0010\b\u001a\u00020\t2\u0006\u0010\u000e\u001a\u00020\u000f2\u0006\u0010\u0010\u001a\u00020\u0011H\u0000ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0012\u0010\u0013\u001ak\u0010\u0014\u001a\u0010\u0012\u0006\u0012\u0004\u0018\u00010\u0001\u0012\u0004\u0012\u00020\u00050\u00152\u0006\u0010\b\u001a\u00020\t2\u0006\u0010\u0016\u001a\u00020\u00112\u0006\u0010\u0017\u001a\u00020\u00112\b\u0010\u0018\u001a\u0004\u0018\u00010\u00112\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u0019\u001a\u00020\u001a2\n\b\u0002\u0010\u001b\u001a\u0004\u0018\u00010\u00012\b\b\u0002\u0010\u001c\u001a\u00020\u0005H\u0000ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001d\u0010\u001e\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006\u001f"}, d2 = {"getAssembledSelectionInfo", "Landroidx/compose/foundation/text/selection/Selection;", "newSelectionRange", "Landroidx/compose/ui/text/TextRange;", "handlesCrossed", "", "selectableId", "", "textLayoutResult", "Landroidx/compose/ui/text/TextLayoutResult;", "getAssembledSelectionInfo-vJH6DeI", "(JZJLandroidx/compose/ui/text/TextLayoutResult;)Landroidx/compose/foundation/text/selection/Selection;", "getOffsetForPosition", "", "bounds", "Landroidx/compose/ui/geometry/Rect;", "position", "Landroidx/compose/ui/geometry/Offset;", "getOffsetForPosition-0AR0LA0", "(Landroidx/compose/ui/text/TextLayoutResult;Landroidx/compose/ui/geometry/Rect;J)I", "getTextSelectionInfo", "Lkotlin/Pair;", "startHandlePosition", "endHandlePosition", "previousHandlePosition", "adjustment", "Landroidx/compose/foundation/text/selection/SelectionAdjustment;", "previousSelection", "isStartHandle", "getTextSelectionInfo-yM0VcXU", "(Landroidx/compose/ui/text/TextLayoutResult;JJLandroidx/compose/ui/geometry/Offset;JLandroidx/compose/foundation/text/selection/SelectionAdjustment;Landroidx/compose/foundation/text/selection/Selection;Z)Lkotlin/Pair;", "foundation_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class MultiWidgetSelectionDelegateKt {
    /* renamed from: access$getAssembledSelectionInfo-vJH6DeI */
    public static final /* synthetic */ Selection m809access$getAssembledSelectionInfovJH6DeI(long newSelectionRange, boolean handlesCrossed, long selectableId, TextLayoutResult textLayoutResult) {
        return m810getAssembledSelectionInfovJH6DeI(newSelectionRange, handlesCrossed, selectableId, textLayoutResult);
    }

    /* renamed from: getTextSelectionInfo-yM0VcXU$default */
    public static /* synthetic */ Pair m813getTextSelectionInfoyM0VcXU$default(TextLayoutResult textLayoutResult, long j, long j2, Offset offset, long j3, SelectionAdjustment selectionAdjustment, Selection selection, boolean z, int i, Object obj) {
        Selection selection2;
        boolean z2;
        if ((i & 64) == 0) {
            selection2 = selection;
        } else {
            selection2 = null;
        }
        if ((i & 128) == 0) {
            z2 = z;
        } else {
            z2 = true;
        }
        return m812getTextSelectionInfoyM0VcXU(textLayoutResult, j, j2, offset, j3, selectionAdjustment, selection2, z2);
    }

    /* renamed from: getTextSelectionInfo-yM0VcXU */
    public static final Pair<Selection, Boolean> m812getTextSelectionInfoyM0VcXU(TextLayoutResult textLayoutResult, long startHandlePosition, long endHandlePosition, Offset previousHandlePosition, long selectableId, SelectionAdjustment adjustment, Selection previousSelection, boolean isStartHandle) {
        int i;
        boolean handleUpdated;
        Intrinsics.checkNotNullParameter(textLayoutResult, "textLayoutResult");
        Intrinsics.checkNotNullParameter(adjustment, "adjustment");
        Rect bounds = new Rect(0.0f, 0.0f, IntSize.m5282getWidthimpl(textLayoutResult.m4610getSizeYbymL2g()), IntSize.m5281getHeightimpl(textLayoutResult.m4610getSizeYbymL2g()));
        boolean isSelected = SelectionMode.Vertical.m864isSelected2x9bVx0$foundation_release(bounds, startHandlePosition, endHandlePosition);
        boolean z = false;
        if (!isSelected) {
            return new Pair<>(null, false);
        }
        int rawStartHandleOffset = m811getOffsetForPosition0AR0LA0(textLayoutResult, bounds, startHandlePosition);
        int rawEndHandleOffset = m811getOffsetForPosition0AR0LA0(textLayoutResult, bounds, endHandlePosition);
        if (previousHandlePosition != null) {
            long it = previousHandlePosition.m2378unboximpl();
            i = m811getOffsetForPosition0AR0LA0(textLayoutResult, bounds, it);
        } else {
            i = -1;
        }
        int rawPreviousHandleOffset = i;
        long adjustedTextRange = adjustment.mo816adjustZXO7KMw(textLayoutResult, TextRangeKt.TextRange(rawStartHandleOffset, rawEndHandleOffset), rawPreviousHandleOffset, isStartHandle, previousSelection != null ? TextRange.m4625boximpl(previousSelection.m815toTextRanged9O1mEE()) : null);
        Selection newSelection = m810getAssembledSelectionInfovJH6DeI(adjustedTextRange, TextRange.m4636getReversedimpl(adjustedTextRange), selectableId, textLayoutResult);
        boolean selectionUpdated = !Intrinsics.areEqual(newSelection, previousSelection);
        if (isStartHandle) {
            handleUpdated = rawStartHandleOffset != rawPreviousHandleOffset;
        } else {
            handleUpdated = rawEndHandleOffset != rawPreviousHandleOffset;
        }
        if (handleUpdated || selectionUpdated) {
            z = true;
        }
        boolean consumed = z;
        return new Pair<>(newSelection, Boolean.valueOf(consumed));
    }

    /* renamed from: getOffsetForPosition-0AR0LA0 */
    public static final int m811getOffsetForPosition0AR0LA0(TextLayoutResult textLayoutResult, Rect bounds, long position) {
        Intrinsics.checkNotNullParameter(textLayoutResult, "textLayoutResult");
        Intrinsics.checkNotNullParameter(bounds, "bounds");
        int length = textLayoutResult.getLayoutInput().getText().length();
        if (bounds.m2394containsk4lQ0M(position)) {
            return RangesKt.coerceIn(textLayoutResult.m4609getOffsetForPositionk4lQ0M(position), 0, length);
        }
        int value = SelectionMode.Vertical.mo863compare3MmeM6k$foundation_release(position, bounds);
        if (value < 0) {
            return 0;
        }
        return length;
    }

    /* renamed from: getAssembledSelectionInfo-vJH6DeI */
    public static final Selection m810getAssembledSelectionInfovJH6DeI(long newSelectionRange, boolean handlesCrossed, long selectableId, TextLayoutResult textLayoutResult) {
        return new Selection(new Selection.AnchorInfo(textLayoutResult.getBidiRunDirection(TextRange.m4637getStartimpl(newSelectionRange)), TextRange.m4637getStartimpl(newSelectionRange), selectableId), new Selection.AnchorInfo(textLayoutResult.getBidiRunDirection(Math.max(TextRange.m4632getEndimpl(newSelectionRange) - 1, 0)), TextRange.m4632getEndimpl(newSelectionRange), selectableId), handlesCrossed);
    }
}
