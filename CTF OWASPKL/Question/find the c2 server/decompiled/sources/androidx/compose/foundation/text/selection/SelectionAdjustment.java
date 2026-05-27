package androidx.compose.foundation.text.selection;

import androidx.compose.foundation.text.selection.SelectionAdjustment;
import androidx.compose.ui.text.TextLayoutResult;
import androidx.compose.ui.text.TextRange;
import androidx.compose.ui.text.TextRangeKt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt;
import kotlin.reflect.KFunction;
import kotlin.text.StringsKt;
/* compiled from: SelectionAdjustment.kt */
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0005\b`\u0018\u0000 \u000e2\u00020\u0001:\u0001\u000eJ?\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00032\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\n2\b\u0010\u000b\u001a\u0004\u0018\u00010\u0003H&ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\f\u0010\rø\u0001\u0002\u0082\u0002\u0011\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019\n\u0004\b!0\u0001¨\u0006\u000fÀ\u0006\u0001"}, d2 = {"Landroidx/compose/foundation/text/selection/SelectionAdjustment;", "", "adjust", "Landroidx/compose/ui/text/TextRange;", "textLayoutResult", "Landroidx/compose/ui/text/TextLayoutResult;", "newRawSelectionRange", "previousHandleOffset", "", "isStartHandle", "", "previousSelectionRange", "adjust-ZXO7KMw", "(Landroidx/compose/ui/text/TextLayoutResult;JIZLandroidx/compose/ui/text/TextRange;)J", "Companion", "foundation_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public interface SelectionAdjustment {
    public static final Companion Companion = Companion.$$INSTANCE;

    /* renamed from: adjust-ZXO7KMw  reason: not valid java name */
    long mo816adjustZXO7KMw(TextLayoutResult textLayoutResult, long j, int i, boolean z, TextRange textRange);

    /* compiled from: SelectionAdjustment.kt */
    @Metadata(d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0003\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J9\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00102\u0012\u0010\u0014\u001a\u000e\u0012\u0004\u0012\u00020\u0016\u0012\u0004\u0012\u00020\u00100\u0015H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0017\u0010\u0018R\u0011\u0010\u0003\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0005\u0010\u0006R\u0011\u0010\u0007\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\b\u0010\u0006R\u0011\u0010\t\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\n\u0010\u0006R\u0011\u0010\u000b\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\f\u0010\u0006R\u0011\u0010\r\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u000e\u0010\u0006\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006\u0019"}, d2 = {"Landroidx/compose/foundation/text/selection/SelectionAdjustment$Companion;", "", "()V", "Character", "Landroidx/compose/foundation/text/selection/SelectionAdjustment;", "getCharacter", "()Landroidx/compose/foundation/text/selection/SelectionAdjustment;", "CharacterWithWordAccelerate", "getCharacterWithWordAccelerate", "None", "getNone", "Paragraph", "getParagraph", "Word", "getWord", "adjustByBoundary", "Landroidx/compose/ui/text/TextRange;", "textLayoutResult", "Landroidx/compose/ui/text/TextLayoutResult;", "newRawSelection", "boundaryFun", "Lkotlin/Function1;", "", "adjustByBoundary--Dv-ylE", "(Landroidx/compose/ui/text/TextLayoutResult;JLkotlin/jvm/functions/Function1;)J", "foundation_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class Companion {
        static final /* synthetic */ Companion $$INSTANCE = new Companion();
        private static final SelectionAdjustment None = new SelectionAdjustment() { // from class: androidx.compose.foundation.text.selection.SelectionAdjustment$Companion$None$1
            @Override // androidx.compose.foundation.text.selection.SelectionAdjustment
            /* renamed from: adjust-ZXO7KMw */
            public long mo816adjustZXO7KMw(TextLayoutResult textLayoutResult, long newRawSelectionRange, int previousHandleOffset, boolean isStartHandle, TextRange previousSelectionRange) {
                Intrinsics.checkNotNullParameter(textLayoutResult, "textLayoutResult");
                return newRawSelectionRange;
            }
        };
        private static final SelectionAdjustment Character = new SelectionAdjustment() { // from class: androidx.compose.foundation.text.selection.SelectionAdjustment$Companion$Character$1
            @Override // androidx.compose.foundation.text.selection.SelectionAdjustment
            /* renamed from: adjust-ZXO7KMw */
            public long mo816adjustZXO7KMw(TextLayoutResult textLayoutResult, long newRawSelectionRange, int previousHandleOffset, boolean isStartHandle, TextRange previousSelectionRange) {
                Intrinsics.checkNotNullParameter(textLayoutResult, "textLayoutResult");
                if (TextRange.m4631getCollapsedimpl(newRawSelectionRange)) {
                    boolean previousHandlesCrossed = previousSelectionRange != null ? TextRange.m4636getReversedimpl(previousSelectionRange.m4641unboximpl()) : false;
                    return SelectionAdjustmentKt.ensureAtLeastOneChar(textLayoutResult.getLayoutInput().getText().getText(), TextRange.m4637getStartimpl(newRawSelectionRange), StringsKt.getLastIndex(textLayoutResult.getLayoutInput().getText()), isStartHandle, previousHandlesCrossed);
                }
                return newRawSelectionRange;
            }
        };
        private static final SelectionAdjustment Word = new SelectionAdjustment() { // from class: androidx.compose.foundation.text.selection.SelectionAdjustment$Companion$Word$1
            @Override // androidx.compose.foundation.text.selection.SelectionAdjustment
            /* renamed from: adjust-ZXO7KMw */
            public long mo816adjustZXO7KMw(TextLayoutResult textLayoutResult, long newRawSelectionRange, int previousHandleOffset, boolean isStartHandle, TextRange previousSelectionRange) {
                long m818adjustByBoundaryDvylE;
                Intrinsics.checkNotNullParameter(textLayoutResult, "textLayoutResult");
                m818adjustByBoundaryDvylE = SelectionAdjustment.Companion.$$INSTANCE.m818adjustByBoundaryDvylE(textLayoutResult, newRawSelectionRange, new SelectionAdjustment$Companion$Word$1$adjust$1(textLayoutResult));
                return m818adjustByBoundaryDvylE;
            }
        };
        private static final SelectionAdjustment Paragraph = new SelectionAdjustment() { // from class: androidx.compose.foundation.text.selection.SelectionAdjustment$Companion$Paragraph$1
            @Override // androidx.compose.foundation.text.selection.SelectionAdjustment
            /* renamed from: adjust-ZXO7KMw */
            public long mo816adjustZXO7KMw(TextLayoutResult textLayoutResult, long newRawSelectionRange, int previousHandleOffset, boolean isStartHandle, TextRange previousSelectionRange) {
                long m818adjustByBoundaryDvylE;
                Intrinsics.checkNotNullParameter(textLayoutResult, "textLayoutResult");
                KFunction boundaryFun = new SelectionAdjustment$Companion$Paragraph$1$adjust$boundaryFun$1(textLayoutResult.getLayoutInput().getText());
                m818adjustByBoundaryDvylE = SelectionAdjustment.Companion.$$INSTANCE.m818adjustByBoundaryDvylE(textLayoutResult, newRawSelectionRange, (Function1) boundaryFun);
                return m818adjustByBoundaryDvylE;
            }
        };
        private static final SelectionAdjustment CharacterWithWordAccelerate = new SelectionAdjustment() { // from class: androidx.compose.foundation.text.selection.SelectionAdjustment$Companion$CharacterWithWordAccelerate$1
            @Override // androidx.compose.foundation.text.selection.SelectionAdjustment
            /* renamed from: adjust-ZXO7KMw */
            public long mo816adjustZXO7KMw(TextLayoutResult textLayoutResult, long newRawSelectionRange, int previousHandleOffset, boolean isStartHandle, TextRange previousSelectionRange) {
                int start;
                int end;
                Intrinsics.checkNotNullParameter(textLayoutResult, "textLayoutResult");
                if (previousSelectionRange == null) {
                    return SelectionAdjustment.Companion.$$INSTANCE.getWord().mo816adjustZXO7KMw(textLayoutResult, newRawSelectionRange, previousHandleOffset, isStartHandle, previousSelectionRange);
                }
                if (TextRange.m4631getCollapsedimpl(newRawSelectionRange)) {
                    return SelectionAdjustmentKt.ensureAtLeastOneChar(textLayoutResult.getLayoutInput().getText().getText(), TextRange.m4637getStartimpl(newRawSelectionRange), StringsKt.getLastIndex(textLayoutResult.getLayoutInput().getText()), isStartHandle, TextRange.m4636getReversedimpl(previousSelectionRange.m4641unboximpl()));
                }
                if (isStartHandle) {
                    start = updateSelectionBoundary(textLayoutResult, TextRange.m4637getStartimpl(newRawSelectionRange), previousHandleOffset, TextRange.m4637getStartimpl(previousSelectionRange.m4641unboximpl()), TextRange.m4632getEndimpl(newRawSelectionRange), true, TextRange.m4636getReversedimpl(newRawSelectionRange));
                    end = TextRange.m4632getEndimpl(newRawSelectionRange);
                } else {
                    start = TextRange.m4637getStartimpl(newRawSelectionRange);
                    end = updateSelectionBoundary(textLayoutResult, TextRange.m4632getEndimpl(newRawSelectionRange), previousHandleOffset, TextRange.m4632getEndimpl(previousSelectionRange.m4641unboximpl()), TextRange.m4637getStartimpl(newRawSelectionRange), false, TextRange.m4636getReversedimpl(newRawSelectionRange));
                }
                return TextRangeKt.TextRange(start, end);
            }

            private final int updateSelectionBoundary(TextLayoutResult textLayoutResult, int newRawOffset, int previousRawOffset, int previousAdjustedOffset, int otherBoundaryOffset, boolean isStart, boolean isReversed) {
                if (newRawOffset == previousRawOffset) {
                    return previousAdjustedOffset;
                }
                int currentLine = textLayoutResult.getLineForOffset(newRawOffset);
                int previousLine = textLayoutResult.getLineForOffset(previousAdjustedOffset);
                if (currentLine == previousLine) {
                    boolean isExpanding = isExpanding(newRawOffset, previousRawOffset, isStart, isReversed);
                    return (isExpanding && isAtWordBoundary(textLayoutResult, previousAdjustedOffset)) ? snapToWordBoundary(textLayoutResult, newRawOffset, currentLine, otherBoundaryOffset, isStart, isReversed) : newRawOffset;
                }
                return snapToWordBoundary(textLayoutResult, newRawOffset, currentLine, otherBoundaryOffset, isStart, isReversed);
            }

            private final int snapToWordBoundary(TextLayoutResult textLayoutResult, int newRawOffset, int currentLine, int otherBoundaryOffset, boolean isStart, boolean isReversed) {
                int start;
                int end;
                long wordBoundary = textLayoutResult.m4611getWordBoundaryjx7JFs(newRawOffset);
                int wordStartLine = textLayoutResult.getLineForOffset(TextRange.m4637getStartimpl(wordBoundary));
                if (wordStartLine == currentLine) {
                    start = TextRange.m4637getStartimpl(wordBoundary);
                } else {
                    start = textLayoutResult.getLineStart(currentLine);
                }
                int wordEndLine = textLayoutResult.getLineForOffset(TextRange.m4632getEndimpl(wordBoundary));
                if (wordEndLine != currentLine) {
                    end = TextLayoutResult.getLineEnd$default(textLayoutResult, currentLine, false, 2, null);
                } else {
                    end = TextRange.m4632getEndimpl(wordBoundary);
                }
                if (start == otherBoundaryOffset) {
                    return end;
                }
                if (end != otherBoundaryOffset) {
                    int threshold = (start + end) / 2;
                    return (!(isStart ^ isReversed) ? newRawOffset >= threshold : newRawOffset > threshold) ? start : end;
                }
                return start;
            }

            private final boolean isAtWordBoundary(TextLayoutResult $this$isAtWordBoundary, int offset) {
                long wordBoundary = $this$isAtWordBoundary.m4611getWordBoundaryjx7JFs(offset);
                return offset == TextRange.m4637getStartimpl(wordBoundary) || offset == TextRange.m4632getEndimpl(wordBoundary);
            }

            private final boolean isExpanding(int newRawOffset, int previousRawOffset, boolean isStart, boolean previousReversed) {
                if (previousRawOffset == -1) {
                    return true;
                }
                if (newRawOffset == previousRawOffset) {
                    return false;
                }
                return isStart ^ previousReversed ? newRawOffset < previousRawOffset : newRawOffset > previousRawOffset;
            }
        };

        private Companion() {
        }

        public final SelectionAdjustment getNone() {
            return None;
        }

        public final SelectionAdjustment getCharacter() {
            return Character;
        }

        public final SelectionAdjustment getWord() {
            return Word;
        }

        public final SelectionAdjustment getParagraph() {
            return Paragraph;
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* renamed from: adjustByBoundary--Dv-ylE  reason: not valid java name */
        public final long m818adjustByBoundaryDvylE(TextLayoutResult textLayoutResult, long newRawSelection, Function1<? super Integer, TextRange> function1) {
            if (textLayoutResult.getLayoutInput().getText().length() == 0) {
                return TextRange.Companion.m4642getZerod9O1mEE();
            }
            int maxOffset = StringsKt.getLastIndex(textLayoutResult.getLayoutInput().getText());
            long startBoundary = function1.invoke(Integer.valueOf(RangesKt.coerceIn(TextRange.m4637getStartimpl(newRawSelection), 0, maxOffset))).m4641unboximpl();
            long endBoundary = function1.invoke(Integer.valueOf(RangesKt.coerceIn(TextRange.m4632getEndimpl(newRawSelection), 0, maxOffset))).m4641unboximpl();
            int start = TextRange.m4636getReversedimpl(newRawSelection) ? TextRange.m4632getEndimpl(startBoundary) : TextRange.m4637getStartimpl(startBoundary);
            int end = TextRange.m4636getReversedimpl(newRawSelection) ? TextRange.m4637getStartimpl(endBoundary) : TextRange.m4632getEndimpl(endBoundary);
            return TextRangeKt.TextRange(start, end);
        }

        public final SelectionAdjustment getCharacterWithWordAccelerate() {
            return CharacterWithWordAccelerate;
        }
    }
}
