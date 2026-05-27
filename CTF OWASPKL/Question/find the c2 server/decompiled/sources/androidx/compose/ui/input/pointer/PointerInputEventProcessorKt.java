package androidx.compose.ui.input.pointer;

import kotlin.Metadata;
/* compiled from: PointerInputEventProcessor.kt */
@Metadata(d1 = {"\u0000\u0010\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0003\u001a \u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0003H\u0000ø\u0001\u0000¢\u0006\u0002\u0010\u0005\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\u0006"}, d2 = {"ProcessResult", "Landroidx/compose/ui/input/pointer/ProcessResult;", "dispatchedToAPointerInputModifier", "", "anyMovementConsumed", "(ZZ)I", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class PointerInputEventProcessorKt {
    public static final int ProcessResult(boolean dispatchedToAPointerInputModifier, boolean anyMovementConsumed) {
        int val2 = anyMovementConsumed ? 2 : 0;
        return ProcessResult.m4090constructorimpl((dispatchedToAPointerInputModifier ? 1 : 0) | val2);
    }
}
