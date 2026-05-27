package androidx.compose.ui.layout;

import androidx.compose.ui.node.LookaheadDelegate;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: LookaheadLayoutCoordinates.kt */
@Metadata(d1 = {"\u0000\n\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\"\u0018\u0010\u0000\u001a\u00020\u0001*\u00020\u00018BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u0002\u0010\u0003¨\u0006\u0004"}, d2 = {"rootLookaheadDelegate", "Landroidx/compose/ui/node/LookaheadDelegate;", "getRootLookaheadDelegate", "(Landroidx/compose/ui/node/LookaheadDelegate;)Landroidx/compose/ui/node/LookaheadDelegate;", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LookaheadLayoutCoordinatesKt {
    public static final /* synthetic */ LookaheadDelegate access$getRootLookaheadDelegate(LookaheadDelegate $receiver) {
        return getRootLookaheadDelegate($receiver);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final LookaheadDelegate getRootLookaheadDelegate(LookaheadDelegate $this$rootLookaheadDelegate) {
        LookaheadDelegate lookaheadDelegate$ui_release = $this$rootLookaheadDelegate.getLookaheadScope().getRoot().getOuterCoordinator$ui_release().getLookaheadDelegate$ui_release();
        Intrinsics.checkNotNull(lookaheadDelegate$ui_release);
        return lookaheadDelegate$ui_release;
    }
}
