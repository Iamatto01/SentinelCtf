package androidx.compose.ui.node;

import androidx.compose.ui.Modifier;
import androidx.compose.ui.geometry.Rect;
import androidx.compose.ui.layout.LayoutCoordinatesKt;
import androidx.compose.ui.semantics.SemanticsActions;
import androidx.compose.ui.semantics.SemanticsConfiguration;
import androidx.compose.ui.semantics.SemanticsConfigurationKt;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: SemanticsModifierNode.kt */
@Metadata(d1 = {"\u0000 \n\u0000\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u001a\f\u0010\u0007\u001a\u00020\b*\u00020\u0002H\u0007\u001a\f\u0010\t\u001a\u00020\n*\u00020\u0002H\u0007\u001a\f\u0010\u000b\u001a\u00020\f*\u00020\u0002H\u0000\"\u001e\u0010\u0000\u001a\u00020\u0001*\u00020\u00028@X\u0080\u0004¢\u0006\f\u0012\u0004\b\u0003\u0010\u0004\u001a\u0004\b\u0005\u0010\u0006¨\u0006\r"}, d2 = {"useMinimumTouchTarget", "", "Landroidx/compose/ui/node/SemanticsModifierNode;", "getUseMinimumTouchTarget$annotations", "(Landroidx/compose/ui/node/SemanticsModifierNode;)V", "getUseMinimumTouchTarget", "(Landroidx/compose/ui/node/SemanticsModifierNode;)Z", "collapsedSemanticsConfiguration", "Landroidx/compose/ui/semantics/SemanticsConfiguration;", "invalidateSemantics", "", "touchBoundsInRoot", "Landroidx/compose/ui/geometry/Rect;", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class SemanticsModifierNodeKt {
    public static /* synthetic */ void getUseMinimumTouchTarget$annotations(SemanticsModifierNode semanticsModifierNode) {
    }

    public static final void invalidateSemantics(SemanticsModifierNode $this$invalidateSemantics) {
        Intrinsics.checkNotNullParameter($this$invalidateSemantics, "<this>");
        DelegatableNodeKt.requireOwner($this$invalidateSemantics).onSemanticsChange();
    }

    public static final SemanticsConfiguration collapsedSemanticsConfiguration(SemanticsModifierNode $this$collapsedSemanticsConfiguration) {
        Intrinsics.checkNotNullParameter($this$collapsedSemanticsConfiguration, "<this>");
        SemanticsModifierNode $this$localChild_u2d64DMado$iv = $this$collapsedSemanticsConfiguration;
        Modifier.Node localChild = DelegatableNodeKt.localChild($this$localChild_u2d64DMado$iv, NodeKind.m4327constructorimpl(8));
        if (!(localChild instanceof SemanticsModifierNode)) {
            localChild = null;
        }
        SemanticsModifierNode next = (SemanticsModifierNode) localChild;
        if (next == null || $this$collapsedSemanticsConfiguration.getSemanticsConfiguration().isClearingSemantics()) {
            return $this$collapsedSemanticsConfiguration.getSemanticsConfiguration();
        }
        SemanticsConfiguration config = $this$collapsedSemanticsConfiguration.getSemanticsConfiguration().copy();
        config.collapsePeer$ui_release(collapsedSemanticsConfiguration(next));
        return config;
    }

    public static final boolean getUseMinimumTouchTarget(SemanticsModifierNode $this$useMinimumTouchTarget) {
        Intrinsics.checkNotNullParameter($this$useMinimumTouchTarget, "<this>");
        return SemanticsConfigurationKt.getOrNull($this$useMinimumTouchTarget.getSemanticsConfiguration(), SemanticsActions.INSTANCE.getOnClick()) != null;
    }

    public static final Rect touchBoundsInRoot(SemanticsModifierNode $this$touchBoundsInRoot) {
        Intrinsics.checkNotNullParameter($this$touchBoundsInRoot, "<this>");
        if (!$this$touchBoundsInRoot.getNode().isAttached()) {
            return Rect.Companion.getZero();
        }
        if (!getUseMinimumTouchTarget($this$touchBoundsInRoot)) {
            return LayoutCoordinatesKt.boundsInRoot(DelegatableNodeKt.m4231requireCoordinator64DMado($this$touchBoundsInRoot, NodeKind.m4327constructorimpl(8)));
        }
        return DelegatableNodeKt.m4231requireCoordinator64DMado($this$touchBoundsInRoot, NodeKind.m4327constructorimpl(8)).touchBoundsInRoot();
    }
}
