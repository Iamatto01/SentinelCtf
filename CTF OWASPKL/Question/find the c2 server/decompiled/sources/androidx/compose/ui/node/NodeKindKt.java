package androidx.compose.ui.node;

import androidx.compose.runtime.collection.MutableVector;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.draw.DrawModifier;
import androidx.compose.ui.focus.FocusEventModifier;
import androidx.compose.ui.focus.FocusEventModifierNode;
import androidx.compose.ui.focus.FocusOrderModifier;
import androidx.compose.ui.focus.FocusPropertiesModifierNode;
import androidx.compose.ui.focus.FocusTargetModifierNode;
import androidx.compose.ui.input.key.KeyInputModifierNode;
import androidx.compose.ui.input.pointer.PointerInputModifier;
import androidx.compose.ui.input.rotary.RotaryInputModifierNode;
import androidx.compose.ui.layout.IntermediateLayoutModifier;
import androidx.compose.ui.layout.LayoutModifier;
import androidx.compose.ui.layout.LookaheadOnPlacedModifier;
import androidx.compose.ui.layout.OnGloballyPositionedModifier;
import androidx.compose.ui.layout.OnPlacedModifier;
import androidx.compose.ui.layout.OnRemeasuredModifier;
import androidx.compose.ui.layout.ParentDataModifier;
import androidx.compose.ui.modifier.ModifierLocalConsumer;
import androidx.compose.ui.modifier.ModifierLocalNode;
import androidx.compose.ui.modifier.ModifierLocalProvider;
import androidx.compose.ui.semantics.SemanticsModifier;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: NodeKind.kt */
@Metadata(d1 = {"\u00004\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a\u0010\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u000eH\u0000\u001a\u0018\u0010\u000f\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u000e2\u0006\u0010\u0010\u001a\u00020\u0001H\u0002\u001a\u0010\u0010\u0011\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u000eH\u0000\u001a\u0010\u0010\u0012\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u000eH\u0000\u001a\u0010\u0010\u0013\u001a\u00020\u00012\u0006\u0010\u0014\u001a\u00020\u0015H\u0000\u001a\u0010\u0010\u0013\u001a\u00020\u00012\u0006\u0010\r\u001a\u00020\u000eH\u0000\u001a&\u0010\u0016\u001a\u00020\u0001*\u00020\u00012\n\u0010\u0017\u001a\u0006\u0012\u0002\b\u00030\u0006H\u0080\fø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\u0018\u0010\u0019\u001a\f\u0010\u001a\u001a\u00020\f*\u00020\u001bH\u0003\u001a\f\u0010\u001c\u001a\u00020\u0005*\u00020\u001bH\u0003\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0002\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0003\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"%\u0010\u0004\u001a\u00020\u0005*\u0006\u0012\u0002\b\u00030\u00068@X\u0080\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u0007\u0010\b\u001a\u0004\b\t\u0010\n\u0082\u0002\u000b\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001¨\u0006\u001d"}, d2 = {"Inserted", "", "Removed", "Updated", "includeSelfInTraversal", "", "Landroidx/compose/ui/node/NodeKind;", "getIncludeSelfInTraversal-H91voCI$annotations", "(I)V", "getIncludeSelfInTraversal-H91voCI", "(I)Z", "autoInvalidateInsertedNode", "", "node", "Landroidx/compose/ui/Modifier$Node;", "autoInvalidateNode", "phase", "autoInvalidateRemovedNode", "autoInvalidateUpdatedNode", "calculateNodeKindSetFrom", "element", "Landroidx/compose/ui/Modifier$Element;", "or", "other", "or-64DMado", "(II)I", "scheduleInvalidationOfAssociatedFocusTargets", "Landroidx/compose/ui/focus/FocusPropertiesModifierNode;", "specifiesCanFocusProperty", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class NodeKindKt {
    private static final int Inserted = 1;
    private static final int Removed = 2;
    private static final int Updated = 0;

    /* renamed from: getIncludeSelfInTraversal-H91voCI$annotations  reason: not valid java name */
    public static /* synthetic */ void m4336getIncludeSelfInTraversalH91voCI$annotations(int i) {
    }

    /* renamed from: or-64DMado  reason: not valid java name */
    public static final int m4337or64DMado(int $this$or_u2d64DMado, int other) {
        return $this$or_u2d64DMado | other;
    }

    /* renamed from: getIncludeSelfInTraversal-H91voCI  reason: not valid java name */
    public static final boolean m4335getIncludeSelfInTraversalH91voCI(int $this$includeSelfInTraversal) {
        return (NodeKind.m4327constructorimpl(128) & $this$includeSelfInTraversal) != 0;
    }

    public static final int calculateNodeKindSetFrom(Modifier.Element element) {
        Intrinsics.checkNotNullParameter(element, "element");
        int mask = NodeKind.m4327constructorimpl(1);
        if (element instanceof LayoutModifier) {
            int other$iv = NodeKind.m4327constructorimpl(2) | mask;
            mask = other$iv;
        }
        if (element instanceof IntermediateLayoutModifier) {
            int $this$or_u2d64DMado$iv = mask;
            int other$iv2 = NodeKind.m4327constructorimpl(512) | $this$or_u2d64DMado$iv;
            mask = other$iv2;
        }
        if (element instanceof DrawModifier) {
            int $this$or_u2d64DMado$iv2 = mask;
            int other$iv3 = NodeKind.m4327constructorimpl(4) | $this$or_u2d64DMado$iv2;
            mask = other$iv3;
        }
        if (element instanceof SemanticsModifier) {
            int $this$or_u2d64DMado$iv3 = mask;
            int other$iv4 = NodeKind.m4327constructorimpl(8) | $this$or_u2d64DMado$iv3;
            mask = other$iv4;
        }
        if (element instanceof PointerInputModifier) {
            int $this$or_u2d64DMado$iv4 = mask;
            int other$iv5 = NodeKind.m4327constructorimpl(16) | $this$or_u2d64DMado$iv4;
            mask = other$iv5;
        }
        if ((element instanceof ModifierLocalConsumer) || (element instanceof ModifierLocalProvider)) {
            int $this$or_u2d64DMado$iv5 = mask;
            int other$iv6 = NodeKind.m4327constructorimpl(32) | $this$or_u2d64DMado$iv5;
            mask = other$iv6;
        }
        if (element instanceof FocusEventModifier) {
            int $this$or_u2d64DMado$iv6 = mask;
            int other$iv7 = NodeKind.m4327constructorimpl(4096) | $this$or_u2d64DMado$iv6;
            mask = other$iv7;
        }
        if (element instanceof FocusOrderModifier) {
            int $this$or_u2d64DMado$iv7 = mask;
            int other$iv8 = NodeKind.m4327constructorimpl(2048) | $this$or_u2d64DMado$iv7;
            mask = other$iv8;
        }
        if (element instanceof OnGloballyPositionedModifier) {
            int $this$or_u2d64DMado$iv8 = mask;
            int other$iv9 = NodeKind.m4327constructorimpl(256) | $this$or_u2d64DMado$iv8;
            mask = other$iv9;
        }
        if (element instanceof ParentDataModifier) {
            int $this$or_u2d64DMado$iv9 = mask;
            int other$iv10 = NodeKind.m4327constructorimpl(64) | $this$or_u2d64DMado$iv9;
            mask = other$iv10;
        }
        if ((element instanceof OnPlacedModifier) || (element instanceof OnRemeasuredModifier) || (element instanceof LookaheadOnPlacedModifier)) {
            int $this$or_u2d64DMado$iv10 = mask;
            int other$iv11 = NodeKind.m4327constructorimpl(128) | $this$or_u2d64DMado$iv10;
            return other$iv11;
        }
        return mask;
    }

    public static final int calculateNodeKindSetFrom(Modifier.Node node) {
        Intrinsics.checkNotNullParameter(node, "node");
        int mask = NodeKind.m4327constructorimpl(1);
        if (node instanceof LayoutModifierNode) {
            int other$iv = NodeKind.m4327constructorimpl(2) | mask;
            mask = other$iv;
        }
        if (node instanceof DrawModifierNode) {
            int $this$or_u2d64DMado$iv = mask;
            int other$iv2 = NodeKind.m4327constructorimpl(4) | $this$or_u2d64DMado$iv;
            mask = other$iv2;
        }
        if (node instanceof SemanticsModifierNode) {
            int $this$or_u2d64DMado$iv2 = mask;
            int other$iv3 = NodeKind.m4327constructorimpl(8) | $this$or_u2d64DMado$iv2;
            mask = other$iv3;
        }
        if (node instanceof PointerInputModifierNode) {
            int $this$or_u2d64DMado$iv3 = mask;
            int other$iv4 = NodeKind.m4327constructorimpl(16) | $this$or_u2d64DMado$iv3;
            mask = other$iv4;
        }
        if (node instanceof ModifierLocalNode) {
            int $this$or_u2d64DMado$iv4 = mask;
            int other$iv5 = NodeKind.m4327constructorimpl(32) | $this$or_u2d64DMado$iv4;
            mask = other$iv5;
        }
        if (node instanceof ParentDataModifierNode) {
            int $this$or_u2d64DMado$iv5 = mask;
            int other$iv6 = NodeKind.m4327constructorimpl(64) | $this$or_u2d64DMado$iv5;
            mask = other$iv6;
        }
        if (node instanceof LayoutAwareModifierNode) {
            int $this$or_u2d64DMado$iv6 = mask;
            int other$iv7 = NodeKind.m4327constructorimpl(128) | $this$or_u2d64DMado$iv6;
            mask = other$iv7;
        }
        if (node instanceof GlobalPositionAwareModifierNode) {
            int $this$or_u2d64DMado$iv7 = mask;
            int other$iv8 = NodeKind.m4327constructorimpl(256) | $this$or_u2d64DMado$iv7;
            mask = other$iv8;
        }
        if (node instanceof IntermediateLayoutModifierNode) {
            int $this$or_u2d64DMado$iv8 = mask;
            int other$iv9 = NodeKind.m4327constructorimpl(512) | $this$or_u2d64DMado$iv8;
            mask = other$iv9;
        }
        if (node instanceof FocusTargetModifierNode) {
            int $this$or_u2d64DMado$iv9 = mask;
            int other$iv10 = NodeKind.m4327constructorimpl(1024) | $this$or_u2d64DMado$iv9;
            mask = other$iv10;
        }
        if (node instanceof FocusPropertiesModifierNode) {
            int $this$or_u2d64DMado$iv10 = mask;
            int other$iv11 = NodeKind.m4327constructorimpl(2048) | $this$or_u2d64DMado$iv10;
            mask = other$iv11;
        }
        if (node instanceof FocusEventModifierNode) {
            int $this$or_u2d64DMado$iv11 = mask;
            int other$iv12 = NodeKind.m4327constructorimpl(4096) | $this$or_u2d64DMado$iv11;
            mask = other$iv12;
        }
        if (node instanceof KeyInputModifierNode) {
            int $this$or_u2d64DMado$iv12 = mask;
            int other$iv13 = NodeKind.m4327constructorimpl(8192) | $this$or_u2d64DMado$iv12;
            mask = other$iv13;
        }
        if (node instanceof RotaryInputModifierNode) {
            int $this$or_u2d64DMado$iv13 = mask;
            int other$iv14 = NodeKind.m4327constructorimpl(16384) | $this$or_u2d64DMado$iv13;
            return other$iv14;
        }
        return mask;
    }

    public static final void autoInvalidateRemovedNode(Modifier.Node node) {
        Intrinsics.checkNotNullParameter(node, "node");
        autoInvalidateNode(node, 2);
    }

    public static final void autoInvalidateInsertedNode(Modifier.Node node) {
        Intrinsics.checkNotNullParameter(node, "node");
        autoInvalidateNode(node, 1);
    }

    public static final void autoInvalidateUpdatedNode(Modifier.Node node) {
        Intrinsics.checkNotNullParameter(node, "node");
        autoInvalidateNode(node, 0);
    }

    private static final void autoInvalidateNode(Modifier.Node node, int phase) {
        if (!node.isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        int kind$iv = (node.getKindSet$ui_release() & NodeKind.m4327constructorimpl(2)) != 0 ? 1 : 0;
        if (kind$iv != 0 && (node instanceof LayoutModifierNode)) {
            LayoutModifierNodeKt.invalidateMeasurements((LayoutModifierNode) node);
            if (phase == 2) {
                NodeCoordinator coordinator = DelegatableNodeKt.m4231requireCoordinator64DMado(node, NodeKind.m4327constructorimpl(2));
                coordinator.onRelease();
            }
        }
        int kind$iv2 = (node.getKindSet$ui_release() & NodeKind.m4327constructorimpl(256)) != 0 ? 1 : 0;
        if (kind$iv2 != 0 && (node instanceof GlobalPositionAwareModifierNode)) {
            DelegatableNodeKt.requireLayoutNode(node).invalidateMeasurements$ui_release();
        }
        int kind$iv3 = (node.getKindSet$ui_release() & NodeKind.m4327constructorimpl(4)) != 0 ? 1 : 0;
        if (kind$iv3 != 0 && (node instanceof DrawModifierNode)) {
            DrawModifierNodeKt.invalidateDraw((DrawModifierNode) node);
        }
        int kind$iv4 = (node.getKindSet$ui_release() & NodeKind.m4327constructorimpl(8)) != 0 ? 1 : 0;
        if (kind$iv4 != 0 && (node instanceof SemanticsModifierNode)) {
            SemanticsModifierNodeKt.invalidateSemantics((SemanticsModifierNode) node);
        }
        int kind$iv5 = (node.getKindSet$ui_release() & NodeKind.m4327constructorimpl(64)) != 0 ? 1 : 0;
        if (kind$iv5 != 0 && (node instanceof ParentDataModifierNode)) {
            ParentDataModifierNodeKt.invalidateParentData((ParentDataModifierNode) node);
        }
        int kind$iv6 = (node.getKindSet$ui_release() & NodeKind.m4327constructorimpl(1024)) != 0 ? 1 : 0;
        if (kind$iv6 != 0 && (node instanceof FocusTargetModifierNode)) {
            if (phase == 2) {
                node.onReset();
            } else {
                DelegatableNodeKt.requireOwner(node).getFocusOwner().scheduleInvalidation((FocusTargetModifierNode) node);
            }
        }
        int kind$iv7 = (node.getKindSet$ui_release() & NodeKind.m4327constructorimpl(2048)) != 0 ? 1 : 0;
        if (kind$iv7 != 0 && (node instanceof FocusPropertiesModifierNode) && specifiesCanFocusProperty((FocusPropertiesModifierNode) node)) {
            if (phase == 2) {
                scheduleInvalidationOfAssociatedFocusTargets((FocusPropertiesModifierNode) node);
            } else {
                DelegatableNodeKt.requireOwner(node).getFocusOwner().scheduleInvalidation((FocusPropertiesModifierNode) node);
            }
        }
        if (((node.getKindSet$ui_release() & NodeKind.m4327constructorimpl(4096)) != 0) && (node instanceof FocusEventModifierNode) && phase != 2) {
            DelegatableNodeKt.requireOwner(node).getFocusOwner().scheduleInvalidation((FocusEventModifierNode) node);
        }
    }

    private static final void scheduleInvalidationOfAssociatedFocusTargets(FocusPropertiesModifierNode $this$scheduleInvalidationOfAssociatedFocusTargets) {
        FocusPropertiesModifierNode $this$visitChildren_u2d6rFNWt0$iv = $this$scheduleInvalidationOfAssociatedFocusTargets;
        int m4327constructorimpl = NodeKind.m4327constructorimpl(1024);
        if (!$this$visitChildren_u2d6rFNWt0$iv.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        MutableVector branches$iv$iv = new MutableVector(new Modifier.Node[16], 0);
        Modifier.Node child$iv$iv = $this$visitChildren_u2d6rFNWt0$iv.getNode().getChild$ui_release();
        if (child$iv$iv == null) {
            DelegatableNodeKt.addLayoutNodeChildren(branches$iv$iv, $this$visitChildren_u2d6rFNWt0$iv.getNode());
        } else {
            branches$iv$iv.add(child$iv$iv);
        }
        while (branches$iv$iv.isNotEmpty()) {
            Modifier.Node branch$iv$iv = (Modifier.Node) branches$iv$iv.removeAt(branches$iv$iv.getSize() - 1);
            if ((branch$iv$iv.getAggregateChildKindSet$ui_release() & m4327constructorimpl) == 0) {
                DelegatableNodeKt.addLayoutNodeChildren(branches$iv$iv, branch$iv$iv);
            } else {
                Modifier.Node node$iv$iv = branch$iv$iv;
                while (true) {
                    if (node$iv$iv == null) {
                        break;
                    } else if ((node$iv$iv.getKindSet$ui_release() & m4327constructorimpl) != 0) {
                        Modifier.Node it$iv = node$iv$iv;
                        if (it$iv instanceof FocusTargetModifierNode) {
                            FocusTargetModifierNode it = (FocusTargetModifierNode) it$iv;
                            DelegatableNodeKt.requireOwner($this$scheduleInvalidationOfAssociatedFocusTargets).getFocusOwner().scheduleInvalidation(it);
                        }
                    } else {
                        node$iv$iv = node$iv$iv.getChild$ui_release();
                    }
                }
            }
        }
    }

    private static final boolean specifiesCanFocusProperty(FocusPropertiesModifierNode $this$specifiesCanFocusProperty) {
        CanFocusChecker.INSTANCE.reset();
        $this$specifiesCanFocusProperty.modifyFocusProperties(CanFocusChecker.INSTANCE);
        return CanFocusChecker.INSTANCE.isCanFocusSet();
    }
}
