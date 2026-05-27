package androidx.compose.ui.focus;

import androidx.compose.ui.Modifier;
import androidx.compose.ui.node.DelegatableNodeKt;
import androidx.compose.ui.node.LayoutNode;
import androidx.compose.ui.node.NodeChain;
import androidx.compose.ui.node.NodeKind;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: FocusEventModifierNode.kt */
@Metadata(d1 = {"\u0000\u0016\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\u001a\f\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0000\u001a\f\u0010\u0003\u001a\u00020\u0004*\u00020\u0005H\u0001¨\u0006\u0006"}, d2 = {"getFocusState", "Landroidx/compose/ui/focus/FocusState;", "Landroidx/compose/ui/focus/FocusEventModifierNode;", "refreshFocusEventNodes", "", "Landroidx/compose/ui/focus/FocusTargetModifierNode;", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class FocusEventModifierNodeKt {

    /* compiled from: FocusEventModifierNode.kt */
    @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[FocusStateImpl.values().length];
            try {
                iArr[FocusStateImpl.Active.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                iArr[FocusStateImpl.ActiveParent.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                iArr[FocusStateImpl.Captured.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                iArr[FocusStateImpl.Inactive.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            $EnumSwitchMapping$0 = iArr;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:38:0x0044, code lost:
        continue;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.ui.focus.FocusState getFocusState(androidx.compose.ui.focus.FocusEventModifierNode r18) {
        /*
            r0 = r18
            java.lang.String r1 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            r1 = r0
            androidx.compose.ui.node.DelegatableNode r1 = (androidx.compose.ui.node.DelegatableNode) r1
            r2 = 0
            r3 = 1024(0x400, float:1.435E-42)
            int r2 = androidx.compose.ui.node.NodeKind.m4327constructorimpl(r3)
            r3 = 0
            r4 = r2
            r5 = r1
            r6 = 0
            androidx.compose.ui.Modifier$Node r7 = r5.getNode()
            boolean r7 = r7.isAttached()
            if (r7 == 0) goto L9c
            r7 = 0
            r8 = 16
            r9 = 0
            androidx.compose.runtime.collection.MutableVector r10 = new androidx.compose.runtime.collection.MutableVector
            androidx.compose.ui.Modifier$Node[] r11 = new androidx.compose.ui.Modifier.Node[r8]
            r12 = 0
            r10.<init>(r11, r12)
            r7 = r10
            androidx.compose.ui.Modifier$Node r8 = r5.getNode()
            androidx.compose.ui.Modifier$Node r8 = r8.getChild$ui_release()
            if (r8 != 0) goto L41
            androidx.compose.ui.Modifier$Node r9 = r5.getNode()
            androidx.compose.ui.node.DelegatableNodeKt.access$addLayoutNodeChildren(r7, r9)
            goto L44
        L41:
            r7.add(r8)
        L44:
            boolean r9 = r7.isNotEmpty()
            if (r9 == 0) goto L95
            r9 = r7
            r10 = 0
            int r11 = r9.getSize()
            int r11 = r11 + (-1)
            java.lang.Object r9 = r7.removeAt(r11)
            androidx.compose.ui.Modifier$Node r9 = (androidx.compose.ui.Modifier.Node) r9
            int r10 = r9.getAggregateChildKindSet$ui_release()
            r10 = r10 & r4
            if (r10 != 0) goto L63
            androidx.compose.ui.node.DelegatableNodeKt.access$addLayoutNodeChildren(r7, r9)
            goto L44
        L63:
            r10 = r9
        L64:
            if (r10 == 0) goto L44
            int r11 = r10.getKindSet$ui_release()
            r11 = r11 & r4
            if (r11 == 0) goto L90
            r11 = r10
            r12 = 0
            boolean r13 = r11 instanceof androidx.compose.ui.focus.FocusTargetModifierNode
            if (r13 == 0) goto L8d
            r13 = r11
            androidx.compose.ui.focus.FocusTargetModifierNode r13 = (androidx.compose.ui.focus.FocusTargetModifierNode) r13
            r14 = 0
            androidx.compose.ui.focus.FocusStateImpl r15 = r13.getFocusStateImpl$ui_release()
            int[] r16 = androidx.compose.ui.focus.FocusEventModifierNodeKt.WhenMappings.$EnumSwitchMapping$0
            int r17 = r15.ordinal()
            r16 = r16[r17]
            switch(r16) {
                case 1: goto L88;
                case 2: goto L88;
                case 3: goto L88;
                case 4: goto L87;
                default: goto L86;
            }
        L86:
            goto L8d
        L87:
            goto L8d
        L88:
            r16 = r15
            androidx.compose.ui.focus.FocusState r16 = (androidx.compose.ui.focus.FocusState) r16
            return r16
        L8d:
            goto L44
        L90:
            androidx.compose.ui.Modifier$Node r10 = r10.getChild$ui_release()
            goto L64
        L95:
            androidx.compose.ui.focus.FocusStateImpl r1 = androidx.compose.ui.focus.FocusStateImpl.Inactive
            androidx.compose.ui.focus.FocusState r1 = (androidx.compose.ui.focus.FocusState) r1
            return r1
        L9c:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "Check failed."
            java.lang.String r8 = r8.toString()
            r7.<init>(r8)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.FocusEventModifierNodeKt.getFocusState(androidx.compose.ui.focus.FocusEventModifierNode):androidx.compose.ui.focus.FocusState");
    }

    public static final void refreshFocusEventNodes(FocusTargetModifierNode $this$refreshFocusEventNodes) {
        NodeChain nodes$ui_release;
        Intrinsics.checkNotNullParameter($this$refreshFocusEventNodes, "<this>");
        FocusTargetModifierNode $this$visitAncestors$iv = $this$refreshFocusEventNodes;
        int mask$iv = NodeKind.m4327constructorimpl(4096) | NodeKind.m4327constructorimpl(1024);
        if (!$this$visitAncestors$iv.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        Modifier.Node node$iv = $this$visitAncestors$iv.getNode().getParent$ui_release();
        LayoutNode layout$iv = DelegatableNodeKt.requireLayoutNode($this$visitAncestors$iv);
        while (layout$iv != null) {
            Modifier.Node head$iv = layout$iv.getNodes$ui_release().getHead$ui_release();
            if ((head$iv.getAggregateChildKindSet$ui_release() & mask$iv) != 0) {
                while (node$iv != null) {
                    if ((node$iv.getKindSet$ui_release() & mask$iv) != 0) {
                        Modifier.Node it = node$iv;
                        if ((it.getKindSet$ui_release() & NodeKind.m4327constructorimpl(1024)) != 0) {
                            return;
                        }
                        if (!(it instanceof FocusEventModifierNode)) {
                            throw new IllegalStateException("Check failed.".toString());
                        }
                        ((FocusEventModifierNode) it).onFocusEvent(getFocusState((FocusEventModifierNode) it));
                    }
                    node$iv = node$iv.getParent$ui_release();
                }
            }
            layout$iv = layout$iv.getParent$ui_release();
            node$iv = (layout$iv == null || (nodes$ui_release = layout$iv.getNodes$ui_release()) == null) ? null : nodes$ui_release.getTail$ui_release();
        }
    }
}
