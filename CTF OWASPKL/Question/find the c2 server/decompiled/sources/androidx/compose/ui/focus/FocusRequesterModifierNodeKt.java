package androidx.compose.ui.focus;

import kotlin.Metadata;
/* compiled from: FocusRequesterModifierNode.kt */
@Metadata(d1 = {"\u0000\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a\f\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0007\u001a\f\u0010\u0003\u001a\u00020\u0001*\u00020\u0002H\u0007\u001a\f\u0010\u0004\u001a\u00020\u0001*\u00020\u0002H\u0007¨\u0006\u0005"}, d2 = {"captureFocus", "", "Landroidx/compose/ui/focus/FocusRequesterModifierNode;", "freeFocus", "requestFocus", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class FocusRequesterModifierNodeKt {
    /* JADX WARN: Code restructure failed: missing block: B:36:0x0044, code lost:
        continue;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean requestFocus(androidx.compose.ui.focus.FocusRequesterModifierNode r18) {
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
            if (r7 == 0) goto L8b
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
            if (r9 == 0) goto L88
            r9 = r7
            r10 = 0
            int r11 = r9.getSize()
            r13 = 1
            int r11 = r11 - r13
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
            if (r11 == 0) goto L83
            r11 = r10
            r14 = 0
            boolean r15 = r11 instanceof androidx.compose.ui.focus.FocusTargetModifierNode
            if (r15 == 0) goto L81
            r15 = r11
            androidx.compose.ui.focus.FocusTargetModifierNode r15 = (androidx.compose.ui.focus.FocusTargetModifierNode) r15
            r16 = 0
            boolean r17 = androidx.compose.ui.focus.FocusTransactionsKt.requestFocus(r15)
            if (r17 == 0) goto L7f
            return r13
        L7f:
        L81:
            goto L44
        L83:
            androidx.compose.ui.Modifier$Node r10 = r10.getChild$ui_release()
            goto L64
        L88:
            return r12
        L8b:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "Check failed."
            java.lang.String r8 = r8.toString()
            r7.<init>(r8)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.FocusRequesterModifierNodeKt.requestFocus(androidx.compose.ui.focus.FocusRequesterModifierNode):boolean");
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x0044, code lost:
        continue;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean captureFocus(androidx.compose.ui.focus.FocusRequesterModifierNode r18) {
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
            if (r7 == 0) goto L8b
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
            if (r9 == 0) goto L88
            r9 = r7
            r10 = 0
            int r11 = r9.getSize()
            r13 = 1
            int r11 = r11 - r13
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
            if (r11 == 0) goto L83
            r11 = r10
            r14 = 0
            boolean r15 = r11 instanceof androidx.compose.ui.focus.FocusTargetModifierNode
            if (r15 == 0) goto L81
            r15 = r11
            androidx.compose.ui.focus.FocusTargetModifierNode r15 = (androidx.compose.ui.focus.FocusTargetModifierNode) r15
            r16 = 0
            boolean r17 = androidx.compose.ui.focus.FocusTransactionsKt.captureFocus(r15)
            if (r17 == 0) goto L7f
            return r13
        L7f:
        L81:
            goto L44
        L83:
            androidx.compose.ui.Modifier$Node r10 = r10.getChild$ui_release()
            goto L64
        L88:
            return r12
        L8b:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "Check failed."
            java.lang.String r8 = r8.toString()
            r7.<init>(r8)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.FocusRequesterModifierNodeKt.captureFocus(androidx.compose.ui.focus.FocusRequesterModifierNode):boolean");
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x0044, code lost:
        continue;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean freeFocus(androidx.compose.ui.focus.FocusRequesterModifierNode r18) {
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
            if (r7 == 0) goto L8b
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
            if (r9 == 0) goto L88
            r9 = r7
            r10 = 0
            int r11 = r9.getSize()
            r13 = 1
            int r11 = r11 - r13
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
            if (r11 == 0) goto L83
            r11 = r10
            r14 = 0
            boolean r15 = r11 instanceof androidx.compose.ui.focus.FocusTargetModifierNode
            if (r15 == 0) goto L81
            r15 = r11
            androidx.compose.ui.focus.FocusTargetModifierNode r15 = (androidx.compose.ui.focus.FocusTargetModifierNode) r15
            r16 = 0
            boolean r17 = androidx.compose.ui.focus.FocusTransactionsKt.freeFocus(r15)
            if (r17 == 0) goto L7f
            return r13
        L7f:
        L81:
            goto L44
        L83:
            androidx.compose.ui.Modifier$Node r10 = r10.getChild$ui_release()
            goto L64
        L88:
            return r12
        L8b:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "Check failed."
            java.lang.String r8 = r8.toString()
            r7.<init>(r8)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.FocusRequesterModifierNodeKt.freeFocus(androidx.compose.ui.focus.FocusRequesterModifierNode):boolean");
    }
}
