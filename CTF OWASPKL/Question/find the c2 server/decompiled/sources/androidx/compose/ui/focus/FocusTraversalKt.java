package androidx.compose.ui.focus;

import androidx.compose.ui.Modifier;
import androidx.compose.ui.geometry.Rect;
import androidx.compose.ui.layout.LayoutCoordinatesKt;
import androidx.compose.ui.node.DelegatableNodeKt;
import androidx.compose.ui.node.LayoutNode;
import androidx.compose.ui.node.NodeChain;
import androidx.compose.ui.node.NodeCoordinator;
import androidx.compose.ui.node.NodeKind;
import androidx.compose.ui.unit.LayoutDirection;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: FocusTraversal.kt */
@Metadata(d1 = {"\u00006\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a)\u0010\n\u001a\u00020\u000b*\u00020\u00012\u0006\u0010\f\u001a\u00020\r2\u0006\u0010\u000e\u001a\u00020\u000fH\u0000ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0010\u0010\u0011\u001a\u000e\u0010\u0012\u001a\u0004\u0018\u00010\u0001*\u00020\u0001H\u0000\u001a\u000e\u0010\u0013\u001a\u0004\u0018\u00010\u0001*\u00020\u0001H\u0002\u001a\f\u0010\u0014\u001a\u00020\u0015*\u00020\u0001H\u0001\u001a=\u0010\u0016\u001a\u00020\u0007*\u00020\u00012\u0006\u0010\f\u001a\u00020\r2\u0006\u0010\u000e\u001a\u00020\u000f2\u0012\u0010\u0017\u001a\u000e\u0012\u0004\u0012\u00020\u0001\u0012\u0004\u0012\u00020\u00070\u0018H\u0000ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0019\u0010\u001a\" \u0010\u0000\u001a\u0004\u0018\u00010\u0001*\u00020\u00018@X\u0081\u0004¢\u0006\f\u0012\u0004\b\u0002\u0010\u0003\u001a\u0004\b\u0004\u0010\u0005\"\u001e\u0010\u0006\u001a\u00020\u0007*\u00020\u00018@X\u0081\u0004¢\u0006\f\u0012\u0004\b\b\u0010\u0003\u001a\u0004\b\u0006\u0010\t\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006\u001b"}, d2 = {"activeChild", "Landroidx/compose/ui/focus/FocusTargetModifierNode;", "getActiveChild$annotations", "(Landroidx/compose/ui/focus/FocusTargetModifierNode;)V", "getActiveChild", "(Landroidx/compose/ui/focus/FocusTargetModifierNode;)Landroidx/compose/ui/focus/FocusTargetModifierNode;", "isEligibleForFocusSearch", "", "isEligibleForFocusSearch$annotations", "(Landroidx/compose/ui/focus/FocusTargetModifierNode;)Z", "customFocusSearch", "Landroidx/compose/ui/focus/FocusRequester;", "focusDirection", "Landroidx/compose/ui/focus/FocusDirection;", "layoutDirection", "Landroidx/compose/ui/unit/LayoutDirection;", "customFocusSearch--OM-vw8", "(Landroidx/compose/ui/focus/FocusTargetModifierNode;ILandroidx/compose/ui/unit/LayoutDirection;)Landroidx/compose/ui/focus/FocusRequester;", "findActiveFocusNode", "findNonDeactivatedParent", "focusRect", "Landroidx/compose/ui/geometry/Rect;", "focusSearch", "onFound", "Lkotlin/Function1;", "focusSearch-sMXa3k8", "(Landroidx/compose/ui/focus/FocusTargetModifierNode;ILandroidx/compose/ui/unit/LayoutDirection;Lkotlin/jvm/functions/Function1;)Z", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class FocusTraversalKt {

    /* compiled from: FocusTraversal.kt */
    @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;
        public static final /* synthetic */ int[] $EnumSwitchMapping$1;

        static {
            int[] iArr = new int[LayoutDirection.values().length];
            try {
                iArr[LayoutDirection.Ltr.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                iArr[LayoutDirection.Rtl.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            $EnumSwitchMapping$0 = iArr;
            int[] iArr2 = new int[FocusStateImpl.values().length];
            try {
                iArr2[FocusStateImpl.Active.ordinal()] = 1;
            } catch (NoSuchFieldError e3) {
            }
            try {
                iArr2[FocusStateImpl.ActiveParent.ordinal()] = 2;
            } catch (NoSuchFieldError e4) {
            }
            try {
                iArr2[FocusStateImpl.Captured.ordinal()] = 3;
            } catch (NoSuchFieldError e5) {
            }
            try {
                iArr2[FocusStateImpl.Inactive.ordinal()] = 4;
            } catch (NoSuchFieldError e6) {
            }
            $EnumSwitchMapping$1 = iArr2;
        }
    }

    public static /* synthetic */ void getActiveChild$annotations(FocusTargetModifierNode focusTargetModifierNode) {
    }

    public static /* synthetic */ void isEligibleForFocusSearch$annotations(FocusTargetModifierNode focusTargetModifierNode) {
    }

    /* renamed from: customFocusSearch--OM-vw8  reason: not valid java name */
    public static final FocusRequester m2320customFocusSearchOMvw8(FocusTargetModifierNode customFocusSearch, int focusDirection, LayoutDirection layoutDirection) {
        FocusRequester end;
        FocusRequester start;
        Intrinsics.checkNotNullParameter(customFocusSearch, "$this$customFocusSearch");
        Intrinsics.checkNotNullParameter(layoutDirection, "layoutDirection");
        FocusProperties focusProperties = customFocusSearch.fetchFocusProperties$ui_release();
        if (FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2307getNextdhqQ8s())) {
            return focusProperties.getNext();
        }
        if (FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2309getPreviousdhqQ8s())) {
            return focusProperties.getPrevious();
        }
        if (FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2311getUpdhqQ8s())) {
            return focusProperties.getUp();
        }
        if (FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2302getDowndhqQ8s())) {
            return focusProperties.getDown();
        }
        if (FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2306getLeftdhqQ8s())) {
            switch (WhenMappings.$EnumSwitchMapping$0[layoutDirection.ordinal()]) {
                case 1:
                    start = focusProperties.getStart();
                    break;
                case 2:
                    start = focusProperties.getEnd();
                    break;
                default:
                    throw new NoWhenBranchMatchedException();
            }
            FocusRequester it = start;
            if (Intrinsics.areEqual(it, FocusRequester.Companion.getDefault())) {
                start = null;
            }
            if (start != null) {
                return start;
            }
            return focusProperties.getLeft();
        } else if (FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2310getRightdhqQ8s())) {
            switch (WhenMappings.$EnumSwitchMapping$0[layoutDirection.ordinal()]) {
                case 1:
                    end = focusProperties.getEnd();
                    break;
                case 2:
                    end = focusProperties.getStart();
                    break;
                default:
                    throw new NoWhenBranchMatchedException();
            }
            FocusRequester it2 = end;
            if (Intrinsics.areEqual(it2, FocusRequester.Companion.getDefault())) {
                end = null;
            }
            if (end != null) {
                return end;
            }
            return focusProperties.getRight();
        } else if (FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2303getEnterdhqQ8s())) {
            return focusProperties.getEnter().invoke(FocusDirection.m2291boximpl(focusDirection));
        } else {
            if (FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2304getExitdhqQ8s())) {
                return focusProperties.getExit().invoke(FocusDirection.m2291boximpl(focusDirection));
            }
            throw new IllegalStateException("invalid FocusDirection".toString());
        }
    }

    /* renamed from: focusSearch-sMXa3k8  reason: not valid java name */
    public static final boolean m2321focusSearchsMXa3k8(FocusTargetModifierNode focusSearch, int focusDirection, LayoutDirection layoutDirection, Function1<? super FocusTargetModifierNode, Boolean> onFound) {
        int direction;
        Boolean m2333twoDimensionalFocusSearchOMvw8;
        Intrinsics.checkNotNullParameter(focusSearch, "$this$focusSearch");
        Intrinsics.checkNotNullParameter(layoutDirection, "layoutDirection");
        Intrinsics.checkNotNullParameter(onFound, "onFound");
        if (FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2307getNextdhqQ8s()) ? true : FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2309getPreviousdhqQ8s())) {
            return OneDimensionalFocusSearchKt.m2324oneDimensionalFocusSearchOMvw8(focusSearch, focusDirection, onFound);
        }
        if (FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2306getLeftdhqQ8s()) ? true : FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2310getRightdhqQ8s()) ? true : FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2311getUpdhqQ8s()) ? true : FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2302getDowndhqQ8s())) {
            Boolean m2333twoDimensionalFocusSearchOMvw82 = TwoDimensionalFocusSearchKt.m2333twoDimensionalFocusSearchOMvw8(focusSearch, focusDirection, onFound);
            if (m2333twoDimensionalFocusSearchOMvw82 != null) {
                return m2333twoDimensionalFocusSearchOMvw82.booleanValue();
            }
            return false;
        } else if (FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2303getEnterdhqQ8s())) {
            switch (WhenMappings.$EnumSwitchMapping$0[layoutDirection.ordinal()]) {
                case 1:
                    direction = FocusDirection.Companion.m2310getRightdhqQ8s();
                    break;
                case 2:
                    direction = FocusDirection.Companion.m2306getLeftdhqQ8s();
                    break;
                default:
                    throw new NoWhenBranchMatchedException();
            }
            FocusTargetModifierNode findActiveFocusNode = findActiveFocusNode(focusSearch);
            if (findActiveFocusNode == null || (m2333twoDimensionalFocusSearchOMvw8 = TwoDimensionalFocusSearchKt.m2333twoDimensionalFocusSearchOMvw8(findActiveFocusNode, direction, onFound)) == null) {
                return false;
            }
            return m2333twoDimensionalFocusSearchOMvw8.booleanValue();
        } else if (FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2304getExitdhqQ8s())) {
            FocusTargetModifierNode findActiveFocusNode2 = findActiveFocusNode(focusSearch);
            FocusTargetModifierNode it = findActiveFocusNode2 != null ? findNonDeactivatedParent(findActiveFocusNode2) : null;
            if (it == null || Intrinsics.areEqual(it, focusSearch)) {
                return false;
            }
            return onFound.invoke(it).booleanValue();
        } else {
            throw new IllegalStateException(("Focus search invoked with invalid FocusDirection " + ((Object) FocusDirection.m2296toStringimpl(focusDirection))).toString());
        }
    }

    public static final Rect focusRect(FocusTargetModifierNode $this$focusRect) {
        Rect localBoundingBoxOf;
        Intrinsics.checkNotNullParameter($this$focusRect, "<this>");
        NodeCoordinator it = $this$focusRect.getCoordinator$ui_release();
        return (it == null || (localBoundingBoxOf = LayoutCoordinatesKt.findRootCoordinates(it).localBoundingBoxOf(it, false)) == null) ? Rect.Companion.getZero() : localBoundingBoxOf;
    }

    public static final boolean isEligibleForFocusSearch(FocusTargetModifierNode $this$isEligibleForFocusSearch) {
        LayoutNode layoutNode;
        LayoutNode layoutNode2;
        Intrinsics.checkNotNullParameter($this$isEligibleForFocusSearch, "<this>");
        NodeCoordinator coordinator$ui_release = $this$isEligibleForFocusSearch.getCoordinator$ui_release();
        if ((coordinator$ui_release == null || (layoutNode2 = coordinator$ui_release.getLayoutNode()) == null || !layoutNode2.isPlaced()) ? false : true) {
            NodeCoordinator coordinator$ui_release2 = $this$isEligibleForFocusSearch.getCoordinator$ui_release();
            if ((coordinator$ui_release2 == null || (layoutNode = coordinator$ui_release2.getLayoutNode()) == null || !layoutNode.isAttached()) ? false : true) {
                return true;
            }
        }
        return false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:40:0x0050, code lost:
        continue;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.ui.focus.FocusTargetModifierNode getActiveChild(androidx.compose.ui.focus.FocusTargetModifierNode r18) {
        /*
            r0 = r18
            java.lang.String r1 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            androidx.compose.ui.Modifier$Node r1 = r18.getNode()
            boolean r1 = r1.isAttached()
            r2 = 0
            if (r1 != 0) goto L13
            return r2
        L13:
            r1 = r0
            androidx.compose.ui.node.DelegatableNode r1 = (androidx.compose.ui.node.DelegatableNode) r1
            r3 = 0
            r4 = 1024(0x400, float:1.435E-42)
            int r3 = androidx.compose.ui.node.NodeKind.m4327constructorimpl(r4)
            r4 = 0
            r5 = r3
            r6 = r1
            r7 = 0
            androidx.compose.ui.Modifier$Node r8 = r6.getNode()
            boolean r8 = r8.isAttached()
            if (r8 == 0) goto La0
            r8 = 0
            r9 = 16
            r10 = 0
            androidx.compose.runtime.collection.MutableVector r11 = new androidx.compose.runtime.collection.MutableVector
            androidx.compose.ui.Modifier$Node[] r12 = new androidx.compose.ui.Modifier.Node[r9]
            r13 = 0
            r11.<init>(r12, r13)
            r8 = r11
            androidx.compose.ui.Modifier$Node r9 = r6.getNode()
            androidx.compose.ui.Modifier$Node r9 = r9.getChild$ui_release()
            if (r9 != 0) goto L4d
            androidx.compose.ui.Modifier$Node r10 = r6.getNode()
            androidx.compose.ui.node.DelegatableNodeKt.access$addLayoutNodeChildren(r8, r10)
            goto L50
        L4d:
            r8.add(r9)
        L50:
            boolean r10 = r8.isNotEmpty()
            if (r10 == 0) goto L9d
            r10 = r8
            r11 = 0
            int r12 = r10.getSize()
            int r12 = r12 + (-1)
            java.lang.Object r10 = r8.removeAt(r12)
            androidx.compose.ui.Modifier$Node r10 = (androidx.compose.ui.Modifier.Node) r10
            int r11 = r10.getAggregateChildKindSet$ui_release()
            r11 = r11 & r5
            if (r11 != 0) goto L6f
            androidx.compose.ui.node.DelegatableNodeKt.access$addLayoutNodeChildren(r8, r10)
            goto L50
        L6f:
            r11 = r10
        L70:
            if (r11 == 0) goto L50
            int r12 = r11.getKindSet$ui_release()
            r12 = r12 & r5
            if (r12 == 0) goto L98
            r12 = r11
            r13 = 0
            boolean r14 = r12 instanceof androidx.compose.ui.focus.FocusTargetModifierNode
            if (r14 == 0) goto L95
            r14 = r12
            androidx.compose.ui.focus.FocusTargetModifierNode r14 = (androidx.compose.ui.focus.FocusTargetModifierNode) r14
            r15 = 0
            androidx.compose.ui.focus.FocusStateImpl r16 = r14.getFocusStateImpl$ui_release()
            int[] r17 = androidx.compose.ui.focus.FocusTraversalKt.WhenMappings.$EnumSwitchMapping$1
            int r16 = r16.ordinal()
            r16 = r17[r16]
            switch(r16) {
                case 1: goto L94;
                case 2: goto L94;
                case 3: goto L94;
                case 4: goto L93;
                default: goto L92;
            }
        L92:
            goto L95
        L93:
            goto L95
        L94:
            return r14
        L95:
            goto L50
        L98:
            androidx.compose.ui.Modifier$Node r11 = r11.getChild$ui_release()
            goto L70
        L9d:
            return r2
        La0:
            java.lang.IllegalStateException r2 = new java.lang.IllegalStateException
            java.lang.String r8 = "Check failed."
            java.lang.String r8 = r8.toString()
            r2.<init>(r8)
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.FocusTraversalKt.getActiveChild(androidx.compose.ui.focus.FocusTargetModifierNode):androidx.compose.ui.focus.FocusTargetModifierNode");
    }

    /* JADX WARN: Code restructure failed: missing block: B:43:0x005b, code lost:
        continue;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.ui.focus.FocusTargetModifierNode findActiveFocusNode(androidx.compose.ui.focus.FocusTargetModifierNode r17) {
        /*
            r0 = r17
            java.lang.String r1 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            androidx.compose.ui.focus.FocusStateImpl r1 = r17.getFocusStateImpl$ui_release()
            int[] r2 = androidx.compose.ui.focus.FocusTraversalKt.WhenMappings.$EnumSwitchMapping$1
            int r1 = r1.ordinal()
            r1 = r2[r1]
            r2 = 0
            switch(r1) {
                case 1: goto Lb1;
                case 2: goto L1e;
                case 3: goto Lb1;
                case 4: goto L1d;
                default: goto L17;
            }
        L17:
            kotlin.NoWhenBranchMatchedException r1 = new kotlin.NoWhenBranchMatchedException
            r1.<init>()
            throw r1
        L1d:
            return r2
        L1e:
            r1 = r0
            androidx.compose.ui.node.DelegatableNode r1 = (androidx.compose.ui.node.DelegatableNode) r1
            r3 = 0
            r4 = 1024(0x400, float:1.435E-42)
            int r3 = androidx.compose.ui.node.NodeKind.m4327constructorimpl(r4)
            r4 = 0
            r5 = r3
            r6 = r1
            r7 = 0
            androidx.compose.ui.Modifier$Node r8 = r6.getNode()
            boolean r8 = r8.isAttached()
            if (r8 == 0) goto La5
            r8 = 0
            r9 = 16
            r10 = 0
            androidx.compose.runtime.collection.MutableVector r11 = new androidx.compose.runtime.collection.MutableVector
            androidx.compose.ui.Modifier$Node[] r12 = new androidx.compose.ui.Modifier.Node[r9]
            r13 = 0
            r11.<init>(r12, r13)
            r8 = r11
            androidx.compose.ui.Modifier$Node r9 = r6.getNode()
            androidx.compose.ui.Modifier$Node r9 = r9.getChild$ui_release()
            if (r9 != 0) goto L58
            androidx.compose.ui.Modifier$Node r10 = r6.getNode()
            androidx.compose.ui.node.DelegatableNodeKt.access$addLayoutNodeChildren(r8, r10)
            goto L5b
        L58:
            r8.add(r9)
        L5b:
            boolean r10 = r8.isNotEmpty()
            if (r10 == 0) goto La2
            r10 = r8
            r11 = 0
            int r12 = r10.getSize()
            int r12 = r12 + (-1)
            java.lang.Object r10 = r8.removeAt(r12)
            androidx.compose.ui.Modifier$Node r10 = (androidx.compose.ui.Modifier.Node) r10
            int r11 = r10.getAggregateChildKindSet$ui_release()
            r11 = r11 & r5
            if (r11 != 0) goto L7a
            androidx.compose.ui.node.DelegatableNodeKt.access$addLayoutNodeChildren(r8, r10)
            goto L5b
        L7a:
            r11 = r10
        L7b:
            if (r11 == 0) goto L5b
            int r12 = r11.getKindSet$ui_release()
            r12 = r12 & r5
            if (r12 == 0) goto L9d
            r12 = r11
            r13 = 0
            boolean r14 = r12 instanceof androidx.compose.ui.focus.FocusTargetModifierNode
            if (r14 == 0) goto L9b
            r14 = r12
            androidx.compose.ui.focus.FocusTargetModifierNode r14 = (androidx.compose.ui.focus.FocusTargetModifierNode) r14
            r15 = 0
            androidx.compose.ui.focus.FocusTargetModifierNode r16 = findActiveFocusNode(r14)
            if (r16 == 0) goto L99
            r2 = r16
            r16 = 0
            return r2
        L99:
        L9b:
            goto L5b
        L9d:
            androidx.compose.ui.Modifier$Node r11 = r11.getChild$ui_release()
            goto L7b
        La2:
            return r2
        La5:
            java.lang.IllegalStateException r2 = new java.lang.IllegalStateException
            java.lang.String r8 = "Check failed."
            java.lang.String r8 = r8.toString()
            r2.<init>(r8)
            throw r2
        Lb1:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.FocusTraversalKt.findActiveFocusNode(androidx.compose.ui.focus.FocusTargetModifierNode):androidx.compose.ui.focus.FocusTargetModifierNode");
    }

    private static final FocusTargetModifierNode findNonDeactivatedParent(FocusTargetModifierNode $this$findNonDeactivatedParent) {
        NodeChain nodes$ui_release;
        FocusTargetModifierNode $this$visitAncestors_u2d6rFNWt0$iv = $this$findNonDeactivatedParent;
        int m4327constructorimpl = NodeKind.m4327constructorimpl(1024);
        if (!$this$visitAncestors_u2d6rFNWt0$iv.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        Modifier.Node node$iv$iv = $this$visitAncestors_u2d6rFNWt0$iv.getNode().getParent$ui_release();
        LayoutNode layout$iv$iv = DelegatableNodeKt.requireLayoutNode($this$visitAncestors_u2d6rFNWt0$iv);
        while (true) {
            Modifier.Node node = null;
            if (layout$iv$iv == null) {
                return null;
            }
            Modifier.Node head$iv$iv = layout$iv$iv.getNodes$ui_release().getHead$ui_release();
            if ((head$iv$iv.getAggregateChildKindSet$ui_release() & m4327constructorimpl) != 0) {
                while (node$iv$iv != null) {
                    if ((node$iv$iv.getKindSet$ui_release() & m4327constructorimpl) != 0) {
                        Modifier.Node it$iv = node$iv$iv;
                        if (it$iv instanceof FocusTargetModifierNode) {
                            FocusTargetModifierNode it = (FocusTargetModifierNode) it$iv;
                            if (it.fetchFocusProperties$ui_release().getCanFocus()) {
                                return it;
                            }
                        } else {
                            continue;
                        }
                    }
                    node$iv$iv = node$iv$iv.getParent$ui_release();
                }
            }
            layout$iv$iv = layout$iv$iv.getParent$ui_release();
            if (layout$iv$iv != null && (nodes$ui_release = layout$iv$iv.getNodes$ui_release()) != null) {
                node = nodes$ui_release.getTail$ui_release();
            }
            node$iv$iv = node;
        }
    }
}
