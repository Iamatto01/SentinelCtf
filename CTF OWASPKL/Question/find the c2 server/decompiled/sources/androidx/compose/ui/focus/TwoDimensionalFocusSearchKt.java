package androidx.compose.ui.focus;

import androidx.compose.runtime.collection.MutableVector;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.geometry.Rect;
import androidx.compose.ui.layout.BeyondBoundsLayout;
import androidx.compose.ui.node.DelegatableNode;
import androidx.compose.ui.node.DelegatableNodeKt;
import androidx.compose.ui.node.NodeKind;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: TwoDimensionalFocusSearch.kt */
@Metadata(d1 = {"\u0000B\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\r\u001a5\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\nH\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u000b\u0010\f\u001a5\u0010\r\u001a\u00020\u00042\u0006\u0010\u000e\u001a\u00020\u00062\u0006\u0010\u000f\u001a\u00020\u00062\u0006\u0010\u0010\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\nH\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0011\u0010\f\u001a\f\u0010\u0012\u001a\u00020\u0013*\u00020\u0013H\u0003\u001a\f\u0010\u0014\u001a\u00020\u0006*\u00020\u0006H\u0002\u001a\u001a\u0010\u0015\u001a\u00020\u0016*\u00020\u00172\f\u0010\u0018\u001a\b\u0012\u0004\u0012\u00020\u00130\u0019H\u0003\u001a1\u0010\u001a\u001a\u0004\u0018\u00010\u0013*\b\u0012\u0004\u0012\u00020\u00130\u00192\u0006\u0010\u001b\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\nH\u0003ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001c\u0010\u001d\u001a5\u0010\u001e\u001a\u00020\u0004*\u00020\u00132\u0006\u0010\t\u001a\u00020\n2\u0012\u0010\u001f\u001a\u000e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\u00040 H\u0001ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b!\u0010\"\u001a=\u0010#\u001a\u00020\u0004*\u00020\u00132\u0006\u0010$\u001a\u00020\u00132\u0006\u0010\t\u001a\u00020\n2\u0012\u0010\u001f\u001a\u000e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\u00040 H\u0003ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b%\u0010&\u001a=\u0010'\u001a\u00020\u0004*\u00020\u00132\u0006\u0010$\u001a\u00020\u00132\u0006\u0010\t\u001a\u00020\n2\u0012\u0010\u001f\u001a\u000e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\u00040 H\u0003ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b(\u0010&\u001a\f\u0010)\u001a\u00020\u0006*\u00020\u0006H\u0002\u001a7\u0010*\u001a\u0004\u0018\u00010\u0004*\u00020\u00132\u0006\u0010\t\u001a\u00020\n2\u0012\u0010\u001f\u001a\u000e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\u00040 H\u0001ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b+\u0010,\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0002\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006-"}, d2 = {"InvalidFocusDirection", "", "NoActiveChild", "beamBeats", "", "source", "Landroidx/compose/ui/geometry/Rect;", "rect1", "rect2", "direction", "Landroidx/compose/ui/focus/FocusDirection;", "beamBeats-I7lrPNg", "(Landroidx/compose/ui/geometry/Rect;Landroidx/compose/ui/geometry/Rect;Landroidx/compose/ui/geometry/Rect;I)Z", "isBetterCandidate", "proposedCandidate", "currentCandidate", "focusedRect", "isBetterCandidate-I7lrPNg", "activeNode", "Landroidx/compose/ui/focus/FocusTargetModifierNode;", "bottomRight", "collectAccessibleChildren", "", "Landroidx/compose/ui/node/DelegatableNode;", "accessibleChildren", "Landroidx/compose/runtime/collection/MutableVector;", "findBestCandidate", "focusRect", "findBestCandidate-4WY_MpI", "(Landroidx/compose/runtime/collection/MutableVector;Landroidx/compose/ui/geometry/Rect;I)Landroidx/compose/ui/focus/FocusTargetModifierNode;", "findChildCorrespondingToFocusEnter", "onFound", "Lkotlin/Function1;", "findChildCorrespondingToFocusEnter--OM-vw8", "(Landroidx/compose/ui/focus/FocusTargetModifierNode;ILkotlin/jvm/functions/Function1;)Z", "generateAndSearchChildren", "focusedItem", "generateAndSearchChildren-4C6V_qg", "(Landroidx/compose/ui/focus/FocusTargetModifierNode;Landroidx/compose/ui/focus/FocusTargetModifierNode;ILkotlin/jvm/functions/Function1;)Z", "searchChildren", "searchChildren-4C6V_qg", "topLeft", "twoDimensionalFocusSearch", "twoDimensionalFocusSearch--OM-vw8", "(Landroidx/compose/ui/focus/FocusTargetModifierNode;ILkotlin/jvm/functions/Function1;)Ljava/lang/Boolean;", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class TwoDimensionalFocusSearchKt {
    private static final String InvalidFocusDirection = "This function should only be used for 2-D focus search";
    private static final String NoActiveChild = "ActiveParent must have a focusedChild";

    /* compiled from: TwoDimensionalFocusSearch.kt */
    @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[FocusStateImpl.values().length];
            try {
                iArr[FocusStateImpl.ActiveParent.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                iArr[FocusStateImpl.Active.ordinal()] = 2;
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

    /* renamed from: twoDimensionalFocusSearch--OM-vw8  reason: not valid java name */
    public static final Boolean m2333twoDimensionalFocusSearchOMvw8(FocusTargetModifierNode twoDimensionalFocusSearch, int direction, Function1<? super FocusTargetModifierNode, Boolean> onFound) {
        Intrinsics.checkNotNullParameter(twoDimensionalFocusSearch, "$this$twoDimensionalFocusSearch");
        Intrinsics.checkNotNullParameter(onFound, "onFound");
        switch (WhenMappings.$EnumSwitchMapping$0[twoDimensionalFocusSearch.getFocusStateImpl$ui_release().ordinal()]) {
            case 1:
                FocusTargetModifierNode focusedChild = FocusTraversalKt.getActiveChild(twoDimensionalFocusSearch);
                if (focusedChild == null) {
                    throw new IllegalStateException(NoActiveChild.toString());
                }
                switch (WhenMappings.$EnumSwitchMapping$0[focusedChild.getFocusStateImpl$ui_release().ordinal()]) {
                    case 1:
                        Boolean found = m2333twoDimensionalFocusSearchOMvw8(focusedChild, direction, onFound);
                        if (Intrinsics.areEqual((Object) found, (Object) false)) {
                            FocusRequester it = focusedChild.fetchFocusProperties$ui_release().getExit().invoke(FocusDirection.m2291boximpl(direction));
                            if (Intrinsics.areEqual(it, FocusRequester.Companion.getDefault())) {
                                it = null;
                            }
                            FocusRequester it2 = it;
                            if (it2 != null) {
                                if (Intrinsics.areEqual(it2, FocusRequester.Companion.getCancel())) {
                                    return null;
                                }
                                return Boolean.valueOf(it2.findFocusTarget$ui_release(onFound));
                            }
                            return Boolean.valueOf(m2330generateAndSearchChildren4C6V_qg(twoDimensionalFocusSearch, activeNode(focusedChild), direction, onFound));
                        }
                        return found;
                    case 2:
                    case 3:
                        return Boolean.valueOf(m2330generateAndSearchChildren4C6V_qg(twoDimensionalFocusSearch, focusedChild, direction, onFound));
                    case 4:
                        throw new IllegalStateException(NoActiveChild.toString());
                    default:
                        throw new NoWhenBranchMatchedException();
                }
            case 2:
            case 3:
                return Boolean.valueOf(m2329findChildCorrespondingToFocusEnterOMvw8(twoDimensionalFocusSearch, direction, onFound));
            case 4:
                if (twoDimensionalFocusSearch.fetchFocusProperties$ui_release().getCanFocus()) {
                    return onFound.invoke(twoDimensionalFocusSearch);
                }
                return false;
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r7v0, types: [java.lang.Object[]] */
    /* JADX WARN: Type inference failed for: r7v1 */
    /* renamed from: findChildCorrespondingToFocusEnter--OM-vw8  reason: not valid java name */
    public static final boolean m2329findChildCorrespondingToFocusEnterOMvw8(FocusTargetModifierNode findChildCorrespondingToFocusEnter, int direction, Function1<? super FocusTargetModifierNode, Boolean> onFound) {
        int requestedDirection;
        Rect initialFocusRect;
        Intrinsics.checkNotNullParameter(findChildCorrespondingToFocusEnter, "$this$findChildCorrespondingToFocusEnter");
        Intrinsics.checkNotNullParameter(onFound, "onFound");
        FocusRequester it = findChildCorrespondingToFocusEnter.fetchFocusProperties$ui_release().getEnter().invoke(FocusDirection.m2291boximpl(direction));
        if (Intrinsics.areEqual(it, FocusRequester.Companion.getDefault())) {
            it = null;
        }
        FocusRequester it2 = it;
        if (it2 != null) {
            if (Intrinsics.areEqual(it2, FocusRequester.Companion.getCancel())) {
                return false;
            }
            return it2.findFocusTarget$ui_release(onFound);
        }
        MutableVector focusableChildren = new MutableVector(new FocusTargetModifierNode[16], 0);
        collectAccessibleChildren(findChildCorrespondingToFocusEnter, focusableChildren);
        if (focusableChildren.getSize() > 1) {
            if (FocusDirection.m2294equalsimpl0(direction, FocusDirection.Companion.m2303getEnterdhqQ8s())) {
                requestedDirection = FocusDirection.Companion.m2310getRightdhqQ8s();
            } else {
                requestedDirection = direction;
            }
            if (FocusDirection.m2294equalsimpl0(requestedDirection, FocusDirection.Companion.m2310getRightdhqQ8s()) ? true : FocusDirection.m2294equalsimpl0(requestedDirection, FocusDirection.Companion.m2302getDowndhqQ8s())) {
                initialFocusRect = topLeft(FocusTraversalKt.focusRect(findChildCorrespondingToFocusEnter));
            } else {
                if (!(FocusDirection.m2294equalsimpl0(requestedDirection, FocusDirection.Companion.m2306getLeftdhqQ8s()) ? true : FocusDirection.m2294equalsimpl0(requestedDirection, FocusDirection.Companion.m2311getUpdhqQ8s()))) {
                    throw new IllegalStateException(InvalidFocusDirection.toString());
                }
                initialFocusRect = bottomRight(FocusTraversalKt.focusRect(findChildCorrespondingToFocusEnter));
            }
            FocusTargetModifierNode nextCandidate = m2328findBestCandidate4WY_MpI(focusableChildren, initialFocusRect, requestedDirection);
            if (nextCandidate != null) {
                return onFound.invoke(nextCandidate).booleanValue();
            }
            return false;
        }
        FocusTargetModifierNode it3 = focusableChildren.isEmpty() ? null : focusableChildren.getContent()[0];
        if (it3 != null) {
            return onFound.invoke(it3).booleanValue();
        }
        return false;
    }

    /* renamed from: generateAndSearchChildren-4C6V_qg  reason: not valid java name */
    private static final boolean m2330generateAndSearchChildren4C6V_qg(final FocusTargetModifierNode $this$generateAndSearchChildren_u2d4C6V_qg, final FocusTargetModifierNode focusedItem, final int direction, final Function1<? super FocusTargetModifierNode, Boolean> function1) {
        if (m2332searchChildren4C6V_qg($this$generateAndSearchChildren_u2d4C6V_qg, focusedItem, direction, function1)) {
            return true;
        }
        Boolean bool = (Boolean) BeyondBoundsLayoutKt.m2290searchBeyondBoundsOMvw8($this$generateAndSearchChildren_u2d4C6V_qg, direction, new Function1<BeyondBoundsLayout.BeyondBoundsScope, Boolean>() { // from class: androidx.compose.ui.focus.TwoDimensionalFocusSearchKt$generateAndSearchChildren$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public final Boolean invoke(BeyondBoundsLayout.BeyondBoundsScope searchBeyondBounds) {
                boolean m2332searchChildren4C6V_qg;
                Intrinsics.checkNotNullParameter(searchBeyondBounds, "$this$searchBeyondBounds");
                m2332searchChildren4C6V_qg = TwoDimensionalFocusSearchKt.m2332searchChildren4C6V_qg(FocusTargetModifierNode.this, focusedItem, direction, function1);
                Boolean valueOf = Boolean.valueOf(m2332searchChildren4C6V_qg);
                boolean found = valueOf.booleanValue();
                if (found || !searchBeyondBounds.getHasMoreContent()) {
                    return valueOf;
                }
                return null;
            }
        });
        if (bool != null) {
            return bool.booleanValue();
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: searchChildren-4C6V_qg  reason: not valid java name */
    public static final boolean m2332searchChildren4C6V_qg(FocusTargetModifierNode $this$searchChildren_u2d4C6V_qg, FocusTargetModifierNode focusedItem, int direction, Function1<? super FocusTargetModifierNode, Boolean> function1) {
        FocusTargetModifierNode nextItem;
        MutableVector $this$searchChildren_4C6V_qg_u24lambda_u247 = new MutableVector(new FocusTargetModifierNode[16], 0);
        FocusTargetModifierNode $this$visitChildren_u2d6rFNWt0$iv = $this$searchChildren_u2d4C6V_qg;
        int m4327constructorimpl = NodeKind.m4327constructorimpl(1024);
        if ($this$visitChildren_u2d6rFNWt0$iv.getNode().isAttached()) {
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
                                $this$searchChildren_4C6V_qg_u24lambda_u247.add((FocusTargetModifierNode) it$iv);
                            }
                        } else {
                            node$iv$iv = node$iv$iv.getChild$ui_release();
                        }
                    }
                }
            }
            while ($this$searchChildren_4C6V_qg_u24lambda_u247.isNotEmpty() && (nextItem = m2328findBestCandidate4WY_MpI($this$searchChildren_4C6V_qg_u24lambda_u247, FocusTraversalKt.focusRect(focusedItem), direction)) != null) {
                if (nextItem.fetchFocusProperties$ui_release().getCanFocus()) {
                    return function1.invoke(nextItem).booleanValue();
                }
                FocusRequester it = nextItem.fetchFocusProperties$ui_release().getEnter().invoke(FocusDirection.m2291boximpl(direction));
                if (Intrinsics.areEqual(it, FocusRequester.Companion.getDefault())) {
                    it = null;
                }
                FocusRequester it2 = it;
                if (it2 == null) {
                    if (m2330generateAndSearchChildren4C6V_qg(nextItem, focusedItem, direction, function1)) {
                        return true;
                    }
                    $this$searchChildren_4C6V_qg_u24lambda_u247.remove(nextItem);
                } else if (Intrinsics.areEqual(it2, FocusRequester.Companion.getCancel())) {
                    return false;
                } else {
                    return it2.findFocusTarget$ui_release(function1);
                }
            }
            return false;
        }
        throw new IllegalStateException("Check failed.".toString());
    }

    private static final void collectAccessibleChildren(DelegatableNode $this$collectAccessibleChildren, MutableVector<FocusTargetModifierNode> mutableVector) {
        int type$iv;
        DelegatableNode $this$visitSubtreeIf_u2d6rFNWt0$iv;
        boolean z;
        MutableVector<FocusTargetModifierNode> mutableVector2 = mutableVector;
        int type$iv2 = NodeKind.m4327constructorimpl(1024);
        DelegatableNode $this$visitSubtreeIf_u2d6rFNWt0$iv2 = $this$collectAccessibleChildren;
        if (!$this$visitSubtreeIf_u2d6rFNWt0$iv2.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        boolean z2 = false;
        MutableVector branches$iv$iv = new MutableVector(new Modifier.Node[16], 0);
        Modifier.Node child$iv$iv = $this$visitSubtreeIf_u2d6rFNWt0$iv2.getNode().getChild$ui_release();
        if (child$iv$iv == null) {
            DelegatableNodeKt.addLayoutNodeChildren(branches$iv$iv, $this$visitSubtreeIf_u2d6rFNWt0$iv2.getNode());
        } else {
            branches$iv$iv.add(child$iv$iv);
        }
        while (branches$iv$iv.isNotEmpty()) {
            int size = branches$iv$iv.getSize();
            boolean z3 = true;
            Modifier.Node branch$iv$iv = (Modifier.Node) branches$iv$iv.removeAt(size - 1);
            if ((branch$iv$iv.getAggregateChildKindSet$ui_release() & type$iv2) != 0) {
                Modifier.Node node$iv$iv = branch$iv$iv;
                while (node$iv$iv != null) {
                    if ((node$iv$iv.getKindSet$ui_release() & type$iv2) == 0) {
                        type$iv = type$iv2;
                        $this$visitSubtreeIf_u2d6rFNWt0$iv = $this$visitSubtreeIf_u2d6rFNWt0$iv2;
                        z = z3;
                    } else {
                        Modifier.Node it$iv = node$iv$iv;
                        if (it$iv instanceof FocusTargetModifierNode) {
                            FocusTargetModifierNode it = (FocusTargetModifierNode) it$iv;
                            if (it.fetchFocusProperties$ui_release().getCanFocus()) {
                                mutableVector2.add(it);
                                type$iv = type$iv2;
                                $this$visitSubtreeIf_u2d6rFNWt0$iv = $this$visitSubtreeIf_u2d6rFNWt0$iv2;
                                z = z3;
                            } else {
                                FocusRequester it2 = it.fetchFocusProperties$ui_release().getEnter().invoke(FocusDirection.m2291boximpl(FocusDirection.Companion.m2303getEnterdhqQ8s()));
                                type$iv = type$iv2;
                                if (Intrinsics.areEqual(it2, FocusRequester.Companion.getDefault())) {
                                    it2 = null;
                                }
                                FocusRequester it3 = it2;
                                if (it3 != null) {
                                    if (Intrinsics.areEqual(it3, FocusRequester.Companion.getCancel())) {
                                        $this$visitSubtreeIf_u2d6rFNWt0$iv = $this$visitSubtreeIf_u2d6rFNWt0$iv2;
                                        z = true;
                                    } else {
                                        MutableVector this_$iv = it3.getFocusRequesterNodes$ui_release();
                                        int size$iv = this_$iv.getSize();
                                        if (size$iv <= 0) {
                                            $this$visitSubtreeIf_u2d6rFNWt0$iv = $this$visitSubtreeIf_u2d6rFNWt0$iv2;
                                            z = true;
                                        } else {
                                            int i$iv = 0;
                                            Object[] content$iv = this_$iv.getContent();
                                            while (true) {
                                                FocusRequesterModifierNode node = (FocusRequesterModifierNode) content$iv[i$iv];
                                                $this$visitSubtreeIf_u2d6rFNWt0$iv = $this$visitSubtreeIf_u2d6rFNWt0$iv2;
                                                collectAccessibleChildren(node, mutableVector2);
                                                z = true;
                                                int i$iv2 = i$iv + 1;
                                                if (i$iv2 >= size$iv) {
                                                    break;
                                                }
                                                i$iv = i$iv2;
                                                $this$visitSubtreeIf_u2d6rFNWt0$iv2 = $this$visitSubtreeIf_u2d6rFNWt0$iv;
                                                mutableVector2 = mutableVector;
                                            }
                                        }
                                    }
                                    z2 = false;
                                } else {
                                    $this$visitSubtreeIf_u2d6rFNWt0$iv = $this$visitSubtreeIf_u2d6rFNWt0$iv2;
                                    z = true;
                                    z2 = true;
                                }
                            }
                        } else {
                            type$iv = type$iv2;
                            $this$visitSubtreeIf_u2d6rFNWt0$iv = $this$visitSubtreeIf_u2d6rFNWt0$iv2;
                            z = z3;
                            z2 = z;
                        }
                        boolean diveDeeper$iv$iv = z2;
                        if (!diveDeeper$iv$iv) {
                            mutableVector2 = mutableVector;
                            type$iv2 = type$iv;
                            $this$visitSubtreeIf_u2d6rFNWt0$iv2 = $this$visitSubtreeIf_u2d6rFNWt0$iv;
                            z2 = false;
                            break;
                        }
                    }
                    node$iv$iv = node$iv$iv.getChild$ui_release();
                    mutableVector2 = mutableVector;
                    z3 = z;
                    type$iv2 = type$iv;
                    $this$visitSubtreeIf_u2d6rFNWt0$iv2 = $this$visitSubtreeIf_u2d6rFNWt0$iv;
                    z2 = false;
                }
            }
            DelegatableNodeKt.addLayoutNodeChildren(branches$iv$iv, branch$iv$iv);
            mutableVector2 = mutableVector;
            type$iv2 = type$iv2;
            $this$visitSubtreeIf_u2d6rFNWt0$iv2 = $this$visitSubtreeIf_u2d6rFNWt0$iv2;
            z2 = false;
        }
    }

    /* renamed from: findBestCandidate-4WY_MpI  reason: not valid java name */
    private static final FocusTargetModifierNode m2328findBestCandidate4WY_MpI(MutableVector<FocusTargetModifierNode> mutableVector, Rect focusRect, int direction) {
        Rect translate;
        if (FocusDirection.m2294equalsimpl0(direction, FocusDirection.Companion.m2306getLeftdhqQ8s())) {
            translate = focusRect.translate(focusRect.getWidth() + 1, 0.0f);
        } else if (FocusDirection.m2294equalsimpl0(direction, FocusDirection.Companion.m2310getRightdhqQ8s())) {
            translate = focusRect.translate(-(focusRect.getWidth() + 1), 0.0f);
        } else if (FocusDirection.m2294equalsimpl0(direction, FocusDirection.Companion.m2311getUpdhqQ8s())) {
            translate = focusRect.translate(0.0f, focusRect.getHeight() + 1);
        } else if (!FocusDirection.m2294equalsimpl0(direction, FocusDirection.Companion.m2302getDowndhqQ8s())) {
            throw new IllegalStateException(InvalidFocusDirection.toString());
        } else {
            translate = focusRect.translate(0.0f, -(focusRect.getHeight() + 1));
        }
        Rect rect = translate;
        FocusTargetModifierNode focusTargetModifierNode = null;
        int size$iv = mutableVector.getSize();
        if (size$iv <= 0) {
            return focusTargetModifierNode;
        }
        int i$iv = 0;
        Object[] content$iv = mutableVector.getContent();
        do {
            FocusTargetModifierNode candidateNode = (FocusTargetModifierNode) content$iv[i$iv];
            if (FocusTraversalKt.isEligibleForFocusSearch(candidateNode)) {
                Rect candidateRect = FocusTraversalKt.focusRect(candidateNode);
                if (m2331isBetterCandidateI7lrPNg(candidateRect, rect, focusRect, direction)) {
                    rect = candidateRect;
                    focusTargetModifierNode = candidateNode;
                }
            }
            i$iv++;
        } while (i$iv < size$iv);
        return focusTargetModifierNode;
    }

    private static final boolean isBetterCandidate_I7lrPNg$isCandidate(Rect $this$isBetterCandidate_I7lrPNg_u24isCandidate, int $direction, Rect $focusedRect) {
        if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2306getLeftdhqQ8s())) {
            return ($focusedRect.getRight() > $this$isBetterCandidate_I7lrPNg_u24isCandidate.getRight() || $focusedRect.getLeft() >= $this$isBetterCandidate_I7lrPNg_u24isCandidate.getRight()) && $focusedRect.getLeft() > $this$isBetterCandidate_I7lrPNg_u24isCandidate.getLeft();
        } else if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2310getRightdhqQ8s())) {
            return ($focusedRect.getLeft() < $this$isBetterCandidate_I7lrPNg_u24isCandidate.getLeft() || $focusedRect.getRight() <= $this$isBetterCandidate_I7lrPNg_u24isCandidate.getLeft()) && $focusedRect.getRight() < $this$isBetterCandidate_I7lrPNg_u24isCandidate.getRight();
        } else if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2311getUpdhqQ8s())) {
            return ($focusedRect.getBottom() > $this$isBetterCandidate_I7lrPNg_u24isCandidate.getBottom() || $focusedRect.getTop() >= $this$isBetterCandidate_I7lrPNg_u24isCandidate.getBottom()) && $focusedRect.getTop() > $this$isBetterCandidate_I7lrPNg_u24isCandidate.getTop();
        } else if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2302getDowndhqQ8s())) {
            return ($focusedRect.getTop() < $this$isBetterCandidate_I7lrPNg_u24isCandidate.getTop() || $focusedRect.getBottom() <= $this$isBetterCandidate_I7lrPNg_u24isCandidate.getTop()) && $focusedRect.getBottom() < $this$isBetterCandidate_I7lrPNg_u24isCandidate.getBottom();
        } else {
            throw new IllegalStateException(InvalidFocusDirection.toString());
        }
    }

    private static final float isBetterCandidate_I7lrPNg$majorAxisDistance(Rect $this$isBetterCandidate_I7lrPNg_u24majorAxisDistance, int $direction, Rect $focusedRect) {
        float majorAxisDistance;
        if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2306getLeftdhqQ8s())) {
            majorAxisDistance = $focusedRect.getLeft() - $this$isBetterCandidate_I7lrPNg_u24majorAxisDistance.getRight();
        } else if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2310getRightdhqQ8s())) {
            majorAxisDistance = $this$isBetterCandidate_I7lrPNg_u24majorAxisDistance.getLeft() - $focusedRect.getRight();
        } else if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2311getUpdhqQ8s())) {
            majorAxisDistance = $focusedRect.getTop() - $this$isBetterCandidate_I7lrPNg_u24majorAxisDistance.getBottom();
        } else if (!FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2302getDowndhqQ8s())) {
            throw new IllegalStateException(InvalidFocusDirection.toString());
        } else {
            majorAxisDistance = $this$isBetterCandidate_I7lrPNg_u24majorAxisDistance.getTop() - $focusedRect.getBottom();
        }
        return Math.max(0.0f, majorAxisDistance);
    }

    private static final float isBetterCandidate_I7lrPNg$minorAxisDistance(Rect $this$isBetterCandidate_I7lrPNg_u24minorAxisDistance, int $direction, Rect $focusedRect) {
        if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2306getLeftdhqQ8s()) ? true : FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2310getRightdhqQ8s())) {
            float f = 2;
            return ($focusedRect.getTop() + ($focusedRect.getHeight() / f)) - ($this$isBetterCandidate_I7lrPNg_u24minorAxisDistance.getTop() + ($this$isBetterCandidate_I7lrPNg_u24minorAxisDistance.getHeight() / f));
        }
        if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2311getUpdhqQ8s()) ? true : FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2302getDowndhqQ8s())) {
            float f2 = 2;
            return ($focusedRect.getLeft() + ($focusedRect.getWidth() / f2)) - ($this$isBetterCandidate_I7lrPNg_u24minorAxisDistance.getLeft() + ($this$isBetterCandidate_I7lrPNg_u24minorAxisDistance.getWidth() / f2));
        }
        throw new IllegalStateException(InvalidFocusDirection.toString());
    }

    private static final long isBetterCandidate_I7lrPNg$weightedDistance(int $direction, Rect $focusedRect, Rect candidate) {
        long majorAxisDistance = Math.abs(isBetterCandidate_I7lrPNg$majorAxisDistance(candidate, $direction, $focusedRect));
        long minorAxisDistance = Math.abs(isBetterCandidate_I7lrPNg$minorAxisDistance(candidate, $direction, $focusedRect));
        return (13 * majorAxisDistance * majorAxisDistance) + (minorAxisDistance * minorAxisDistance);
    }

    /* renamed from: isBetterCandidate-I7lrPNg  reason: not valid java name */
    private static final boolean m2331isBetterCandidateI7lrPNg(Rect proposedCandidate, Rect currentCandidate, Rect focusedRect, int direction) {
        if (isBetterCandidate_I7lrPNg$isCandidate(proposedCandidate, direction, focusedRect)) {
            if (isBetterCandidate_I7lrPNg$isCandidate(currentCandidate, direction, focusedRect) && !m2327beamBeatsI7lrPNg(focusedRect, proposedCandidate, currentCandidate, direction)) {
                return !m2327beamBeatsI7lrPNg(focusedRect, currentCandidate, proposedCandidate, direction) && isBetterCandidate_I7lrPNg$weightedDistance(direction, focusedRect, proposedCandidate) < isBetterCandidate_I7lrPNg$weightedDistance(direction, focusedRect, currentCandidate);
            }
            return true;
        }
        return false;
    }

    private static final boolean beamBeats_I7lrPNg$inSourceBeam(Rect $this$beamBeats_I7lrPNg_u24inSourceBeam, int $direction, Rect $source) {
        if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2306getLeftdhqQ8s()) ? true : FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2310getRightdhqQ8s())) {
            return $this$beamBeats_I7lrPNg_u24inSourceBeam.getBottom() > $source.getTop() && $this$beamBeats_I7lrPNg_u24inSourceBeam.getTop() < $source.getBottom();
        }
        if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2311getUpdhqQ8s()) ? true : FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2302getDowndhqQ8s())) {
            return $this$beamBeats_I7lrPNg_u24inSourceBeam.getRight() > $source.getLeft() && $this$beamBeats_I7lrPNg_u24inSourceBeam.getLeft() < $source.getRight();
        }
        throw new IllegalStateException(InvalidFocusDirection.toString());
    }

    private static final boolean beamBeats_I7lrPNg$isInDirectionOfSearch(Rect $this$beamBeats_I7lrPNg_u24isInDirectionOfSearch, int $direction, Rect $source) {
        if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2306getLeftdhqQ8s())) {
            return $source.getLeft() >= $this$beamBeats_I7lrPNg_u24isInDirectionOfSearch.getRight();
        } else if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2310getRightdhqQ8s())) {
            return $source.getRight() <= $this$beamBeats_I7lrPNg_u24isInDirectionOfSearch.getLeft();
        } else if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2311getUpdhqQ8s())) {
            return $source.getTop() >= $this$beamBeats_I7lrPNg_u24isInDirectionOfSearch.getBottom();
        } else if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2302getDowndhqQ8s())) {
            return $source.getBottom() <= $this$beamBeats_I7lrPNg_u24isInDirectionOfSearch.getTop();
        } else {
            throw new IllegalStateException(InvalidFocusDirection.toString());
        }
    }

    private static final float beamBeats_I7lrPNg$majorAxisDistance$15(Rect $this$beamBeats_I7lrPNg_u24majorAxisDistance_u2415, int $direction, Rect $source) {
        float majorAxisDistance;
        if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2306getLeftdhqQ8s())) {
            majorAxisDistance = $source.getLeft() - $this$beamBeats_I7lrPNg_u24majorAxisDistance_u2415.getRight();
        } else if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2310getRightdhqQ8s())) {
            majorAxisDistance = $this$beamBeats_I7lrPNg_u24majorAxisDistance_u2415.getLeft() - $source.getRight();
        } else if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2311getUpdhqQ8s())) {
            majorAxisDistance = $source.getTop() - $this$beamBeats_I7lrPNg_u24majorAxisDistance_u2415.getBottom();
        } else if (!FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2302getDowndhqQ8s())) {
            throw new IllegalStateException(InvalidFocusDirection.toString());
        } else {
            majorAxisDistance = $this$beamBeats_I7lrPNg_u24majorAxisDistance_u2415.getTop() - $source.getBottom();
        }
        return Math.max(0.0f, majorAxisDistance);
    }

    private static final float beamBeats_I7lrPNg$majorAxisDistanceToFarEdge(Rect $this$beamBeats_I7lrPNg_u24majorAxisDistanceToFarEdge, int $direction, Rect $source) {
        float majorAxisDistance;
        if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2306getLeftdhqQ8s())) {
            majorAxisDistance = $source.getLeft() - $this$beamBeats_I7lrPNg_u24majorAxisDistanceToFarEdge.getLeft();
        } else if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2310getRightdhqQ8s())) {
            majorAxisDistance = $this$beamBeats_I7lrPNg_u24majorAxisDistanceToFarEdge.getRight() - $source.getRight();
        } else if (FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2311getUpdhqQ8s())) {
            majorAxisDistance = $source.getTop() - $this$beamBeats_I7lrPNg_u24majorAxisDistanceToFarEdge.getTop();
        } else if (!FocusDirection.m2294equalsimpl0($direction, FocusDirection.Companion.m2302getDowndhqQ8s())) {
            throw new IllegalStateException(InvalidFocusDirection.toString());
        } else {
            majorAxisDistance = $this$beamBeats_I7lrPNg_u24majorAxisDistanceToFarEdge.getBottom() - $source.getBottom();
        }
        return Math.max(1.0f, majorAxisDistance);
    }

    /* renamed from: beamBeats-I7lrPNg  reason: not valid java name */
    private static final boolean m2327beamBeatsI7lrPNg(Rect source, Rect rect1, Rect rect2, int direction) {
        if (beamBeats_I7lrPNg$inSourceBeam(rect2, direction, source) || !beamBeats_I7lrPNg$inSourceBeam(rect1, direction, source)) {
            return false;
        }
        if (beamBeats_I7lrPNg$isInDirectionOfSearch(rect2, direction, source)) {
            if (FocusDirection.m2294equalsimpl0(direction, FocusDirection.Companion.m2306getLeftdhqQ8s()) || FocusDirection.m2294equalsimpl0(direction, FocusDirection.Companion.m2310getRightdhqQ8s())) {
                return true;
            }
            return beamBeats_I7lrPNg$majorAxisDistance$15(rect1, direction, source) < beamBeats_I7lrPNg$majorAxisDistanceToFarEdge(rect2, direction, source);
        }
        return true;
    }

    private static final Rect topLeft(Rect $this$topLeft) {
        return new Rect($this$topLeft.getLeft(), $this$topLeft.getTop(), $this$topLeft.getLeft(), $this$topLeft.getTop());
    }

    private static final Rect bottomRight(Rect $this$bottomRight) {
        return new Rect($this$bottomRight.getRight(), $this$bottomRight.getBottom(), $this$bottomRight.getRight(), $this$bottomRight.getBottom());
    }

    private static final FocusTargetModifierNode activeNode(FocusTargetModifierNode $this$activeNode) {
        if (!($this$activeNode.getFocusState() == FocusStateImpl.ActiveParent)) {
            throw new IllegalStateException("Check failed.".toString());
        }
        FocusTargetModifierNode findActiveFocusNode = FocusTraversalKt.findActiveFocusNode($this$activeNode);
        if (findActiveFocusNode != null) {
            return findActiveFocusNode;
        }
        throw new IllegalStateException(NoActiveChild.toString());
    }
}
