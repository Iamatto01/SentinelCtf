package androidx.compose.ui.focus;

import androidx.compose.runtime.collection.MutableVector;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.layout.BeyondBoundsLayout;
import androidx.compose.ui.node.DelegatableNodeKt;
import androidx.compose.ui.node.NodeKind;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
/* compiled from: OneDimensionalFocusSearch.kt */
@Metadata(d1 = {"\u00000\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u000b\u001a \u0010\u0003\u001a\u00020\u0004*\u00020\u00052\u0012\u0010\u0006\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00040\u0007H\u0003\u001aE\u0010\b\u001a\u00020\t\"\u0004\b\u0000\u0010\n*\b\u0012\u0004\u0012\u0002H\n0\u000b2\u0006\u0010\f\u001a\u0002H\n2\u0012\u0010\r\u001a\u000e\u0012\u0004\u0012\u0002H\n\u0012\u0004\u0012\u00020\t0\u0007H\u0082\b\u0082\u0002\b\n\u0006\b\u0001\u0012\u0002\u0010\u0002¢\u0006\u0002\u0010\u000e\u001aE\u0010\u000f\u001a\u00020\t\"\u0004\b\u0000\u0010\n*\b\u0012\u0004\u0012\u0002H\n0\u000b2\u0006\u0010\f\u001a\u0002H\n2\u0012\u0010\r\u001a\u000e\u0012\u0004\u0012\u0002H\n\u0012\u0004\u0012\u00020\t0\u0007H\u0082\b\u0082\u0002\b\n\u0006\b\u0001\u0012\u0002\u0010\u0002¢\u0006\u0002\u0010\u000e\u001a \u0010\u0010\u001a\u00020\u0004*\u00020\u00052\u0012\u0010\u0006\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00040\u0007H\u0003\u001a=\u0010\u0011\u001a\u00020\u0004*\u00020\u00052\u0006\u0010\u0012\u001a\u00020\u00052\u0006\u0010\u0013\u001a\u00020\u00142\u0012\u0010\u0006\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00040\u0007H\u0003ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0015\u0010\u0016\u001a\f\u0010\u0017\u001a\u00020\u0004*\u00020\u0005H\u0002\u001a5\u0010\u0018\u001a\u00020\u0004*\u00020\u00052\u0006\u0010\u0013\u001a\u00020\u00142\u0012\u0010\u0006\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00040\u0007H\u0001ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0019\u0010\u001a\u001a \u0010\u001b\u001a\u00020\u0004*\u00020\u00052\u0012\u0010\u0006\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00040\u0007H\u0003\u001a \u0010\u001c\u001a\u00020\u0004*\u00020\u00052\u0012\u0010\u0006\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00040\u0007H\u0003\u001a=\u0010\u001d\u001a\u00020\u0004*\u00020\u00052\u0006\u0010\u0012\u001a\u00020\u00052\u0006\u0010\u0013\u001a\u00020\u00142\u0012\u0010\u0006\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00040\u0007H\u0003ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001e\u0010\u0016\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0002\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006\u001f"}, d2 = {"InvalidFocusDirection", "", "NoActiveChild", "backwardFocusSearch", "", "Landroidx/compose/ui/focus/FocusTargetModifierNode;", "onFound", "Lkotlin/Function1;", "forEachItemAfter", "", "T", "Landroidx/compose/runtime/collection/MutableVector;", "item", "action", "(Landroidx/compose/runtime/collection/MutableVector;Ljava/lang/Object;Lkotlin/jvm/functions/Function1;)V", "forEachItemBefore", "forwardFocusSearch", "generateAndSearchChildren", "focusedItem", "direction", "Landroidx/compose/ui/focus/FocusDirection;", "generateAndSearchChildren-4C6V_qg", "(Landroidx/compose/ui/focus/FocusTargetModifierNode;Landroidx/compose/ui/focus/FocusTargetModifierNode;ILkotlin/jvm/functions/Function1;)Z", "isRoot", "oneDimensionalFocusSearch", "oneDimensionalFocusSearch--OM-vw8", "(Landroidx/compose/ui/focus/FocusTargetModifierNode;ILkotlin/jvm/functions/Function1;)Z", "pickChildForBackwardSearch", "pickChildForForwardSearch", "searchChildren", "searchChildren-4C6V_qg", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class OneDimensionalFocusSearchKt {
    private static final String InvalidFocusDirection = "This function should only be used for 1-D focus search";
    private static final String NoActiveChild = "ActiveParent must have a focusedChild";

    /* compiled from: OneDimensionalFocusSearch.kt */
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

    /* renamed from: oneDimensionalFocusSearch--OM-vw8  reason: not valid java name */
    public static final boolean m2324oneDimensionalFocusSearchOMvw8(FocusTargetModifierNode oneDimensionalFocusSearch, int direction, Function1<? super FocusTargetModifierNode, Boolean> onFound) {
        Intrinsics.checkNotNullParameter(oneDimensionalFocusSearch, "$this$oneDimensionalFocusSearch");
        Intrinsics.checkNotNullParameter(onFound, "onFound");
        if (FocusDirection.m2294equalsimpl0(direction, FocusDirection.Companion.m2307getNextdhqQ8s())) {
            return forwardFocusSearch(oneDimensionalFocusSearch, onFound);
        }
        if (FocusDirection.m2294equalsimpl0(direction, FocusDirection.Companion.m2309getPreviousdhqQ8s())) {
            return backwardFocusSearch(oneDimensionalFocusSearch, onFound);
        }
        throw new IllegalStateException(InvalidFocusDirection.toString());
    }

    private static final boolean forwardFocusSearch(FocusTargetModifierNode $this$forwardFocusSearch, Function1<? super FocusTargetModifierNode, Boolean> function1) {
        switch (WhenMappings.$EnumSwitchMapping$0[$this$forwardFocusSearch.getFocusStateImpl$ui_release().ordinal()]) {
            case 1:
                FocusTargetModifierNode focusedChild = FocusTraversalKt.getActiveChild($this$forwardFocusSearch);
                if (focusedChild != null) {
                    return forwardFocusSearch(focusedChild, function1) || m2323generateAndSearchChildren4C6V_qg($this$forwardFocusSearch, focusedChild, FocusDirection.Companion.m2307getNextdhqQ8s(), function1);
                }
                throw new IllegalStateException(NoActiveChild.toString());
            case 2:
            case 3:
                return pickChildForForwardSearch($this$forwardFocusSearch, function1);
            case 4:
                if ($this$forwardFocusSearch.fetchFocusProperties$ui_release().getCanFocus()) {
                    return function1.invoke($this$forwardFocusSearch).booleanValue();
                }
                return pickChildForForwardSearch($this$forwardFocusSearch, function1);
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    private static final boolean backwardFocusSearch(FocusTargetModifierNode $this$backwardFocusSearch, Function1<? super FocusTargetModifierNode, Boolean> function1) {
        switch (WhenMappings.$EnumSwitchMapping$0[$this$backwardFocusSearch.getFocusStateImpl$ui_release().ordinal()]) {
            case 1:
                FocusTargetModifierNode focusedChild = FocusTraversalKt.getActiveChild($this$backwardFocusSearch);
                if (focusedChild == null) {
                    throw new IllegalStateException(NoActiveChild.toString());
                }
                switch (WhenMappings.$EnumSwitchMapping$0[focusedChild.getFocusStateImpl$ui_release().ordinal()]) {
                    case 1:
                        if (backwardFocusSearch(focusedChild, function1) || m2323generateAndSearchChildren4C6V_qg($this$backwardFocusSearch, focusedChild, FocusDirection.Companion.m2309getPreviousdhqQ8s(), function1)) {
                            return true;
                        }
                        return $this$backwardFocusSearch.fetchFocusProperties$ui_release().getCanFocus() && function1.invoke(focusedChild).booleanValue();
                    case 2:
                    case 3:
                        return m2323generateAndSearchChildren4C6V_qg($this$backwardFocusSearch, focusedChild, FocusDirection.Companion.m2309getPreviousdhqQ8s(), function1);
                    case 4:
                        throw new IllegalStateException(NoActiveChild.toString());
                    default:
                        throw new NoWhenBranchMatchedException();
                }
            case 2:
            case 3:
                return pickChildForBackwardSearch($this$backwardFocusSearch, function1);
            case 4:
                if (pickChildForBackwardSearch($this$backwardFocusSearch, function1)) {
                    return true;
                }
                return $this$backwardFocusSearch.fetchFocusProperties$ui_release().getCanFocus() ? function1.invoke($this$backwardFocusSearch).booleanValue() : false;
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    /* renamed from: generateAndSearchChildren-4C6V_qg  reason: not valid java name */
    private static final boolean m2323generateAndSearchChildren4C6V_qg(final FocusTargetModifierNode $this$generateAndSearchChildren_u2d4C6V_qg, final FocusTargetModifierNode focusedItem, final int direction, final Function1<? super FocusTargetModifierNode, Boolean> function1) {
        if (m2325searchChildren4C6V_qg($this$generateAndSearchChildren_u2d4C6V_qg, focusedItem, direction, function1)) {
            return true;
        }
        Boolean bool = (Boolean) BeyondBoundsLayoutKt.m2290searchBeyondBoundsOMvw8($this$generateAndSearchChildren_u2d4C6V_qg, direction, new Function1<BeyondBoundsLayout.BeyondBoundsScope, Boolean>() { // from class: androidx.compose.ui.focus.OneDimensionalFocusSearchKt$generateAndSearchChildren$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public final Boolean invoke(BeyondBoundsLayout.BeyondBoundsScope searchBeyondBounds) {
                boolean m2325searchChildren4C6V_qg;
                Intrinsics.checkNotNullParameter(searchBeyondBounds, "$this$searchBeyondBounds");
                m2325searchChildren4C6V_qg = OneDimensionalFocusSearchKt.m2325searchChildren4C6V_qg(FocusTargetModifierNode.this, focusedItem, direction, function1);
                Boolean valueOf = Boolean.valueOf(m2325searchChildren4C6V_qg);
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
    public static final boolean m2325searchChildren4C6V_qg(FocusTargetModifierNode $this$searchChildren_u2d4C6V_qg, FocusTargetModifierNode focusedItem, int direction, Function1<? super FocusTargetModifierNode, Boolean> function1) {
        if (!($this$searchChildren_u2d4C6V_qg.getFocusStateImpl$ui_release() == FocusStateImpl.ActiveParent)) {
            throw new IllegalStateException("This function should only be used within a parent that has focus.".toString());
        }
        MutableVector $this$searchChildren_4C6V_qg_u24lambda_u242 = new MutableVector(new FocusTargetModifierNode[16], 0);
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
                MutableVector this_$iv$iv$iv = branches$iv$iv;
                Modifier.Node branch$iv$iv = (Modifier.Node) branches$iv$iv.removeAt(this_$iv$iv$iv.getSize() - 1);
                if ((branch$iv$iv.getAggregateChildKindSet$ui_release() & m4327constructorimpl) == 0) {
                    DelegatableNodeKt.addLayoutNodeChildren(branches$iv$iv, branch$iv$iv);
                } else {
                    Modifier.Node node$iv$iv = branch$iv$iv;
                    while (true) {
                        if (node$iv$iv == null) {
                            break;
                        } else if ((node$iv$iv.getKindSet$ui_release() & m4327constructorimpl) != 0) {
                            Modifier.Node it$iv = node$iv$iv;
                            MutableVector branches$iv$iv2 = branches$iv$iv;
                            if (it$iv instanceof FocusTargetModifierNode) {
                                FocusTargetModifierNode it = (FocusTargetModifierNode) it$iv;
                                $this$searchChildren_4C6V_qg_u24lambda_u242.add(it);
                            }
                            branches$iv$iv = branches$iv$iv2;
                        } else {
                            node$iv$iv = node$iv$iv.getChild$ui_release();
                        }
                    }
                }
            }
            $this$searchChildren_4C6V_qg_u24lambda_u242.sortWith(FocusableChildrenComparator.INSTANCE);
            if (!FocusDirection.m2294equalsimpl0(direction, FocusDirection.Companion.m2307getNextdhqQ8s())) {
                if (FocusDirection.m2294equalsimpl0(direction, FocusDirection.Companion.m2309getPreviousdhqQ8s())) {
                    boolean itemFound$iv = false;
                    IntRange intRange = new IntRange(0, $this$searchChildren_4C6V_qg_u24lambda_u242.getSize() - 1);
                    int first = intRange.getFirst();
                    int index$iv = intRange.getLast();
                    if (first <= index$iv) {
                        while (true) {
                            if (itemFound$iv) {
                                FocusTargetModifierNode child = (FocusTargetModifierNode) $this$searchChildren_4C6V_qg_u24lambda_u242.getContent()[index$iv];
                                if (FocusTraversalKt.isEligibleForFocusSearch(child) && backwardFocusSearch(child, function1)) {
                                    return true;
                                }
                            }
                            if (Intrinsics.areEqual($this$searchChildren_4C6V_qg_u24lambda_u242.getContent()[index$iv], focusedItem)) {
                                itemFound$iv = true;
                            }
                            if (index$iv == first) {
                                break;
                            }
                            index$iv--;
                        }
                    }
                } else {
                    throw new IllegalStateException(InvalidFocusDirection.toString());
                }
            } else {
                boolean itemFound$iv2 = false;
                IntRange intRange2 = new IntRange(0, $this$searchChildren_4C6V_qg_u24lambda_u242.getSize() - 1);
                int index$iv2 = intRange2.getFirst();
                int last = intRange2.getLast();
                if (index$iv2 <= last) {
                    while (true) {
                        if (itemFound$iv2) {
                            FocusTargetModifierNode child2 = (FocusTargetModifierNode) $this$searchChildren_4C6V_qg_u24lambda_u242.getContent()[index$iv2];
                            if (FocusTraversalKt.isEligibleForFocusSearch(child2) && forwardFocusSearch(child2, function1)) {
                                return true;
                            }
                        }
                        if (Intrinsics.areEqual($this$searchChildren_4C6V_qg_u24lambda_u242.getContent()[index$iv2], focusedItem)) {
                            itemFound$iv2 = true;
                        }
                        if (index$iv2 == last) {
                            break;
                        }
                        index$iv2++;
                    }
                }
            }
            if (FocusDirection.m2294equalsimpl0(direction, FocusDirection.Companion.m2307getNextdhqQ8s()) || !$this$searchChildren_u2d4C6V_qg.fetchFocusProperties$ui_release().getCanFocus() || isRoot($this$searchChildren_u2d4C6V_qg)) {
                return false;
            }
            return function1.invoke($this$searchChildren_u2d4C6V_qg).booleanValue();
        }
        throw new IllegalStateException("Check failed.".toString());
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x00c3  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00c1 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static final boolean pickChildForForwardSearch(androidx.compose.ui.focus.FocusTargetModifierNode r17, kotlin.jvm.functions.Function1<? super androidx.compose.ui.focus.FocusTargetModifierNode, java.lang.Boolean> r18) {
        /*
            Method dump skipped, instructions count: 218
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.OneDimensionalFocusSearchKt.pickChildForForwardSearch(androidx.compose.ui.focus.FocusTargetModifierNode, kotlin.jvm.functions.Function1):boolean");
    }

    private static final boolean pickChildForBackwardSearch(FocusTargetModifierNode $this$pickChildForBackwardSearch, Function1<? super FocusTargetModifierNode, Boolean> function1) {
        MutableVector $this$pickChildForBackwardSearch_u24lambda_u249 = new MutableVector(new FocusTargetModifierNode[16], 0);
        FocusTargetModifierNode $this$visitChildren_u2d6rFNWt0$iv = $this$pickChildForBackwardSearch;
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
                                $this$pickChildForBackwardSearch_u24lambda_u249.add((FocusTargetModifierNode) it$iv);
                            }
                        } else {
                            node$iv$iv = node$iv$iv.getChild$ui_release();
                        }
                    }
                }
            }
            $this$pickChildForBackwardSearch_u24lambda_u249.sortWith(FocusableChildrenComparator.INSTANCE);
            int size$iv = $this$pickChildForBackwardSearch_u24lambda_u249.getSize();
            if (size$iv <= 0) {
                return false;
            }
            int i$iv = size$iv - 1;
            Object[] content$iv = $this$pickChildForBackwardSearch_u24lambda_u249.getContent();
            do {
                FocusTargetModifierNode it = (FocusTargetModifierNode) content$iv[i$iv];
                if (FocusTraversalKt.isEligibleForFocusSearch(it) && backwardFocusSearch(it, function1)) {
                    return true;
                }
                i$iv--;
            } while (i$iv >= 0);
            return false;
        }
        throw new IllegalStateException("Check failed.".toString());
    }

    private static final boolean isRoot(FocusTargetModifierNode $this$isRoot) {
        FocusTargetModifierNode $this$nearestAncestor_u2d64DMado$iv = $this$isRoot;
        Modifier.Node nearestAncestor = DelegatableNodeKt.nearestAncestor($this$nearestAncestor_u2d64DMado$iv, NodeKind.m4327constructorimpl(1024));
        if (!(nearestAncestor instanceof FocusTargetModifierNode)) {
            nearestAncestor = null;
        }
        return ((FocusTargetModifierNode) nearestAncestor) == null;
    }

    private static final <T> void forEachItemAfter(MutableVector<T> mutableVector, T t, Function1<? super T, Unit> function1) {
        boolean itemFound = false;
        IntRange intRange = new IntRange(0, mutableVector.getSize() - 1);
        int index = intRange.getFirst();
        int last = intRange.getLast();
        if (index > last) {
            return;
        }
        while (true) {
            if (itemFound) {
                function1.invoke(mutableVector.getContent()[index]);
            }
            if (Intrinsics.areEqual(mutableVector.getContent()[index], t)) {
                itemFound = true;
            }
            if (index == last) {
                return;
            }
            index++;
        }
    }

    private static final <T> void forEachItemBefore(MutableVector<T> mutableVector, T t, Function1<? super T, Unit> function1) {
        boolean itemFound = false;
        IntRange intRange = new IntRange(0, mutableVector.getSize() - 1);
        int first = intRange.getFirst();
        int index = intRange.getLast();
        if (first > index) {
            return;
        }
        while (true) {
            if (itemFound) {
                function1.invoke(mutableVector.getContent()[index]);
            }
            if (Intrinsics.areEqual(mutableVector.getContent()[index], t)) {
                itemFound = true;
            }
            if (index == first) {
                return;
            }
            index--;
        }
    }
}
