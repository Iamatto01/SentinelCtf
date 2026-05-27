package androidx.compose.ui.focus;

import androidx.compose.ui.Modifier;
import androidx.compose.ui.node.DelegatableNodeKt;
import androidx.compose.ui.node.LayoutNode;
import androidx.compose.ui.node.NodeCoordinator;
import androidx.compose.ui.node.NodeKind;
import androidx.compose.ui.node.ObserverNodeKt;
import androidx.compose.ui.node.Owner;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: FocusTransactions.kt */
@Metadata(d1 = {"\u0000\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u000b\u001a\f\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0001\u001a \u0010\u0003\u001a\u00020\u0001*\u00020\u00022\b\b\u0002\u0010\u0004\u001a\u00020\u00012\b\b\u0002\u0010\u0005\u001a\u00020\u0001H\u0003\u001a\u001e\u0010\u0006\u001a\u00020\u0001*\u00020\u00022\b\b\u0002\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0001H\u0001\u001a\f\u0010\u0007\u001a\u00020\u0001*\u00020\u0002H\u0001\u001a\f\u0010\b\u001a\u00020\u0001*\u00020\u0002H\u0002\u001a\f\u0010\t\u001a\u00020\u0001*\u00020\u0002H\u0001\u001a\u0014\u0010\n\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u000b\u001a\u00020\u0002H\u0002\u001a\f\u0010\f\u001a\u00020\u0001*\u00020\u0002H\u0002¨\u0006\r"}, d2 = {"captureFocus", "", "Landroidx/compose/ui/focus/FocusTargetModifierNode;", "clearChildFocus", "forced", "refreshFocusEvents", "clearFocus", "freeFocus", "grantFocus", "requestFocus", "requestFocusForChild", "childNode", "requestFocusForOwner", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class FocusTransactionsKt {

    /* compiled from: FocusTransactions.kt */
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
                iArr[FocusStateImpl.Captured.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                iArr[FocusStateImpl.ActiveParent.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                iArr[FocusStateImpl.Inactive.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            $EnumSwitchMapping$0 = iArr;
        }
    }

    public static final boolean requestFocus(FocusTargetModifierNode $this$requestFocus) {
        Intrinsics.checkNotNullParameter($this$requestFocus, "<this>");
        if (!$this$requestFocus.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        FocusProperties focusProperties = $this$requestFocus.fetchFocusProperties$ui_release();
        if (!focusProperties.getCanFocus()) {
            return TwoDimensionalFocusSearchKt.m2329findChildCorrespondingToFocusEnterOMvw8($this$requestFocus, FocusDirection.Companion.m2303getEnterdhqQ8s(), new Function1<FocusTargetModifierNode, Boolean>() { // from class: androidx.compose.ui.focus.FocusTransactionsKt$requestFocus$1
                @Override // kotlin.jvm.functions.Function1
                public final Boolean invoke(FocusTargetModifierNode it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                    return Boolean.valueOf(FocusTransactionsKt.requestFocus(it));
                }
            });
        }
        boolean z = true;
        switch (WhenMappings.$EnumSwitchMapping$0[$this$requestFocus.getFocusStateImpl$ui_release().ordinal()]) {
            case 1:
            case 2:
                FocusEventModifierNodeKt.refreshFocusEventNodes($this$requestFocus);
                return true;
            case 3:
                if (!clearChildFocus$default($this$requestFocus, false, false, 3, null) || !grantFocus($this$requestFocus)) {
                    z = false;
                }
                boolean success = z;
                if (success) {
                    FocusEventModifierNodeKt.refreshFocusEventNodes($this$requestFocus);
                }
                return z;
            case 4:
                FocusTargetModifierNode $this$nearestAncestor_u2d64DMado$iv = $this$requestFocus;
                Modifier.Node nearestAncestor = DelegatableNodeKt.nearestAncestor($this$nearestAncestor_u2d64DMado$iv, NodeKind.m4327constructorimpl(1024));
                FocusTargetModifierNode focusTargetModifierNode = nearestAncestor instanceof FocusTargetModifierNode ? nearestAncestor : null;
                if (focusTargetModifierNode != null) {
                    return requestFocusForChild(focusTargetModifierNode, $this$requestFocus);
                }
                if (!requestFocusForOwner($this$requestFocus) || !grantFocus($this$requestFocus)) {
                    z = false;
                }
                boolean success2 = z;
                if (success2) {
                    FocusEventModifierNodeKt.refreshFocusEventNodes($this$requestFocus);
                }
                boolean success3 = z;
                return success3;
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    public static final boolean captureFocus(FocusTargetModifierNode $this$captureFocus) {
        Intrinsics.checkNotNullParameter($this$captureFocus, "<this>");
        switch (WhenMappings.$EnumSwitchMapping$0[$this$captureFocus.getFocusStateImpl$ui_release().ordinal()]) {
            case 1:
                $this$captureFocus.setFocusStateImpl$ui_release(FocusStateImpl.Captured);
                FocusEventModifierNodeKt.refreshFocusEventNodes($this$captureFocus);
                return true;
            case 2:
                return true;
            case 3:
            case 4:
                return false;
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    public static final boolean freeFocus(FocusTargetModifierNode $this$freeFocus) {
        Intrinsics.checkNotNullParameter($this$freeFocus, "<this>");
        switch (WhenMappings.$EnumSwitchMapping$0[$this$freeFocus.getFocusStateImpl$ui_release().ordinal()]) {
            case 1:
                return true;
            case 2:
                $this$freeFocus.setFocusStateImpl$ui_release(FocusStateImpl.Active);
                FocusEventModifierNodeKt.refreshFocusEventNodes($this$freeFocus);
                return true;
            case 3:
            case 4:
                return false;
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    public static /* synthetic */ boolean clearFocus$default(FocusTargetModifierNode focusTargetModifierNode, boolean z, boolean z2, int i, Object obj) {
        if ((i & 1) != 0) {
            z = false;
        }
        return clearFocus(focusTargetModifierNode, z, z2);
    }

    public static final boolean clearFocus(FocusTargetModifierNode $this$clearFocus, boolean forced, boolean refreshFocusEvents) {
        Intrinsics.checkNotNullParameter($this$clearFocus, "<this>");
        switch (WhenMappings.$EnumSwitchMapping$0[$this$clearFocus.getFocusStateImpl$ui_release().ordinal()]) {
            case 1:
                $this$clearFocus.setFocusStateImpl$ui_release(FocusStateImpl.Inactive);
                if (refreshFocusEvents) {
                    FocusEventModifierNodeKt.refreshFocusEventNodes($this$clearFocus);
                    return true;
                }
                return true;
            case 2:
                if (forced) {
                    $this$clearFocus.setFocusStateImpl$ui_release(FocusStateImpl.Inactive);
                    if (refreshFocusEvents) {
                        FocusEventModifierNodeKt.refreshFocusEventNodes($this$clearFocus);
                    }
                }
                return forced;
            case 3:
                if (clearChildFocus($this$clearFocus, forced, refreshFocusEvents)) {
                    $this$clearFocus.setFocusStateImpl$ui_release(FocusStateImpl.Inactive);
                    if (refreshFocusEvents) {
                        FocusEventModifierNodeKt.refreshFocusEventNodes($this$clearFocus);
                        return true;
                    }
                    return true;
                }
                return false;
            case 4:
                return true;
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    private static final boolean grantFocus(final FocusTargetModifierNode $this$grantFocus) {
        ObserverNodeKt.observeReads($this$grantFocus, new Function0<Unit>() { // from class: androidx.compose.ui.focus.FocusTransactionsKt$grantFocus$1
            /* JADX INFO: Access modifiers changed from: package-private */
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke  reason: avoid collision after fix types in other method */
            public final void invoke2() {
                FocusTargetModifierNode.this.fetchFocusProperties$ui_release();
            }
        });
        switch (WhenMappings.$EnumSwitchMapping$0[$this$grantFocus.getFocusStateImpl$ui_release().ordinal()]) {
            case 3:
            case 4:
                $this$grantFocus.setFocusStateImpl$ui_release(FocusStateImpl.Active);
                return true;
            default:
                return true;
        }
    }

    static /* synthetic */ boolean clearChildFocus$default(FocusTargetModifierNode focusTargetModifierNode, boolean z, boolean z2, int i, Object obj) {
        if ((i & 1) != 0) {
            z = false;
        }
        if ((i & 2) != 0) {
            z2 = true;
        }
        return clearChildFocus(focusTargetModifierNode, z, z2);
    }

    private static final boolean clearChildFocus(FocusTargetModifierNode $this$clearChildFocus, boolean forced, boolean refreshFocusEvents) {
        FocusTargetModifierNode activeChild = FocusTraversalKt.getActiveChild($this$clearChildFocus);
        if (activeChild != null) {
            return clearFocus(activeChild, forced, refreshFocusEvents);
        }
        return true;
    }

    private static final boolean requestFocusForChild(FocusTargetModifierNode $this$requestFocusForChild, FocusTargetModifierNode childNode) {
        FocusTargetModifierNode $this$nearestAncestor_u2d64DMado$iv = childNode;
        Modifier.Node nearestAncestor = DelegatableNodeKt.nearestAncestor($this$nearestAncestor_u2d64DMado$iv, NodeKind.m4327constructorimpl(1024));
        if (!(nearestAncestor instanceof FocusTargetModifierNode)) {
            nearestAncestor = null;
        }
        if (!Intrinsics.areEqual((FocusTargetModifierNode) nearestAncestor, $this$requestFocusForChild)) {
            throw new IllegalStateException("Non child node cannot request focus.".toString());
        }
        switch (WhenMappings.$EnumSwitchMapping$0[$this$requestFocusForChild.getFocusStateImpl$ui_release().ordinal()]) {
            case 1:
                boolean success = grantFocus(childNode);
                if (!success) {
                    return success;
                }
                $this$requestFocusForChild.setFocusStateImpl$ui_release(FocusStateImpl.ActiveParent);
                FocusEventModifierNodeKt.refreshFocusEventNodes(childNode);
                FocusEventModifierNodeKt.refreshFocusEventNodes($this$requestFocusForChild);
                return success;
            case 2:
                return false;
            case 3:
                if (FocusTraversalKt.getActiveChild($this$requestFocusForChild) == null) {
                    throw new IllegalStateException("Required value was null.".toString());
                }
                if (!clearChildFocus$default($this$requestFocusForChild, false, false, 3, null) || !grantFocus(childNode)) {
                    success = false;
                }
                if (success) {
                    FocusEventModifierNodeKt.refreshFocusEventNodes(childNode);
                }
                return success;
            case 4:
                FocusTargetModifierNode $this$nearestAncestor_u2d64DMado$iv2 = $this$requestFocusForChild;
                int type$iv = NodeKind.m4327constructorimpl(1024);
                Modifier.Node nearestAncestor2 = DelegatableNodeKt.nearestAncestor($this$nearestAncestor_u2d64DMado$iv2, type$iv);
                FocusTargetModifierNode focusParent = nearestAncestor2 instanceof FocusTargetModifierNode ? nearestAncestor2 : null;
                if (focusParent == null && requestFocusForOwner($this$requestFocusForChild)) {
                    $this$requestFocusForChild.setFocusStateImpl$ui_release(FocusStateImpl.Active);
                    FocusEventModifierNodeKt.refreshFocusEventNodes($this$requestFocusForChild);
                    return requestFocusForChild($this$requestFocusForChild, childNode);
                } else if (focusParent == null || !requestFocusForChild(focusParent, $this$requestFocusForChild)) {
                    return false;
                } else {
                    boolean requestFocusForChild = requestFocusForChild($this$requestFocusForChild, childNode);
                    if ($this$requestFocusForChild.getFocusState() == FocusStateImpl.ActiveParent) {
                        return requestFocusForChild;
                    }
                    throw new IllegalStateException("Check failed.".toString());
                }
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    private static final boolean requestFocusForOwner(FocusTargetModifierNode $this$requestFocusForOwner) {
        LayoutNode layoutNode;
        Owner owner$ui_release;
        NodeCoordinator coordinator$ui_release = $this$requestFocusForOwner.getCoordinator$ui_release();
        if (coordinator$ui_release == null || (layoutNode = coordinator$ui_release.getLayoutNode()) == null || (owner$ui_release = layoutNode.getOwner$ui_release()) == null) {
            throw new IllegalStateException("Owner not initialized.".toString());
        }
        return owner$ui_release.requestFocus();
    }
}
