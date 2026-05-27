package androidx.compose.ui.focus;

import android.view.KeyEvent;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.geometry.Rect;
import androidx.compose.ui.input.key.KeyInputModifierNode;
import androidx.compose.ui.input.rotary.RotaryInputModifierNode;
import androidx.compose.ui.input.rotary.RotaryScrollEvent;
import androidx.compose.ui.node.DelegatableNode;
import androidx.compose.ui.node.DelegatableNodeKt;
import androidx.compose.ui.node.ModifierNodeElement;
import androidx.compose.ui.node.NodeKind;
import androidx.compose.ui.platform.InspectorInfo;
import androidx.compose.ui.unit.LayoutDirection;
import androidx.core.app.NotificationCompat;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: FocusOwnerImpl.kt */
@Metadata(d1 = {"\u0000~\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0000\u0018\u00002\u00020\u0001B\u001f\u0012\u0018\u0010\u0002\u001a\u0014\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00050\u0004\u0012\u0004\u0012\u00020\u00050\u0003¢\u0006\u0002\u0010\u0006J\u0010\u0010\u001c\u001a\u00020\u00052\u0006\u0010\u001d\u001a\u00020\u001eH\u0016J\u0018\u0010\u001c\u001a\u00020\u00052\u0006\u0010\u001d\u001a\u00020\u001e2\u0006\u0010\u001f\u001a\u00020\u001eH\u0016J\u001d\u0010 \u001a\u00020\u001e2\u0006\u0010!\u001a\u00020\"H\u0016ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b#\u0010$J\u0010\u0010%\u001a\u00020\u001e2\u0006\u0010&\u001a\u00020'H\u0016J\n\u0010(\u001a\u0004\u0018\u00010)H\u0016J\u001d\u0010*\u001a\u00020\u001e2\u0006\u0010+\u001a\u00020,H\u0016ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b-\u0010.J\b\u0010/\u001a\u00020\u0005H\u0016J\u0010\u00100\u001a\u00020\u00052\u0006\u00101\u001a\u000202H\u0016J\u0010\u00100\u001a\u00020\u00052\u0006\u00101\u001a\u000203H\u0016J\u0010\u00100\u001a\u00020\u00052\u0006\u00101\u001a\u00020\u0016H\u0016J\b\u00104\u001a\u00020\u0005H\u0016J\u001d\u00105\u001a\u00020\u001e2\u0006\u0010+\u001a\u00020,H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b6\u0010.J\u000e\u00107\u001a\u0004\u0018\u000108*\u000209H\u0002J\\\u0010:\u001a\u00020\u0005\"\n\b\u0000\u0010;\u0018\u0001*\u000209*\u0002H;2\f\u0010<\u001a\b\u0012\u0004\u0012\u0002H;0=2\u0012\u0010>\u001a\u000e\u0012\u0004\u0012\u0002H;\u0012\u0004\u0012\u00020\u00050\u00032\u0012\u0010?\u001a\u000e\u0012\u0004\u0012\u0002H;\u0012\u0004\u0012\u00020\u00050\u0003H\u0083\bø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b@\u0010AR\u000e\u0010\u0007\u001a\u00020\bX\u0082\u0004¢\u0006\u0002\n\u0000R\u001a\u0010\t\u001a\u00020\nX\u0096.¢\u0006\u000e\n\u0000\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000eR\u001a\u0010\u000f\u001a\u00020\u0010X\u0096\u0004¢\u0006\u000e\n\u0000\u0012\u0004\b\u0011\u0010\u0012\u001a\u0004\b\u0013\u0010\u0014R \u0010\u0015\u001a\u00020\u0016X\u0080\u000e¢\u0006\u0014\n\u0000\u0012\u0004\b\u0017\u0010\u0012\u001a\u0004\b\u0018\u0010\u0019\"\u0004\b\u001a\u0010\u001b\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006B"}, d2 = {"Landroidx/compose/ui/focus/FocusOwnerImpl;", "Landroidx/compose/ui/focus/FocusOwner;", "onRequestApplyChangesListener", "Lkotlin/Function1;", "Lkotlin/Function0;", "", "(Lkotlin/jvm/functions/Function1;)V", "focusInvalidationManager", "Landroidx/compose/ui/focus/FocusInvalidationManager;", "layoutDirection", "Landroidx/compose/ui/unit/LayoutDirection;", "getLayoutDirection", "()Landroidx/compose/ui/unit/LayoutDirection;", "setLayoutDirection", "(Landroidx/compose/ui/unit/LayoutDirection;)V", "modifier", "Landroidx/compose/ui/Modifier;", "getModifier$annotations", "()V", "getModifier", "()Landroidx/compose/ui/Modifier;", "rootFocusNode", "Landroidx/compose/ui/focus/FocusTargetModifierNode;", "getRootFocusNode$ui_release$annotations", "getRootFocusNode$ui_release", "()Landroidx/compose/ui/focus/FocusTargetModifierNode;", "setRootFocusNode$ui_release", "(Landroidx/compose/ui/focus/FocusTargetModifierNode;)V", "clearFocus", "force", "", "refreshFocusEvents", "dispatchKeyEvent", "keyEvent", "Landroidx/compose/ui/input/key/KeyEvent;", "dispatchKeyEvent-ZmokQxo", "(Landroid/view/KeyEvent;)Z", "dispatchRotaryEvent", NotificationCompat.CATEGORY_EVENT, "Landroidx/compose/ui/input/rotary/RotaryScrollEvent;", "getFocusRect", "Landroidx/compose/ui/geometry/Rect;", "moveFocus", "focusDirection", "Landroidx/compose/ui/focus/FocusDirection;", "moveFocus-3ESFkO8", "(I)Z", "releaseFocus", "scheduleInvalidation", "node", "Landroidx/compose/ui/focus/FocusEventModifierNode;", "Landroidx/compose/ui/focus/FocusPropertiesModifierNode;", "takeFocus", "wrapAroundFocus", "wrapAroundFocus-3ESFkO8", "lastLocalKeyInputNode", "Landroidx/compose/ui/input/key/KeyInputModifierNode;", "Landroidx/compose/ui/node/DelegatableNode;", "traverseAncestors", "T", "type", "Landroidx/compose/ui/node/NodeKind;", "onPreVisit", "onVisit", "traverseAncestors-Y-YKmho", "(Landroidx/compose/ui/node/DelegatableNode;ILkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function1;)V", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class FocusOwnerImpl implements FocusOwner {
    private final FocusInvalidationManager focusInvalidationManager;
    public LayoutDirection layoutDirection;
    private final Modifier modifier;
    private FocusTargetModifierNode rootFocusNode;

    /* compiled from: FocusOwnerImpl.kt */
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

    public static /* synthetic */ void getModifier$annotations() {
    }

    public static /* synthetic */ void getRootFocusNode$ui_release$annotations() {
    }

    public FocusOwnerImpl(Function1<? super Function0<Unit>, Unit> onRequestApplyChangesListener) {
        Intrinsics.checkNotNullParameter(onRequestApplyChangesListener, "onRequestApplyChangesListener");
        this.rootFocusNode = new FocusTargetModifierNode();
        this.focusInvalidationManager = new FocusInvalidationManager(onRequestApplyChangesListener);
        this.modifier = new ModifierNodeElement<FocusTargetModifierNode>() { // from class: androidx.compose.ui.focus.FocusOwnerImpl$modifier$1
            @Override // androidx.compose.ui.node.ModifierNodeElement
            public FocusTargetModifierNode create() {
                return FocusOwnerImpl.this.getRootFocusNode$ui_release();
            }

            @Override // androidx.compose.ui.node.ModifierNodeElement
            public FocusTargetModifierNode update(FocusTargetModifierNode node) {
                Intrinsics.checkNotNullParameter(node, "node");
                return node;
            }

            @Override // androidx.compose.ui.node.ModifierNodeElement
            public void inspectableProperties(InspectorInfo $this$inspectableProperties) {
                Intrinsics.checkNotNullParameter($this$inspectableProperties, "<this>");
                $this$inspectableProperties.setName("RootFocusTarget");
            }

            @Override // androidx.compose.ui.node.ModifierNodeElement
            public int hashCode() {
                return FocusOwnerImpl.this.getRootFocusNode$ui_release().hashCode();
            }

            @Override // androidx.compose.ui.node.ModifierNodeElement
            public boolean equals(Object other) {
                return other == this;
            }
        };
    }

    public final FocusTargetModifierNode getRootFocusNode$ui_release() {
        return this.rootFocusNode;
    }

    public final void setRootFocusNode$ui_release(FocusTargetModifierNode focusTargetModifierNode) {
        Intrinsics.checkNotNullParameter(focusTargetModifierNode, "<set-?>");
        this.rootFocusNode = focusTargetModifierNode;
    }

    @Override // androidx.compose.ui.focus.FocusOwner
    public Modifier getModifier() {
        return this.modifier;
    }

    @Override // androidx.compose.ui.focus.FocusOwner
    public LayoutDirection getLayoutDirection() {
        LayoutDirection layoutDirection = this.layoutDirection;
        if (layoutDirection != null) {
            return layoutDirection;
        }
        Intrinsics.throwUninitializedPropertyAccessException("layoutDirection");
        return null;
    }

    @Override // androidx.compose.ui.focus.FocusOwner
    public void setLayoutDirection(LayoutDirection layoutDirection) {
        Intrinsics.checkNotNullParameter(layoutDirection, "<set-?>");
        this.layoutDirection = layoutDirection;
    }

    @Override // androidx.compose.ui.focus.FocusOwner
    public void takeFocus() {
        if (this.rootFocusNode.getFocusStateImpl$ui_release() == FocusStateImpl.Inactive) {
            this.rootFocusNode.setFocusStateImpl$ui_release(FocusStateImpl.Active);
        }
    }

    @Override // androidx.compose.ui.focus.FocusOwner
    public void releaseFocus() {
        FocusTransactionsKt.clearFocus(this.rootFocusNode, true, true);
    }

    @Override // androidx.compose.ui.focus.FocusManager
    public void clearFocus(boolean force) {
        clearFocus(force, true);
    }

    @Override // androidx.compose.ui.focus.FocusOwner
    public void clearFocus(boolean force, boolean refreshFocusEvents) {
        FocusStateImpl focusStateImpl;
        FocusStateImpl rootInitialState = this.rootFocusNode.getFocusStateImpl$ui_release();
        if (FocusTransactionsKt.clearFocus(this.rootFocusNode, force, refreshFocusEvents)) {
            FocusTargetModifierNode focusTargetModifierNode = this.rootFocusNode;
            switch (WhenMappings.$EnumSwitchMapping$0[rootInitialState.ordinal()]) {
                case 1:
                case 2:
                case 3:
                    focusStateImpl = FocusStateImpl.Active;
                    break;
                case 4:
                    focusStateImpl = FocusStateImpl.Inactive;
                    break;
                default:
                    throw new NoWhenBranchMatchedException();
            }
            focusTargetModifierNode.setFocusStateImpl$ui_release(focusStateImpl);
        }
    }

    @Override // androidx.compose.ui.focus.FocusManager
    /* renamed from: moveFocus-3ESFkO8 */
    public boolean mo2312moveFocus3ESFkO8(int focusDirection) {
        final FocusTargetModifierNode source = FocusTraversalKt.findActiveFocusNode(this.rootFocusNode);
        if (source == null) {
            return false;
        }
        FocusRequester next = FocusTraversalKt.m2320customFocusSearchOMvw8(source, focusDirection, getLayoutDirection());
        if (Intrinsics.areEqual(next, FocusRequester.Companion.getCancel())) {
            return false;
        }
        if (Intrinsics.areEqual(next, FocusRequester.Companion.getDefault())) {
            boolean foundNextItem = FocusTraversalKt.m2321focusSearchsMXa3k8(this.rootFocusNode, focusDirection, getLayoutDirection(), new Function1<FocusTargetModifierNode, Boolean>() { // from class: androidx.compose.ui.focus.FocusOwnerImpl$moveFocus$foundNextItem$1
                /* JADX INFO: Access modifiers changed from: package-private */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public final Boolean invoke(FocusTargetModifierNode destination) {
                    Intrinsics.checkNotNullParameter(destination, "destination");
                    if (Intrinsics.areEqual(destination, FocusTargetModifierNode.this)) {
                        return false;
                    }
                    FocusTargetModifierNode $this$nearestAncestor_u2d64DMado$iv = destination;
                    Modifier.Node nearestAncestor = DelegatableNodeKt.nearestAncestor($this$nearestAncestor_u2d64DMado$iv, NodeKind.m4327constructorimpl(1024));
                    if (!(nearestAncestor instanceof FocusTargetModifierNode)) {
                        nearestAncestor = null;
                    }
                    if (((FocusTargetModifierNode) nearestAncestor) != null) {
                        return Boolean.valueOf(FocusTransactionsKt.requestFocus(destination));
                    }
                    throw new IllegalStateException("Focus search landed at the root.".toString());
                }
            });
            return foundNextItem || m2315wrapAroundFocus3ESFkO8(focusDirection);
        }
        return next.findFocusTarget$ui_release(new Function1<FocusTargetModifierNode, Boolean>() { // from class: androidx.compose.ui.focus.FocusOwnerImpl$moveFocus$1
            @Override // kotlin.jvm.functions.Function1
            public final Boolean invoke(FocusTargetModifierNode it) {
                Intrinsics.checkNotNullParameter(it, "it");
                return Boolean.valueOf(FocusTransactionsKt.requestFocus(it));
            }
        });
    }

    @Override // androidx.compose.ui.focus.FocusOwner
    /* renamed from: dispatchKeyEvent-ZmokQxo */
    public boolean mo2313dispatchKeyEventZmokQxo(KeyEvent keyEvent) {
        Intrinsics.checkNotNullParameter(keyEvent, "keyEvent");
        DelegatableNode activeFocusTarget = FocusTraversalKt.findActiveFocusNode(this.rootFocusNode);
        if (activeFocusTarget == null) {
            throw new IllegalStateException("Event can't be processed because we do not have an active focus target.".toString());
        }
        DelegatableNode $this$nearestAncestor_u2d64DMado$iv = lastLocalKeyInputNode(activeFocusTarget);
        if ($this$nearestAncestor_u2d64DMado$iv == null) {
            DelegatableNode nearestAncestor = DelegatableNodeKt.nearestAncestor(activeFocusTarget, NodeKind.m4327constructorimpl(8192));
            if (!(nearestAncestor instanceof KeyInputModifierNode)) {
                nearestAncestor = null;
            }
            $this$nearestAncestor_u2d64DMado$iv = (KeyInputModifierNode) nearestAncestor;
        }
        if ($this$nearestAncestor_u2d64DMado$iv == null) {
            return false;
        }
        DelegatableNode $this$traverseAncestors_u2dY_u2dYKmho$iv = $this$nearestAncestor_u2d64DMado$iv;
        int type$iv = NodeKind.m4327constructorimpl(8192);
        List ancestors = DelegatableNodeKt.ancestors($this$traverseAncestors_u2dY_u2dYKmho$iv, type$iv);
        List ancestors$iv = ancestors instanceof List ? ancestors : null;
        if (ancestors$iv != null) {
            List $this$fastForEachReversed$iv$iv = ancestors$iv;
            int size = $this$fastForEachReversed$iv$iv.size() - 1;
            if (size >= 0) {
                do {
                    int index$iv$iv = size;
                    size--;
                    Object item$iv$iv = $this$fastForEachReversed$iv$iv.get(index$iv$iv);
                    KeyInputModifierNode it = (KeyInputModifierNode) item$iv$iv;
                    if (it.mo3882onPreKeyEventZmokQxo(keyEvent)) {
                        return true;
                    }
                } while (size >= 0);
            }
        }
        KeyInputModifierNode it2 = (KeyInputModifierNode) $this$traverseAncestors_u2dY_u2dYKmho$iv;
        if (it2.mo3882onPreKeyEventZmokQxo(keyEvent)) {
            return true;
        }
        KeyInputModifierNode it3 = (KeyInputModifierNode) $this$traverseAncestors_u2dY_u2dYKmho$iv;
        if (it3.mo3881onKeyEventZmokQxo(keyEvent)) {
            return true;
        }
        if (ancestors$iv == null) {
            return false;
        }
        List $this$fastForEach$iv$iv = ancestors$iv;
        int size2 = $this$fastForEach$iv$iv.size();
        for (int index$iv$iv2 = 0; index$iv$iv2 < size2; index$iv$iv2++) {
            Object item$iv$iv2 = $this$fastForEach$iv$iv.get(index$iv$iv2);
            KeyInputModifierNode it4 = (KeyInputModifierNode) item$iv$iv2;
            if (it4.mo3881onKeyEventZmokQxo(keyEvent)) {
                return true;
            }
        }
        return false;
    }

    @Override // androidx.compose.ui.focus.FocusOwner
    public boolean dispatchRotaryEvent(RotaryScrollEvent event) {
        DelegatableNode delegatableNode;
        Intrinsics.checkNotNullParameter(event, "event");
        DelegatableNode findActiveFocusNode = FocusTraversalKt.findActiveFocusNode(this.rootFocusNode);
        if (findActiveFocusNode != null) {
            DelegatableNode $this$nearestAncestor_u2d64DMado$iv = findActiveFocusNode;
            DelegatableNode nearestAncestor = DelegatableNodeKt.nearestAncestor($this$nearestAncestor_u2d64DMado$iv, NodeKind.m4327constructorimpl(16384));
            if (!(nearestAncestor instanceof RotaryInputModifierNode)) {
                nearestAncestor = null;
            }
            delegatableNode = (RotaryInputModifierNode) nearestAncestor;
        } else {
            delegatableNode = null;
        }
        DelegatableNode focusedRotaryInputNode = delegatableNode;
        if (focusedRotaryInputNode == null) {
            return false;
        }
        DelegatableNode $this$traverseAncestors_u2dY_u2dYKmho$iv = focusedRotaryInputNode;
        int type$iv = NodeKind.m4327constructorimpl(16384);
        List ancestors = DelegatableNodeKt.ancestors($this$traverseAncestors_u2dY_u2dYKmho$iv, type$iv);
        List ancestors$iv = ancestors instanceof List ? ancestors : null;
        if (ancestors$iv != null) {
            List $this$fastForEachReversed$iv$iv = ancestors$iv;
            int size = $this$fastForEachReversed$iv$iv.size() - 1;
            if (size >= 0) {
                do {
                    int index$iv$iv = size;
                    size--;
                    Object item$iv$iv = $this$fastForEachReversed$iv$iv.get(index$iv$iv);
                    RotaryInputModifierNode it = (RotaryInputModifierNode) item$iv$iv;
                    if (it.onPreRotaryScrollEvent(event)) {
                        return true;
                    }
                } while (size >= 0);
            }
        }
        RotaryInputModifierNode it2 = (RotaryInputModifierNode) $this$traverseAncestors_u2dY_u2dYKmho$iv;
        if (it2.onPreRotaryScrollEvent(event)) {
            return true;
        }
        RotaryInputModifierNode it3 = (RotaryInputModifierNode) $this$traverseAncestors_u2dY_u2dYKmho$iv;
        if (it3.onRotaryScrollEvent(event)) {
            return true;
        }
        if (ancestors$iv == null) {
            return false;
        }
        List $this$fastForEach$iv$iv = ancestors$iv;
        int size2 = $this$fastForEach$iv$iv.size();
        for (int index$iv$iv2 = 0; index$iv$iv2 < size2; index$iv$iv2++) {
            Object item$iv$iv2 = $this$fastForEach$iv$iv.get(index$iv$iv2);
            RotaryInputModifierNode it4 = (RotaryInputModifierNode) item$iv$iv2;
            if (it4.onRotaryScrollEvent(event)) {
                return true;
            }
        }
        return false;
    }

    @Override // androidx.compose.ui.focus.FocusOwner
    public void scheduleInvalidation(FocusTargetModifierNode node) {
        Intrinsics.checkNotNullParameter(node, "node");
        this.focusInvalidationManager.scheduleInvalidation(node);
    }

    @Override // androidx.compose.ui.focus.FocusOwner
    public void scheduleInvalidation(FocusEventModifierNode node) {
        Intrinsics.checkNotNullParameter(node, "node");
        this.focusInvalidationManager.scheduleInvalidation(node);
    }

    @Override // androidx.compose.ui.focus.FocusOwner
    public void scheduleInvalidation(FocusPropertiesModifierNode node) {
        Intrinsics.checkNotNullParameter(node, "node");
        this.focusInvalidationManager.scheduleInvalidation(node);
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0030  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0045 A[ORIG_RETURN, RETURN] */
    /* renamed from: traverseAncestors-Y-YKmho  reason: not valid java name */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final /* synthetic */ <T extends androidx.compose.ui.node.DelegatableNode> void m2314traverseAncestorsYYKmho(T r8, int r9, kotlin.jvm.functions.Function1<? super T, kotlin.Unit> r10, kotlin.jvm.functions.Function1<? super T, kotlin.Unit> r11) {
        /*
            r7 = this;
            r0 = 0
            r1 = r8
            r2 = 0
            java.util.List r3 = androidx.compose.ui.node.DelegatableNodeKt.ancestors(r1, r9)
            boolean r4 = r3 instanceof java.util.List
            if (r4 == 0) goto Lc
            goto Ld
        Lc:
            r3 = 0
        Ld:
            r1 = r3
            if (r1 == 0) goto L28
            r2 = r1
            r3 = 0
            int r4 = r2.size()
            int r4 = r4 + (-1)
            if (r4 < 0) goto L27
        L1b:
            r5 = r4
            int r4 = r4 + (-1)
            java.lang.Object r6 = r2.get(r5)
            r10.invoke(r6)
            if (r4 >= 0) goto L1b
        L27:
        L28:
            r10.invoke(r8)
            r11.invoke(r8)
            if (r1 == 0) goto L45
            r2 = r1
            r3 = 0
            r4 = 0
            int r5 = r2.size()
        L38:
            if (r4 >= r5) goto L44
            java.lang.Object r6 = r2.get(r4)
            r11.invoke(r6)
            int r4 = r4 + 1
            goto L38
        L44:
        L45:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.FocusOwnerImpl.m2314traverseAncestorsYYKmho(androidx.compose.ui.node.DelegatableNode, int, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1):void");
    }

    @Override // androidx.compose.ui.focus.FocusOwner
    public Rect getFocusRect() {
        FocusTargetModifierNode findActiveFocusNode = FocusTraversalKt.findActiveFocusNode(this.rootFocusNode);
        if (findActiveFocusNode != null) {
            return FocusTraversalKt.focusRect(findActiveFocusNode);
        }
        return null;
    }

    private final KeyInputModifierNode lastLocalKeyInputNode(DelegatableNode $this$lastLocalKeyInputNode) {
        KeyInputModifierNode keyInputModifierNode = null;
        int mask$iv = NodeKind.m4327constructorimpl(1024) | NodeKind.m4327constructorimpl(8192);
        if (!$this$lastLocalKeyInputNode.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        Modifier.Node self$iv = $this$lastLocalKeyInputNode.getNode();
        if ((self$iv.getAggregateChildKindSet$ui_release() & mask$iv) != 0) {
            for (Modifier.Node next$iv = self$iv.getChild$ui_release(); next$iv != null; next$iv = next$iv.getChild$ui_release()) {
                if ((next$iv.getKindSet$ui_release() & mask$iv) != 0) {
                    Modifier.Node modifierNode = next$iv;
                    if ((modifierNode.getKindSet$ui_release() & NodeKind.m4327constructorimpl(1024)) != 0) {
                        return keyInputModifierNode;
                    }
                    if (!(modifierNode instanceof KeyInputModifierNode)) {
                        throw new IllegalStateException("Check failed.".toString());
                    }
                    keyInputModifierNode = modifierNode;
                }
            }
        }
        return keyInputModifierNode;
    }

    /* renamed from: wrapAroundFocus-3ESFkO8  reason: not valid java name */
    private final boolean m2315wrapAroundFocus3ESFkO8(int focusDirection) {
        if (!this.rootFocusNode.getFocusState().getHasFocus() || this.rootFocusNode.getFocusState().isFocused()) {
            return false;
        }
        if (FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2307getNextdhqQ8s()) ? true : FocusDirection.m2294equalsimpl0(focusDirection, FocusDirection.Companion.m2309getPreviousdhqQ8s())) {
            clearFocus(false);
            if (this.rootFocusNode.getFocusState().isFocused()) {
                return mo2312moveFocus3ESFkO8(focusDirection);
            }
            return false;
        }
        return false;
    }
}
