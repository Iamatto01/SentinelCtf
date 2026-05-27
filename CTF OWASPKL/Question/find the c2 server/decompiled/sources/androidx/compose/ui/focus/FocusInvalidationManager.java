package androidx.compose.ui.focus;

import androidx.compose.runtime.collection.MutableVector;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.node.DelegatableNode;
import androidx.compose.ui.node.DelegatableNodeKt;
import androidx.compose.ui.node.NodeKind;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: FocusInvalidationManager.kt */
@Metadata(d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010#\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\b\u0000\u0018\u00002\u00020\u0001B\u001f\u0012\u0018\u0010\u0002\u001a\u0014\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00050\u0004\u0012\u0004\u0012\u00020\u00050\u0003¢\u0006\u0002\u0010\u0006J\u000e\u0010\u000f\u001a\u00020\u00052\u0006\u0010\u0010\u001a\u00020\tJ\u000e\u0010\u000f\u001a\u00020\u00052\u0006\u0010\u0010\u001a\u00020\u000bJ\u000e\u0010\u000f\u001a\u00020\u00052\u0006\u0010\u0010\u001a\u00020\rJ%\u0010\u000f\u001a\u00020\u0005\"\u0004\b\u0000\u0010\u0011*\b\u0012\u0004\u0012\u0002H\u00110\b2\u0006\u0010\u0010\u001a\u0002H\u0011H\u0002¢\u0006\u0002\u0010\u0012R\u0014\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\t0\bX\u0082\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\n\u001a\b\u0012\u0004\u0012\u00020\u000b0\bX\u0082\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\f\u001a\b\u0012\u0004\u0012\u00020\r0\bX\u0082\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\u00050\u0004X\u0082\u0004¢\u0006\u0002\n\u0000R \u0010\u0002\u001a\u0014\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00050\u0004\u0012\u0004\u0012\u00020\u00050\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0013"}, d2 = {"Landroidx/compose/ui/focus/FocusInvalidationManager;", "", "onRequestApplyChangesListener", "Lkotlin/Function1;", "Lkotlin/Function0;", "", "(Lkotlin/jvm/functions/Function1;)V", "focusEventNodes", "", "Landroidx/compose/ui/focus/FocusEventModifierNode;", "focusPropertiesNodes", "Landroidx/compose/ui/focus/FocusPropertiesModifierNode;", "focusTargetNodes", "Landroidx/compose/ui/focus/FocusTargetModifierNode;", "invalidateNodes", "scheduleInvalidation", "node", "T", "(Ljava/util/Set;Ljava/lang/Object;)V", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class FocusInvalidationManager {
    private Set<FocusEventModifierNode> focusEventNodes;
    private Set<FocusPropertiesModifierNode> focusPropertiesNodes;
    private Set<FocusTargetModifierNode> focusTargetNodes;
    private final Function0<Unit> invalidateNodes;
    private final Function1<Function0<Unit>, Unit> onRequestApplyChangesListener;

    /* JADX WARN: Multi-variable type inference failed */
    public FocusInvalidationManager(Function1<? super Function0<Unit>, Unit> onRequestApplyChangesListener) {
        Intrinsics.checkNotNullParameter(onRequestApplyChangesListener, "onRequestApplyChangesListener");
        this.onRequestApplyChangesListener = onRequestApplyChangesListener;
        this.focusTargetNodes = new LinkedHashSet();
        this.focusEventNodes = new LinkedHashSet();
        this.focusPropertiesNodes = new LinkedHashSet();
        this.invalidateNodes = new Function0<Unit>() { // from class: androidx.compose.ui.focus.FocusInvalidationManager$invalidateNodes$1
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
                Iterable iterable;
                Set set;
                Iterable iterable2;
                Set set2;
                Iterable $this$forEach$iv;
                Set set3;
                Set set4;
                Set set5;
                Set set6;
                Iterable $this$forEach$iv2;
                boolean z;
                Iterator it;
                FocusStateImpl focusStateImpl;
                Modifier.Node child$iv$iv;
                Set set7;
                Modifier.Node child$iv$iv2;
                Set set8;
                iterable = FocusInvalidationManager.this.focusPropertiesNodes;
                Iterable $this$forEach$iv3 = iterable;
                FocusInvalidationManager focusInvalidationManager = FocusInvalidationManager.this;
                boolean z2 = false;
                Iterator it2 = $this$forEach$iv3.iterator();
                while (true) {
                    int i = 1024;
                    if (!it2.hasNext()) {
                        set = FocusInvalidationManager.this.focusPropertiesNodes;
                        set.clear();
                        Set focusTargetsWithInvalidatedFocusEvents = new LinkedHashSet();
                        iterable2 = FocusInvalidationManager.this.focusEventNodes;
                        Iterable iterable3 = iterable2;
                        FocusInvalidationManager focusInvalidationManager2 = FocusInvalidationManager.this;
                        boolean z3 = false;
                        Iterator it3 = iterable3.iterator();
                        while (it3.hasNext()) {
                            Object element$iv = it3.next();
                            FocusEventModifierNode focusEventNode = (FocusEventModifierNode) element$iv;
                            if (!focusEventNode.getNode().isAttached()) {
                                $this$forEach$iv2 = iterable3;
                                z = z3;
                                it = it3;
                            } else {
                                boolean requiresUpdate = true;
                                boolean aggregatedNode = false;
                                FocusTargetModifierNode focusTargetModifierNode = null;
                                FocusEventModifierNode $this$visitChildren_u2d6rFNWt0$iv = focusEventNode;
                                int m4327constructorimpl = NodeKind.m4327constructorimpl(i);
                                if (!$this$visitChildren_u2d6rFNWt0$iv.getNode().isAttached()) {
                                    throw new IllegalStateException("Check failed.".toString());
                                }
                                $this$forEach$iv2 = iterable3;
                                z = z3;
                                it = it3;
                                MutableVector branches$iv$iv = new MutableVector(new Modifier.Node[16], 0);
                                Modifier.Node child$iv$iv3 = $this$visitChildren_u2d6rFNWt0$iv.getNode().getChild$ui_release();
                                if (child$iv$iv3 == null) {
                                    DelegatableNodeKt.addLayoutNodeChildren(branches$iv$iv, $this$visitChildren_u2d6rFNWt0$iv.getNode());
                                } else {
                                    branches$iv$iv.add(child$iv$iv3);
                                }
                                while (branches$iv$iv.isNotEmpty()) {
                                    MutableVector this_$iv$iv$iv = branches$iv$iv;
                                    Modifier.Node branch$iv$iv = (Modifier.Node) branches$iv$iv.removeAt(this_$iv$iv$iv.getSize() - 1);
                                    if ((branch$iv$iv.getAggregateChildKindSet$ui_release() & m4327constructorimpl) == 0) {
                                        DelegatableNodeKt.addLayoutNodeChildren(branches$iv$iv, branch$iv$iv);
                                    } else {
                                        for (Modifier.Node node$iv$iv = branch$iv$iv; node$iv$iv != null; node$iv$iv = node$iv$iv.getChild$ui_release()) {
                                            if ((node$iv$iv.getKindSet$ui_release() & m4327constructorimpl) != 0) {
                                                Modifier.Node it$iv = node$iv$iv;
                                                MutableVector branches$iv$iv2 = branches$iv$iv;
                                                if (it$iv instanceof FocusTargetModifierNode) {
                                                    FocusTargetModifierNode it4 = (FocusTargetModifierNode) it$iv;
                                                    if (focusTargetModifierNode != null) {
                                                        aggregatedNode = true;
                                                    }
                                                    focusTargetModifierNode = it4;
                                                    child$iv$iv = child$iv$iv3;
                                                    set7 = focusInvalidationManager2.focusTargetNodes;
                                                    if (set7.contains(it4)) {
                                                        requiresUpdate = false;
                                                        focusTargetsWithInvalidatedFocusEvents.add(it4);
                                                    }
                                                } else {
                                                    child$iv$iv = child$iv$iv3;
                                                }
                                                branches$iv$iv = branches$iv$iv2;
                                                child$iv$iv3 = child$iv$iv;
                                            }
                                        }
                                    }
                                    branches$iv$iv = branches$iv$iv;
                                    child$iv$iv3 = child$iv$iv3;
                                }
                                if (requiresUpdate) {
                                    if (aggregatedNode) {
                                        focusStateImpl = FocusEventModifierNodeKt.getFocusState(focusEventNode);
                                    } else if (focusTargetModifierNode == null || (focusStateImpl = focusTargetModifierNode.getFocusState()) == null) {
                                        focusStateImpl = FocusStateImpl.Inactive;
                                    }
                                    focusEventNode.onFocusEvent(focusStateImpl);
                                }
                            }
                            iterable3 = $this$forEach$iv2;
                            z3 = z;
                            it3 = it;
                            i = 1024;
                        }
                        set2 = FocusInvalidationManager.this.focusEventNodes;
                        set2.clear();
                        $this$forEach$iv = FocusInvalidationManager.this.focusTargetNodes;
                        for (Object element$iv2 : $this$forEach$iv) {
                            FocusTargetModifierNode it5 = (FocusTargetModifierNode) element$iv2;
                            if (it5.isAttached()) {
                                FocusState preInvalidationState = it5.getFocusState();
                                it5.invalidateFocus$ui_release();
                                if (!Intrinsics.areEqual(preInvalidationState, it5.getFocusState()) || focusTargetsWithInvalidatedFocusEvents.contains(it5)) {
                                    FocusEventModifierNodeKt.refreshFocusEventNodes(it5);
                                }
                            }
                        }
                        set3 = FocusInvalidationManager.this.focusTargetNodes;
                        set3.clear();
                        focusTargetsWithInvalidatedFocusEvents.clear();
                        set4 = FocusInvalidationManager.this.focusPropertiesNodes;
                        if (set4.isEmpty()) {
                            set5 = FocusInvalidationManager.this.focusEventNodes;
                            if (set5.isEmpty()) {
                                set6 = FocusInvalidationManager.this.focusTargetNodes;
                                if (!set6.isEmpty()) {
                                    throw new IllegalStateException("Check failed.".toString());
                                }
                                return;
                            }
                            throw new IllegalStateException("Check failed.".toString());
                        }
                        throw new IllegalStateException("Check failed.".toString());
                    }
                    Object element$iv3 = it2.next();
                    DelegatableNode $this$visitChildren_u2d6rFNWt0$iv2 = (FocusPropertiesModifierNode) element$iv3;
                    int type$iv = NodeKind.m4327constructorimpl(1024);
                    if (!$this$visitChildren_u2d6rFNWt0$iv2.getNode().isAttached()) {
                        throw new IllegalStateException("Check failed.".toString());
                    }
                    Iterable $this$forEach$iv4 = $this$forEach$iv3;
                    boolean z4 = z2;
                    Iterator it6 = it2;
                    MutableVector branches$iv$iv3 = new MutableVector(new Modifier.Node[16], 0);
                    Modifier.Node child$iv$iv4 = $this$visitChildren_u2d6rFNWt0$iv2.getNode().getChild$ui_release();
                    if (child$iv$iv4 == null) {
                        DelegatableNodeKt.addLayoutNodeChildren(branches$iv$iv3, $this$visitChildren_u2d6rFNWt0$iv2.getNode());
                    } else {
                        branches$iv$iv3.add(child$iv$iv4);
                    }
                    while (branches$iv$iv3.isNotEmpty()) {
                        MutableVector this_$iv$iv$iv2 = branches$iv$iv3;
                        Modifier.Node branch$iv$iv2 = (Modifier.Node) branches$iv$iv3.removeAt(this_$iv$iv$iv2.getSize() - 1);
                        if ((branch$iv$iv2.getAggregateChildKindSet$ui_release() & type$iv) == 0) {
                            DelegatableNodeKt.addLayoutNodeChildren(branches$iv$iv3, branch$iv$iv2);
                        } else {
                            Modifier.Node node$iv$iv2 = branch$iv$iv2;
                            while (true) {
                                if (node$iv$iv2 == null) {
                                    break;
                                } else if ((node$iv$iv2.getKindSet$ui_release() & type$iv) != 0) {
                                    Modifier.Node it$iv2 = node$iv$iv2;
                                    MutableVector branches$iv$iv4 = branches$iv$iv3;
                                    if (it$iv2 instanceof FocusTargetModifierNode) {
                                        FocusTargetModifierNode focusTarget = (FocusTargetModifierNode) it$iv2;
                                        child$iv$iv2 = child$iv$iv4;
                                        set8 = focusInvalidationManager.focusTargetNodes;
                                        set8.add(focusTarget);
                                    } else {
                                        child$iv$iv2 = child$iv$iv4;
                                    }
                                    branches$iv$iv3 = branches$iv$iv4;
                                    child$iv$iv4 = child$iv$iv2;
                                } else {
                                    node$iv$iv2 = node$iv$iv2.getChild$ui_release();
                                }
                            }
                        }
                    }
                    $this$forEach$iv3 = $this$forEach$iv4;
                    z2 = z4;
                    it2 = it6;
                }
            }
        };
    }

    public final void scheduleInvalidation(FocusTargetModifierNode node) {
        Intrinsics.checkNotNullParameter(node, "node");
        scheduleInvalidation(this.focusTargetNodes, node);
    }

    public final void scheduleInvalidation(FocusEventModifierNode node) {
        Intrinsics.checkNotNullParameter(node, "node");
        scheduleInvalidation(this.focusEventNodes, node);
    }

    public final void scheduleInvalidation(FocusPropertiesModifierNode node) {
        Intrinsics.checkNotNullParameter(node, "node");
        scheduleInvalidation(this.focusPropertiesNodes, node);
    }

    private final <T> void scheduleInvalidation(Set<T> set, T t) {
        if (set.contains(t)) {
            return;
        }
        set.add(t);
        if (this.focusTargetNodes.size() + this.focusEventNodes.size() + this.focusPropertiesNodes.size() == 1) {
            this.onRequestApplyChangesListener.invoke(this.invalidateNodes);
        }
    }
}
