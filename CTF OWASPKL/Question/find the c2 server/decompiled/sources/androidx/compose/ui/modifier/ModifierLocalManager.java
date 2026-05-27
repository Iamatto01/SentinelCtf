package androidx.compose.ui.modifier;

import androidx.compose.runtime.collection.MutableVector;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.node.BackwardsCompatNode;
import androidx.compose.ui.node.DelegatableNode;
import androidx.compose.ui.node.DelegatableNodeKt;
import androidx.compose.ui.node.LayoutNode;
import androidx.compose.ui.node.NodeKind;
import androidx.compose.ui.node.Owner;
import java.util.Set;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: ModifierLocalManager.kt */
@Metadata(d1 = {"\u0000H\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010#\n\u0002\b\u0004\b\u0000\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u001a\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00072\n\u0010\u0014\u001a\u0006\u0012\u0002\b\u00030\tJ\u0006\u0010\u0015\u001a\u00020\u0012J*\u0010\u0016\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00172\n\u0010\u0014\u001a\u0006\u0012\u0002\b\u00030\t2\f\u0010\u0018\u001a\b\u0012\u0004\u0012\u00020\u00070\u0019H\u0002J\u001a\u0010\u001a\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00072\n\u0010\u0014\u001a\u0006\u0012\u0002\b\u00030\tJ\u0006\u0010\u001b\u001a\u00020\u0012J\u001a\u0010\u001c\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00072\n\u0010\u0014\u001a\u0006\u0012\u0002\b\u00030\tR\u0014\u0010\u0005\u001a\b\u0012\u0004\u0012\u00020\u00070\u0006X\u0082\u0004¢\u0006\u0002\n\u0000R\u0018\u0010\b\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\t0\u0006X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u000bX\u0082\u000e¢\u0006\u0002\n\u0000R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\f\u0010\rR\u0014\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\u000f0\u0006X\u0082\u0004¢\u0006\u0002\n\u0000R\u0018\u0010\u0010\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\t0\u0006X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u001d"}, d2 = {"Landroidx/compose/ui/modifier/ModifierLocalManager;", "", "owner", "Landroidx/compose/ui/node/Owner;", "(Landroidx/compose/ui/node/Owner;)V", "inserted", "Landroidx/compose/runtime/collection/MutableVector;", "Landroidx/compose/ui/node/BackwardsCompatNode;", "insertedLocal", "Landroidx/compose/ui/modifier/ModifierLocal;", "invalidated", "", "getOwner", "()Landroidx/compose/ui/node/Owner;", "removed", "Landroidx/compose/ui/node/LayoutNode;", "removedLocal", "insertedProvider", "", "node", "key", "invalidate", "invalidateConsumersOfNodeForKey", "Landroidx/compose/ui/Modifier$Node;", "set", "", "removedProvider", "triggerUpdates", "updatedProvider", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ModifierLocalManager {
    private final MutableVector<BackwardsCompatNode> inserted;
    private final MutableVector<ModifierLocal<?>> insertedLocal;
    private boolean invalidated;
    private final Owner owner;
    private final MutableVector<LayoutNode> removed;
    private final MutableVector<ModifierLocal<?>> removedLocal;

    public ModifierLocalManager(Owner owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        this.owner = owner;
        this.inserted = new MutableVector<>(new BackwardsCompatNode[16], 0);
        this.insertedLocal = new MutableVector<>(new ModifierLocal[16], 0);
        this.removed = new MutableVector<>(new LayoutNode[16], 0);
        this.removedLocal = new MutableVector<>(new ModifierLocal[16], 0);
    }

    public final Owner getOwner() {
        return this.owner;
    }

    public final void invalidate() {
        if (!this.invalidated) {
            this.invalidated = true;
            this.owner.registerOnEndApplyChangesListener(new Function0<Unit>() { // from class: androidx.compose.ui.modifier.ModifierLocalManager$invalidate$1
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
                    ModifierLocalManager.this.triggerUpdates();
                }
            });
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x005f  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x008b  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x00a3 A[LOOP:2: B:21:0x009d->B:23:0x00a3, LOOP_END] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void triggerUpdates() {
        /*
            r12 = this;
            r0 = 0
            r12.invalidated = r0
            java.util.HashSet r0 = new java.util.HashSet
            r0.<init>()
            androidx.compose.runtime.collection.MutableVector<androidx.compose.ui.node.LayoutNode> r1 = r12.removed
            r2 = 0
            int r3 = r1.getSize()
            if (r3 <= 0) goto L4a
            r4 = 0
            java.lang.Object[] r5 = r1.getContent()
        L17:
            r6 = r5[r4]
            androidx.compose.ui.node.LayoutNode r6 = (androidx.compose.ui.node.LayoutNode) r6
            r7 = r4
            r8 = 0
            androidx.compose.runtime.collection.MutableVector<androidx.compose.ui.modifier.ModifierLocal<?>> r9 = r12.removedLocal
            r10 = 0
            java.lang.Object[] r11 = r9.getContent()
            r9 = r11[r7]
            androidx.compose.ui.modifier.ModifierLocal r9 = (androidx.compose.ui.modifier.ModifierLocal) r9
            androidx.compose.ui.node.NodeChain r10 = r6.getNodes$ui_release()
            androidx.compose.ui.Modifier$Node r10 = r10.getHead$ui_release()
            boolean r10 = r10.isAttached()
            if (r10 == 0) goto L44
            androidx.compose.ui.node.NodeChain r10 = r6.getNodes$ui_release()
            androidx.compose.ui.Modifier$Node r10 = r10.getHead$ui_release()
            r11 = r0
            java.util.Set r11 = (java.util.Set) r11
            r12.invalidateConsumersOfNodeForKey(r10, r9, r11)
        L44:
            int r4 = r4 + 1
            if (r4 < r3) goto L17
        L4a:
        L4b:
            androidx.compose.runtime.collection.MutableVector<androidx.compose.ui.node.LayoutNode> r1 = r12.removed
            r1.clear()
            androidx.compose.runtime.collection.MutableVector<androidx.compose.ui.modifier.ModifierLocal<?>> r1 = r12.removedLocal
            r1.clear()
            androidx.compose.runtime.collection.MutableVector<androidx.compose.ui.node.BackwardsCompatNode> r1 = r12.inserted
            r2 = 0
            int r3 = r1.getSize()
            if (r3 <= 0) goto L8a
            r4 = 0
            java.lang.Object[] r5 = r1.getContent()
        L64:
            r6 = r5[r4]
            androidx.compose.ui.node.BackwardsCompatNode r6 = (androidx.compose.ui.node.BackwardsCompatNode) r6
            r7 = r4
            r8 = 0
            androidx.compose.runtime.collection.MutableVector<androidx.compose.ui.modifier.ModifierLocal<?>> r9 = r12.insertedLocal
            r10 = 0
            java.lang.Object[] r11 = r9.getContent()
            r9 = r11[r7]
            androidx.compose.ui.modifier.ModifierLocal r9 = (androidx.compose.ui.modifier.ModifierLocal) r9
            boolean r10 = r6.isAttached()
            if (r10 == 0) goto L84
            r10 = r6
            androidx.compose.ui.Modifier$Node r10 = (androidx.compose.ui.Modifier.Node) r10
            r11 = r0
            java.util.Set r11 = (java.util.Set) r11
            r12.invalidateConsumersOfNodeForKey(r10, r9, r11)
        L84:
            int r4 = r4 + 1
            if (r4 < r3) goto L64
        L8a:
        L8b:
            androidx.compose.runtime.collection.MutableVector<androidx.compose.ui.node.BackwardsCompatNode> r1 = r12.inserted
            r1.clear()
            androidx.compose.runtime.collection.MutableVector<androidx.compose.ui.modifier.ModifierLocal<?>> r1 = r12.insertedLocal
            r1.clear()
            r1 = r0
            java.lang.Iterable r1 = (java.lang.Iterable) r1
            r2 = 0
            java.util.Iterator r3 = r1.iterator()
        L9d:
            boolean r4 = r3.hasNext()
            if (r4 == 0) goto Lb0
            java.lang.Object r4 = r3.next()
            r5 = r4
            androidx.compose.ui.node.BackwardsCompatNode r5 = (androidx.compose.ui.node.BackwardsCompatNode) r5
            r6 = 0
            r5.updateModifierLocalConsumer()
            goto L9d
        Lb0:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.modifier.ModifierLocalManager.triggerUpdates():void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final void invalidateConsumersOfNodeForKey(Modifier.Node node, ModifierLocal<?> modifierLocal, Set<BackwardsCompatNode> set) {
        DelegatableNode $this$visitSubtreeIf_u2d6rFNWt0$iv;
        boolean z;
        boolean diveDeeper$iv$iv;
        Modifier.Node $this$visitSubtreeIf_u2d6rFNWt0$iv2 = node;
        int m4327constructorimpl = NodeKind.m4327constructorimpl(32);
        if (!$this$visitSubtreeIf_u2d6rFNWt0$iv2.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        MutableVector branches$iv$iv = new MutableVector(new Modifier.Node[16], 0);
        Modifier.Node child$iv$iv = $this$visitSubtreeIf_u2d6rFNWt0$iv2.getNode().getChild$ui_release();
        if (child$iv$iv == null) {
            DelegatableNodeKt.addLayoutNodeChildren(branches$iv$iv, $this$visitSubtreeIf_u2d6rFNWt0$iv2.getNode());
        } else {
            branches$iv$iv.add(child$iv$iv);
        }
        while (branches$iv$iv.isNotEmpty()) {
            int size = branches$iv$iv.getSize();
            boolean z2 = true;
            Modifier.Node branch$iv$iv = (Modifier.Node) branches$iv$iv.removeAt(size - 1);
            if ((branch$iv$iv.getAggregateChildKindSet$ui_release() & m4327constructorimpl) != 0) {
                Modifier.Node node$iv$iv = branch$iv$iv;
                while (node$iv$iv != null) {
                    if ((node$iv$iv.getKindSet$ui_release() & m4327constructorimpl) == 0) {
                        $this$visitSubtreeIf_u2d6rFNWt0$iv = $this$visitSubtreeIf_u2d6rFNWt0$iv2;
                        z = z2;
                    } else {
                        Modifier.Node it$iv = node$iv$iv;
                        if (it$iv instanceof ModifierLocalNode) {
                            ModifierLocalNode it = (ModifierLocalNode) it$iv;
                            if ((it instanceof BackwardsCompatNode) && (((BackwardsCompatNode) it).getElement() instanceof ModifierLocalConsumer)) {
                                if (((BackwardsCompatNode) it).getReadValues().contains(modifierLocal)) {
                                    set.add(it);
                                }
                            }
                            $this$visitSubtreeIf_u2d6rFNWt0$iv = $this$visitSubtreeIf_u2d6rFNWt0$iv2;
                            z = true;
                            diveDeeper$iv$iv = !it.getProvidedValues().contains$ui_release(modifierLocal);
                        } else {
                            $this$visitSubtreeIf_u2d6rFNWt0$iv = $this$visitSubtreeIf_u2d6rFNWt0$iv2;
                            z = z2;
                            diveDeeper$iv$iv = z;
                        }
                        if (!diveDeeper$iv$iv) {
                            $this$visitSubtreeIf_u2d6rFNWt0$iv2 = $this$visitSubtreeIf_u2d6rFNWt0$iv;
                            break;
                        }
                    }
                    node$iv$iv = node$iv$iv.getChild$ui_release();
                    z2 = z;
                    $this$visitSubtreeIf_u2d6rFNWt0$iv2 = $this$visitSubtreeIf_u2d6rFNWt0$iv;
                }
            }
            DelegatableNodeKt.addLayoutNodeChildren(branches$iv$iv, branch$iv$iv);
            $this$visitSubtreeIf_u2d6rFNWt0$iv2 = $this$visitSubtreeIf_u2d6rFNWt0$iv2;
        }
    }

    public final void updatedProvider(BackwardsCompatNode node, ModifierLocal<?> key) {
        Intrinsics.checkNotNullParameter(node, "node");
        Intrinsics.checkNotNullParameter(key, "key");
        MutableVector this_$iv = this.inserted;
        this_$iv.add(node);
        MutableVector this_$iv2 = this.insertedLocal;
        this_$iv2.add(key);
        invalidate();
    }

    public final void insertedProvider(BackwardsCompatNode node, ModifierLocal<?> key) {
        Intrinsics.checkNotNullParameter(node, "node");
        Intrinsics.checkNotNullParameter(key, "key");
        MutableVector this_$iv = this.inserted;
        this_$iv.add(node);
        MutableVector this_$iv2 = this.insertedLocal;
        this_$iv2.add(key);
        invalidate();
    }

    public final void removedProvider(BackwardsCompatNode node, ModifierLocal<?> key) {
        Intrinsics.checkNotNullParameter(node, "node");
        Intrinsics.checkNotNullParameter(key, "key");
        MutableVector this_$iv = this.removed;
        this_$iv.add(DelegatableNodeKt.requireLayoutNode(node));
        MutableVector this_$iv2 = this.removedLocal;
        this_$iv2.add(key);
        invalidate();
    }
}
