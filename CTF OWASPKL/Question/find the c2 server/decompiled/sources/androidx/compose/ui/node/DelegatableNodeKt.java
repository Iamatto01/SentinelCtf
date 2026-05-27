package androidx.compose.ui.node;

import androidx.compose.runtime.collection.MutableVector;
import androidx.compose.ui.Modifier;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: DelegatableNode.kt */
@Metadata(d1 = {"\u0000Z\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\r\u001a\u001a\u0010\u0000\u001a\u00020\u0001*\b\u0012\u0004\u0012\u00020\u00030\u00022\u0006\u0010\u0004\u001a\u00020\u0003H\u0002\u001a8\u0010\u0005\u001a\n\u0012\u0004\u0012\u0002H\u0007\u0018\u00010\u0006\"\u0006\b\u0000\u0010\u0007\u0018\u0001*\u00020\b2\f\u0010\t\u001a\b\u0012\u0004\u0012\u0002H\u00070\nH\u0081\bø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u000b\u0010\f\u001a\u001c\u0010\u0005\u001a\n\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u0006*\u00020\b2\u0006\u0010\r\u001a\u00020\u000eH\u0001\u001a6\u0010\u000f\u001a\u0004\u0018\u0001H\u0007\"\n\b\u0000\u0010\u0007\u0018\u0001*\u00020\u0010*\u00020\b2\f\u0010\t\u001a\b\u0012\u0004\u0012\u0002H\u00070\nH\u0081\bø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0011\u0010\u0012\u001a\u0016\u0010\u000f\u001a\u0004\u0018\u00010\u0003*\u00020\b2\u0006\u0010\r\u001a\u00020\u000eH\u0001\u001a%\u0010\u0013\u001a\u00020\u0014*\u00020\b2\n\u0010\t\u001a\u0006\u0012\u0002\b\u00030\nH\u0001ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0015\u0010\u0016\u001a\f\u0010\u0017\u001a\u00020\u0001*\u00020\bH\u0007\u001a2\u0010\u0018\u001a\u0004\u0018\u0001H\u0007\"\u0006\b\u0000\u0010\u0007\u0018\u0001*\u00020\b2\f\u0010\t\u001a\b\u0012\u0004\u0012\u0002H\u00070\nH\u0081\bø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0019\u0010\u0012\u001a\u0016\u0010\u0018\u001a\u0004\u0018\u00010\u0003*\u00020\b2\u0006\u0010\r\u001a\u00020\u000eH\u0001\u001a2\u0010\u001a\u001a\u0004\u0018\u0001H\u0007\"\u0006\b\u0000\u0010\u0007\u0018\u0001*\u00020\b2\f\u0010\t\u001a\b\u0012\u0004\u0012\u0002H\u00070\nH\u0081\bø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001b\u0010\u0012\u001a\u0016\u0010\u001a\u001a\u0004\u0018\u00010\u0003*\u00020\b2\u0006\u0010\r\u001a\u00020\u000eH\u0001\u001a6\u0010\u001c\u001a\u0004\u0018\u0001H\u0007\"\n\b\u0000\u0010\u0007\u0018\u0001*\u00020\u0010*\u00020\b2\f\u0010\t\u001a\b\u0012\u0004\u0012\u0002H\u00070\nH\u0081\bø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001d\u0010\u0012\u001a\u0016\u0010\u001c\u001a\u0004\u0018\u00010\u0003*\u00020\b2\u0006\u0010\r\u001a\u00020\u000eH\u0001\u001a%\u0010\u001e\u001a\u00020\u001f*\u00020\b2\n\u0010 \u001a\u0006\u0012\u0002\b\u00030\nH\u0001ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b!\u0010\"\u001a\f\u0010#\u001a\u00020$*\u00020\bH\u0001\u001a\f\u0010%\u001a\u00020&*\u00020\bH\u0001\u001aG\u0010'\u001a\u00020\u0001\"\u0006\b\u0000\u0010\u0007\u0018\u0001*\u00020\b2\f\u0010\t\u001a\b\u0012\u0004\u0012\u0002H\u00070\n2\u0012\u0010(\u001a\u000e\u0012\u0004\u0012\u0002H\u0007\u0012\u0004\u0012\u00020\u00010)H\u0081\bø\u0001\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b*\u0010+\u001a,\u0010'\u001a\u00020\u0001*\u00020\b2\u0006\u0010\r\u001a\u00020\u000e2\u0012\u0010(\u001a\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00010)H\u0081\bø\u0001\u0002\u001aG\u0010,\u001a\u00020\u0001\"\u0006\b\u0000\u0010\u0007\u0018\u0001*\u00020\b2\f\u0010\t\u001a\b\u0012\u0004\u0012\u0002H\u00070\n2\u0012\u0010(\u001a\u000e\u0012\u0004\u0012\u0002H\u0007\u0012\u0004\u0012\u00020\u00010)H\u0081\bø\u0001\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b-\u0010+\u001a,\u0010,\u001a\u00020\u0001*\u00020\b2\u0006\u0010\r\u001a\u00020\u000e2\u0012\u0010(\u001a\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00010)H\u0081\bø\u0001\u0002\u001aG\u0010.\u001a\u00020\u0001\"\u0006\b\u0000\u0010\u0007\u0018\u0001*\u00020\b2\f\u0010\t\u001a\b\u0012\u0004\u0012\u0002H\u00070\n2\u0012\u0010(\u001a\u000e\u0012\u0004\u0012\u0002H\u0007\u0012\u0004\u0012\u00020\u00010)H\u0081\bø\u0001\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b/\u0010+\u001a,\u0010.\u001a\u00020\u0001*\u00020\b2\u0006\u0010\r\u001a\u00020\u000e2\u0012\u0010(\u001a\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00010)H\u0081\bø\u0001\u0002\u001aG\u00100\u001a\u00020\u0001\"\u0006\b\u0000\u0010\u0007\u0018\u0001*\u00020\b2\f\u0010\t\u001a\b\u0012\u0004\u0012\u0002H\u00070\n2\u0012\u0010(\u001a\u000e\u0012\u0004\u0012\u0002H\u0007\u0012\u0004\u0012\u00020\u00010)H\u0081\bø\u0001\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b1\u0010+\u001a,\u00100\u001a\u00020\u0001*\u00020\b2\u0006\u0010\r\u001a\u00020\u000e2\u0012\u0010(\u001a\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00010)H\u0081\bø\u0001\u0002\u001aG\u00102\u001a\u00020\u0001\"\u0006\b\u0000\u0010\u0007\u0018\u0001*\u00020\b2\f\u0010\t\u001a\b\u0012\u0004\u0012\u0002H\u00070\n2\u0012\u0010(\u001a\u000e\u0012\u0004\u0012\u0002H\u0007\u0012\u0004\u0012\u00020\u00010)H\u0081\bø\u0001\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b3\u0010+\u001a,\u00102\u001a\u00020\u0001*\u00020\b2\u0006\u0010\r\u001a\u00020\u000e2\u0012\u0010(\u001a\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00010)H\u0081\bø\u0001\u0002\u001aG\u00104\u001a\u00020\u0001\"\u0006\b\u0000\u0010\u0007\u0018\u0001*\u00020\b2\f\u0010\t\u001a\b\u0012\u0004\u0012\u0002H\u00070\n2\u0012\u0010(\u001a\u000e\u0012\u0004\u0012\u0002H\u0007\u0012\u0004\u0012\u00020\u00140)H\u0081\bø\u0001\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b5\u0010+\u001a,\u00104\u001a\u00020\u0001*\u00020\b2\u0006\u0010\r\u001a\u00020\u000e2\u0012\u0010(\u001a\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00140)H\u0081\bø\u0001\u0002\u0082\u0002\u0012\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019\n\u0005\b\u009920\u0001¨\u00066"}, d2 = {"addLayoutNodeChildren", "", "Landroidx/compose/runtime/collection/MutableVector;", "Landroidx/compose/ui/Modifier$Node;", "node", "ancestors", "", "T", "Landroidx/compose/ui/node/DelegatableNode;", "type", "Landroidx/compose/ui/node/NodeKind;", "ancestors-64DMado", "(Landroidx/compose/ui/node/DelegatableNode;I)Ljava/util/List;", "mask", "", "firstChild", "", "firstChild-64DMado", "(Landroidx/compose/ui/node/DelegatableNode;I)Ljava/lang/Object;", "has", "", "has-64DMado", "(Landroidx/compose/ui/node/DelegatableNode;I)Z", "invalidateSubtree", "localChild", "localChild-64DMado", "localParent", "localParent-64DMado", "nearestAncestor", "nearestAncestor-64DMado", "requireCoordinator", "Landroidx/compose/ui/node/NodeCoordinator;", "kind", "requireCoordinator-64DMado", "(Landroidx/compose/ui/node/DelegatableNode;I)Landroidx/compose/ui/node/NodeCoordinator;", "requireLayoutNode", "Landroidx/compose/ui/node/LayoutNode;", "requireOwner", "Landroidx/compose/ui/node/Owner;", "visitAncestors", "block", "Lkotlin/Function1;", "visitAncestors-6rFNWt0", "(Landroidx/compose/ui/node/DelegatableNode;ILkotlin/jvm/functions/Function1;)V", "visitChildren", "visitChildren-6rFNWt0", "visitLocalChildren", "visitLocalChildren-6rFNWt0", "visitLocalParents", "visitLocalParents-6rFNWt0", "visitSubtree", "visitSubtree-6rFNWt0", "visitSubtreeIf", "visitSubtreeIf-6rFNWt0", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class DelegatableNodeKt {
    public static final Modifier.Node localChild(DelegatableNode $this$localChild, int mask) {
        Intrinsics.checkNotNullParameter($this$localChild, "<this>");
        Modifier.Node child = $this$localChild.getNode().getChild$ui_release();
        if (child == null || (child.getAggregateChildKindSet$ui_release() & mask) == 0) {
            return null;
        }
        for (Modifier.Node next = child; next != null; next = next.getChild$ui_release()) {
            if ((next.getKindSet$ui_release() & mask) != 0) {
                return next;
            }
        }
        return null;
    }

    public static final Modifier.Node localParent(DelegatableNode $this$localParent, int mask) {
        Intrinsics.checkNotNullParameter($this$localParent, "<this>");
        for (Modifier.Node next = $this$localParent.getNode().getParent$ui_release(); next != null; next = next.getParent$ui_release()) {
            if ((next.getKindSet$ui_release() & mask) != 0) {
                return next;
            }
        }
        return null;
    }

    public static final void visitAncestors(DelegatableNode $this$visitAncestors, int mask, Function1<? super Modifier.Node, Unit> block) {
        NodeChain nodes$ui_release;
        Intrinsics.checkNotNullParameter($this$visitAncestors, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        if (!$this$visitAncestors.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        Modifier.Node node = $this$visitAncestors.getNode().getParent$ui_release();
        LayoutNode layout = requireLayoutNode($this$visitAncestors);
        while (layout != null) {
            Modifier.Node head = layout.getNodes$ui_release().getHead$ui_release();
            if ((head.getAggregateChildKindSet$ui_release() & mask) != 0) {
                while (node != null) {
                    if ((node.getKindSet$ui_release() & mask) != 0) {
                        block.invoke(node);
                    }
                    node = node.getParent$ui_release();
                }
            }
            layout = layout.getParent$ui_release();
            node = (layout == null || (nodes$ui_release = layout.getNodes$ui_release()) == null) ? null : nodes$ui_release.getTail$ui_release();
        }
    }

    public static final List<Modifier.Node> ancestors(DelegatableNode $this$ancestors, int mask) {
        NodeChain nodes$ui_release;
        Intrinsics.checkNotNullParameter($this$ancestors, "<this>");
        if (!$this$ancestors.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        List ancestors = null;
        Modifier.Node node = $this$ancestors.getNode().getParent$ui_release();
        LayoutNode layout = requireLayoutNode($this$ancestors);
        while (layout != null) {
            Modifier.Node head = layout.getNodes$ui_release().getHead$ui_release();
            if ((head.getAggregateChildKindSet$ui_release() & mask) != 0) {
                while (node != null) {
                    if ((node.getKindSet$ui_release() & mask) != 0) {
                        if (ancestors == null) {
                            List ancestors2 = new ArrayList();
                            ancestors = ancestors2;
                        }
                        ancestors.add(node);
                    }
                    node = node.getParent$ui_release();
                }
            }
            layout = layout.getParent$ui_release();
            node = (layout == null || (nodes$ui_release = layout.getNodes$ui_release()) == null) ? null : nodes$ui_release.getTail$ui_release();
        }
        return ancestors;
    }

    public static final Modifier.Node nearestAncestor(DelegatableNode $this$nearestAncestor, int mask) {
        NodeChain nodes$ui_release;
        Intrinsics.checkNotNullParameter($this$nearestAncestor, "<this>");
        if (!$this$nearestAncestor.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        Modifier.Node node = $this$nearestAncestor.getNode().getParent$ui_release();
        LayoutNode layout = requireLayoutNode($this$nearestAncestor);
        while (true) {
            Modifier.Node node2 = null;
            if (layout == null) {
                return null;
            }
            Modifier.Node head = layout.getNodes$ui_release().getHead$ui_release();
            if ((head.getAggregateChildKindSet$ui_release() & mask) != 0) {
                while (node != null) {
                    if ((node.getKindSet$ui_release() & mask) != 0) {
                        return node;
                    }
                    node = node.getParent$ui_release();
                }
            }
            layout = layout.getParent$ui_release();
            if (layout != null && (nodes$ui_release = layout.getNodes$ui_release()) != null) {
                node2 = nodes$ui_release.getTail$ui_release();
            }
            node = node2;
        }
    }

    public static final Modifier.Node firstChild(DelegatableNode $this$firstChild, int mask) {
        Intrinsics.checkNotNullParameter($this$firstChild, "<this>");
        if (!$this$firstChild.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        MutableVector branches = new MutableVector(new Modifier.Node[16], 0);
        Modifier.Node child = $this$firstChild.getNode().getChild$ui_release();
        if (child == null) {
            addLayoutNodeChildren(branches, $this$firstChild.getNode());
        } else {
            branches.add(child);
        }
        while (branches.isNotEmpty()) {
            Modifier.Node branch = (Modifier.Node) branches.removeAt(branches.getSize() - 1);
            if ((branch.getAggregateChildKindSet$ui_release() & mask) == 0) {
                addLayoutNodeChildren(branches, branch);
            } else {
                for (Modifier.Node node = branch; node != null; node = node.getChild$ui_release()) {
                    if ((node.getKindSet$ui_release() & mask) != 0) {
                        return node;
                    }
                }
                continue;
            }
        }
        return null;
    }

    public static final void visitSubtree(DelegatableNode $this$visitSubtree, int mask, Function1<? super Modifier.Node, Unit> block) {
        Intrinsics.checkNotNullParameter($this$visitSubtree, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        if (!$this$visitSubtree.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        Modifier.Node node = $this$visitSubtree.getNode().getChild$ui_release();
        NestedVectorStack nodes = new NestedVectorStack();
        for (LayoutNode layout = requireLayoutNode($this$visitSubtree); layout != null; layout = nodes.isNotEmpty() ? (LayoutNode) nodes.pop() : null) {
            node = node == null ? layout.getNodes$ui_release().getHead$ui_release() : node;
            if ((node.getAggregateChildKindSet$ui_release() & mask) != 0) {
                while (node != null) {
                    if ((node.getKindSet$ui_release() & mask) != 0) {
                        block.invoke(node);
                    }
                    node = node.getChild$ui_release();
                }
                node = null;
            }
            nodes.push(layout.get_children$ui_release());
        }
    }

    public static final void addLayoutNodeChildren(MutableVector<Modifier.Node> mutableVector, Modifier.Node node) {
        MutableVector this_$iv = requireLayoutNode(node).get_children$ui_release();
        int size$iv = this_$iv.getSize();
        if (size$iv <= 0) {
            return;
        }
        int i$iv = size$iv - 1;
        Object[] content$iv = this_$iv.getContent();
        do {
            LayoutNode it = (LayoutNode) content$iv[i$iv];
            mutableVector.add(it.getNodes$ui_release().getHead$ui_release());
            i$iv--;
        } while (i$iv >= 0);
    }

    public static final void visitChildren(DelegatableNode $this$visitChildren, int mask, Function1<? super Modifier.Node, Unit> block) {
        Intrinsics.checkNotNullParameter($this$visitChildren, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        if (!$this$visitChildren.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        MutableVector branches = new MutableVector(new Modifier.Node[16], 0);
        Modifier.Node child = $this$visitChildren.getNode().getChild$ui_release();
        if (child == null) {
            addLayoutNodeChildren(branches, $this$visitChildren.getNode());
        } else {
            branches.add(child);
        }
        while (branches.isNotEmpty()) {
            Modifier.Node branch = (Modifier.Node) branches.removeAt(branches.getSize() - 1);
            if ((branch.getAggregateChildKindSet$ui_release() & mask) == 0) {
                addLayoutNodeChildren(branches, branch);
            } else {
                Modifier.Node node = branch;
                while (true) {
                    if (node == null) {
                        break;
                    } else if ((node.getKindSet$ui_release() & mask) != 0) {
                        block.invoke(node);
                        break;
                    } else {
                        node = node.getChild$ui_release();
                    }
                }
            }
        }
    }

    public static final void visitSubtreeIf(DelegatableNode $this$visitSubtreeIf, int mask, Function1<? super Modifier.Node, Boolean> block) {
        Intrinsics.checkNotNullParameter($this$visitSubtreeIf, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        if (!$this$visitSubtreeIf.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        MutableVector branches = new MutableVector(new Modifier.Node[16], 0);
        Modifier.Node child = $this$visitSubtreeIf.getNode().getChild$ui_release();
        if (child == null) {
            addLayoutNodeChildren(branches, $this$visitSubtreeIf.getNode());
        } else {
            branches.add(child);
        }
        while (branches.isNotEmpty()) {
            Modifier.Node branch = (Modifier.Node) branches.removeAt(branches.getSize() - 1);
            if ((branch.getAggregateChildKindSet$ui_release() & mask) != 0) {
                for (Modifier.Node node = branch; node != null; node = node.getChild$ui_release()) {
                    if ((node.getKindSet$ui_release() & mask) != 0) {
                        boolean diveDeeper = block.invoke(node).booleanValue();
                        if (diveDeeper) {
                        }
                    }
                }
            }
            addLayoutNodeChildren(branches, branch);
        }
    }

    public static final void visitLocalChildren(DelegatableNode $this$visitLocalChildren, int mask, Function1<? super Modifier.Node, Unit> block) {
        Intrinsics.checkNotNullParameter($this$visitLocalChildren, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        if (!$this$visitLocalChildren.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        Modifier.Node self = $this$visitLocalChildren.getNode();
        if ((self.getAggregateChildKindSet$ui_release() & mask) == 0) {
            return;
        }
        for (Modifier.Node next = self.getChild$ui_release(); next != null; next = next.getChild$ui_release()) {
            if ((next.getKindSet$ui_release() & mask) != 0) {
                block.invoke(next);
            }
        }
    }

    public static final void visitLocalParents(DelegatableNode $this$visitLocalParents, int mask, Function1<? super Modifier.Node, Unit> block) {
        Intrinsics.checkNotNullParameter($this$visitLocalParents, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        if (!$this$visitLocalParents.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        for (Modifier.Node next = $this$visitLocalParents.getNode().getParent$ui_release(); next != null; next = next.getParent$ui_release()) {
            if ((next.getKindSet$ui_release() & mask) != 0) {
                block.invoke(next);
            }
        }
    }

    /* renamed from: visitLocalChildren-6rFNWt0 */
    public static final /* synthetic */ <T> void m4234visitLocalChildren6rFNWt0(DelegatableNode visitLocalChildren, int type, Function1<? super T, Unit> block) {
        Intrinsics.checkNotNullParameter(visitLocalChildren, "$this$visitLocalChildren");
        Intrinsics.checkNotNullParameter(block, "block");
        if (!visitLocalChildren.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        Modifier.Node self$iv = visitLocalChildren.getNode();
        if ((self$iv.getAggregateChildKindSet$ui_release() & type) == 0) {
            return;
        }
        for (Modifier.Node next$iv = self$iv.getChild$ui_release(); next$iv != null; next$iv = next$iv.getChild$ui_release()) {
            if ((next$iv.getKindSet$ui_release() & type) != 0) {
                Modifier.Node it = next$iv;
                Intrinsics.reifiedOperationMarker(3, "T");
                if (it instanceof Object) {
                    block.invoke(it);
                }
            }
        }
    }

    /* renamed from: visitLocalParents-6rFNWt0 */
    public static final /* synthetic */ <T> void m4235visitLocalParents6rFNWt0(DelegatableNode visitLocalParents, int type, Function1<? super T, Unit> block) {
        Intrinsics.checkNotNullParameter(visitLocalParents, "$this$visitLocalParents");
        Intrinsics.checkNotNullParameter(block, "block");
        if (!visitLocalParents.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        for (Modifier.Node next$iv = visitLocalParents.getNode().getParent$ui_release(); next$iv != null; next$iv = next$iv.getParent$ui_release()) {
            if ((next$iv.getKindSet$ui_release() & type) != 0) {
                Modifier.Node it = next$iv;
                Intrinsics.reifiedOperationMarker(3, "T");
                if (it instanceof Object) {
                    block.invoke(it);
                }
            }
        }
    }

    /* renamed from: localParent-64DMado */
    public static final /* synthetic */ <T> T m4229localParent64DMado(DelegatableNode localParent, int type) {
        Intrinsics.checkNotNullParameter(localParent, "$this$localParent");
        Modifier.Node localParent2 = localParent(localParent, type);
        Intrinsics.reifiedOperationMarker(2, "T");
        return (T) localParent2;
    }

    /* renamed from: localChild-64DMado */
    public static final /* synthetic */ <T> T m4228localChild64DMado(DelegatableNode localChild, int type) {
        Intrinsics.checkNotNullParameter(localChild, "$this$localChild");
        Modifier.Node localChild2 = localChild(localChild, type);
        Intrinsics.reifiedOperationMarker(2, "T");
        return (T) localChild2;
    }

    /* renamed from: visitAncestors-6rFNWt0 */
    public static final /* synthetic */ <T> void m4232visitAncestors6rFNWt0(DelegatableNode visitAncestors, int type, Function1<? super T, Unit> block) {
        NodeChain nodes$ui_release;
        Intrinsics.checkNotNullParameter(visitAncestors, "$this$visitAncestors");
        Intrinsics.checkNotNullParameter(block, "block");
        if (!visitAncestors.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        Modifier.Node node$iv = visitAncestors.getNode().getParent$ui_release();
        LayoutNode layout$iv = requireLayoutNode(visitAncestors);
        while (layout$iv != null) {
            Modifier.Node head$iv = layout$iv.getNodes$ui_release().getHead$ui_release();
            if ((head$iv.getAggregateChildKindSet$ui_release() & type) != 0) {
                while (node$iv != null) {
                    if ((node$iv.getKindSet$ui_release() & type) != 0) {
                        Modifier.Node it = node$iv;
                        Intrinsics.reifiedOperationMarker(3, "T");
                        if (it instanceof Object) {
                            block.invoke(it);
                        }
                    }
                    node$iv = node$iv.getParent$ui_release();
                }
            }
            layout$iv = layout$iv.getParent$ui_release();
            node$iv = (layout$iv == null || (nodes$ui_release = layout$iv.getNodes$ui_release()) == null) ? null : nodes$ui_release.getTail$ui_release();
        }
    }

    /* renamed from: ancestors-64DMado */
    public static final /* synthetic */ <T> List<T> m4225ancestors64DMado(DelegatableNode ancestors, int type) {
        Intrinsics.checkNotNullParameter(ancestors, "$this$ancestors");
        List<T> list = (List<T>) ancestors(ancestors, type);
        if (list instanceof List) {
            return list;
        }
        return null;
    }

    /* renamed from: nearestAncestor-64DMado */
    public static final /* synthetic */ <T> T m4230nearestAncestor64DMado(DelegatableNode nearestAncestor, int type) {
        Intrinsics.checkNotNullParameter(nearestAncestor, "$this$nearestAncestor");
        Modifier.Node nearestAncestor2 = nearestAncestor(nearestAncestor, type);
        Intrinsics.reifiedOperationMarker(2, "T");
        return (T) nearestAncestor2;
    }

    /* renamed from: firstChild-64DMado */
    public static final /* synthetic */ <T> T m4226firstChild64DMado(DelegatableNode firstChild, int type) {
        Intrinsics.checkNotNullParameter(firstChild, "$this$firstChild");
        Modifier.Node firstChild2 = firstChild(firstChild, type);
        Intrinsics.reifiedOperationMarker(2, "T");
        return (T) firstChild2;
    }

    /* renamed from: visitSubtree-6rFNWt0 */
    public static final /* synthetic */ <T> void m4236visitSubtree6rFNWt0(DelegatableNode visitSubtree, int type, Function1<? super T, Unit> block) {
        Intrinsics.checkNotNullParameter(visitSubtree, "$this$visitSubtree");
        Intrinsics.checkNotNullParameter(block, "block");
        if (!visitSubtree.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        Modifier.Node node$iv = visitSubtree.getNode().getChild$ui_release();
        NestedVectorStack nodes$iv = new NestedVectorStack();
        for (LayoutNode layout$iv = requireLayoutNode(visitSubtree); layout$iv != null; layout$iv = nodes$iv.isNotEmpty() ? (LayoutNode) nodes$iv.pop() : null) {
            node$iv = node$iv == null ? layout$iv.getNodes$ui_release().getHead$ui_release() : node$iv;
            if ((node$iv.getAggregateChildKindSet$ui_release() & type) != 0) {
                while (node$iv != null) {
                    if ((node$iv.getKindSet$ui_release() & type) != 0) {
                        Modifier.Node it = node$iv;
                        Intrinsics.reifiedOperationMarker(3, "T");
                        if (it instanceof Object) {
                            block.invoke(it);
                        }
                    }
                    node$iv = node$iv.getChild$ui_release();
                }
                node$iv = null;
            }
            nodes$iv.push(layout$iv.get_children$ui_release());
        }
    }

    /* renamed from: visitChildren-6rFNWt0 */
    public static final /* synthetic */ <T> void m4233visitChildren6rFNWt0(DelegatableNode visitChildren, int type, Function1<? super T, Unit> block) {
        Intrinsics.checkNotNullParameter(visitChildren, "$this$visitChildren");
        Intrinsics.checkNotNullParameter(block, "block");
        if (!visitChildren.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        MutableVector branches$iv = new MutableVector(new Modifier.Node[16], 0);
        Modifier.Node child$iv = visitChildren.getNode().getChild$ui_release();
        if (child$iv == null) {
            addLayoutNodeChildren(branches$iv, visitChildren.getNode());
        } else {
            branches$iv.add(child$iv);
        }
        while (branches$iv.isNotEmpty()) {
            Modifier.Node branch$iv = (Modifier.Node) branches$iv.removeAt(branches$iv.getSize() - 1);
            if ((branch$iv.getAggregateChildKindSet$ui_release() & type) == 0) {
                addLayoutNodeChildren(branches$iv, branch$iv);
            } else {
                Modifier.Node node$iv = branch$iv;
                while (true) {
                    if (node$iv == null) {
                        break;
                    } else if ((node$iv.getKindSet$ui_release() & type) != 0) {
                        Modifier.Node it = node$iv;
                        Intrinsics.reifiedOperationMarker(3, "T");
                        if (it instanceof Object) {
                            block.invoke(it);
                        }
                    } else {
                        node$iv = node$iv.getChild$ui_release();
                    }
                }
            }
        }
    }

    /* renamed from: visitSubtreeIf-6rFNWt0 */
    public static final /* synthetic */ <T> void m4237visitSubtreeIf6rFNWt0(DelegatableNode visitSubtreeIf, int type, Function1<? super T, Boolean> block) {
        Intrinsics.checkNotNullParameter(visitSubtreeIf, "$this$visitSubtreeIf");
        Intrinsics.checkNotNullParameter(block, "block");
        if (!visitSubtreeIf.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        MutableVector branches$iv = new MutableVector(new Modifier.Node[16], 0);
        Modifier.Node child$iv = visitSubtreeIf.getNode().getChild$ui_release();
        if (child$iv == null) {
            addLayoutNodeChildren(branches$iv, visitSubtreeIf.getNode());
        } else {
            branches$iv.add(child$iv);
        }
        while (branches$iv.isNotEmpty()) {
            Modifier.Node branch$iv = (Modifier.Node) branches$iv.removeAt(branches$iv.getSize() - 1);
            if ((branch$iv.getAggregateChildKindSet$ui_release() & type) != 0) {
                for (Modifier.Node node$iv = branch$iv; node$iv != null; node$iv = node$iv.getChild$ui_release()) {
                    if ((node$iv.getKindSet$ui_release() & type) != 0) {
                        Modifier.Node it = node$iv;
                        Intrinsics.reifiedOperationMarker(3, "T");
                        boolean diveDeeper$iv = it instanceof Object ? block.invoke(it).booleanValue() : true;
                        if (diveDeeper$iv) {
                        }
                    }
                }
            }
            addLayoutNodeChildren(branches$iv, branch$iv);
        }
    }

    /* renamed from: has-64DMado */
    public static final boolean m4227has64DMado(DelegatableNode has, int type) {
        Intrinsics.checkNotNullParameter(has, "$this$has");
        return (has.getNode().getAggregateChildKindSet$ui_release() & type) != 0;
    }

    /* renamed from: requireCoordinator-64DMado */
    public static final NodeCoordinator m4231requireCoordinator64DMado(DelegatableNode requireCoordinator, int kind) {
        Intrinsics.checkNotNullParameter(requireCoordinator, "$this$requireCoordinator");
        NodeCoordinator coordinator = requireCoordinator.getNode().getCoordinator$ui_release();
        Intrinsics.checkNotNull(coordinator);
        if (coordinator.getTail() != requireCoordinator || !NodeKindKt.m4335getIncludeSelfInTraversalH91voCI(kind)) {
            return coordinator;
        }
        NodeCoordinator wrapped$ui_release = coordinator.getWrapped$ui_release();
        Intrinsics.checkNotNull(wrapped$ui_release);
        return wrapped$ui_release;
    }

    public static final LayoutNode requireLayoutNode(DelegatableNode $this$requireLayoutNode) {
        Intrinsics.checkNotNullParameter($this$requireLayoutNode, "<this>");
        NodeCoordinator coordinator$ui_release = $this$requireLayoutNode.getNode().getCoordinator$ui_release();
        if (coordinator$ui_release != null) {
            return coordinator$ui_release.getLayoutNode();
        }
        throw new IllegalStateException("Required value was null.".toString());
    }

    public static final Owner requireOwner(DelegatableNode $this$requireOwner) {
        Intrinsics.checkNotNullParameter($this$requireOwner, "<this>");
        Owner owner$ui_release = requireLayoutNode($this$requireOwner).getOwner$ui_release();
        if (owner$ui_release != null) {
            return owner$ui_release;
        }
        throw new IllegalStateException("Required value was null.".toString());
    }

    public static final void invalidateSubtree(DelegatableNode $this$invalidateSubtree) {
        Intrinsics.checkNotNullParameter($this$invalidateSubtree, "<this>");
        if ($this$invalidateSubtree.getNode().isAttached()) {
            LayoutNode.invalidateSubtree$default(requireLayoutNode($this$invalidateSubtree), false, 1, null);
        }
    }
}
