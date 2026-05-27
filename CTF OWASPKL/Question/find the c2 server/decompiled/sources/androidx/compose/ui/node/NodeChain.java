package androidx.compose.ui.node;

import androidx.compose.runtime.collection.MutableVector;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.layout.ModifierInfo;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: NodeChain.kt */
@Metadata(d1 = {"\u0000\u0082\u0001\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u001e\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0007\b\u0000\u0018\u00002\u00020\u0001:\u0002deB\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u000e\u0010%\u001a\u00020&2\u0006\u0010'\u001a\u00020\u0019J\u0018\u0010(\u001a\u00020\u00102\u0006\u0010)\u001a\u00020\u000b2\u0006\u0010*\u001a\u00020\u0010H\u0002J\r\u0010+\u001a\u00020&H\u0000¢\u0006\u0002\b,J\u0010\u0010-\u001a\u00020\u00102\u0006\u0010.\u001a\u00020\u0010H\u0002JE\u0010/\u001a\u0004\u0018\u0001H0\"\u0006\b\u0000\u00100\u0018\u00012\f\u00101\u001a\b\u0012\u0004\u0012\u0002H0022\u0012\u00103\u001a\u000e\u0012\u0004\u0012\u0002H0\u0012\u0004\u0012\u00020\u001904H\u0080\bø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\b5\u00106J0\u00107\u001a\u00060\rR\u00020\u00002\u0006\u0010#\u001a\u00020\u00102\f\u00108\u001a\b\u0012\u0004\u0012\u00020\u000b0\n2\f\u00109\u001a\b\u0012\u0004\u0012\u00020\u000b0\nH\u0002J\f\u0010:\u001a\b\u0012\u0004\u0012\u00020<0;J!\u0010=\u001a\u00020\u00192\n\u00101\u001a\u0006\u0012\u0002\b\u000302H\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\b>\u0010?J\u0015\u0010=\u001a\u00020\u00192\u0006\u0010@\u001a\u00020\u0006H\u0000¢\u0006\u0002\bAJ.\u0010\u0011\u001a\u0004\u0018\u0001H0\"\u0006\b\u0000\u00100\u0018\u00012\f\u00101\u001a\b\u0012\u0004\u0012\u0002H002H\u0080\bø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\bB\u0010CJ%\u0010D\u001a\u00020&2\u0012\u00103\u001a\u000e\u0012\u0004\u0012\u00020\u0010\u0012\u0004\u0012\u00020&04H\u0080\bø\u0001\u0000¢\u0006\u0002\bEJC\u0010D\u001a\u00020&\"\u0006\b\u0000\u00100\u0018\u00012\f\u00101\u001a\b\u0012\u0004\u0012\u0002H0022\u0012\u00103\u001a\u000e\u0012\u0004\u0012\u0002H0\u0012\u0004\u0012\u00020&04H\u0080\bø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\bF\u0010GJ-\u0010D\u001a\u00020&2\u0006\u0010@\u001a\u00020\u00062\u0012\u00103\u001a\u000e\u0012\u0004\u0012\u00020\u0010\u0012\u0004\u0012\u00020&04H\u0080\bø\u0001\u0000¢\u0006\u0002\bEJ%\u0010H\u001a\u00020&2\u0012\u00103\u001a\u000e\u0012\u0004\u0012\u00020\u0010\u0012\u0004\u0012\u00020&04H\u0080\bø\u0001\u0000¢\u0006\u0002\bIJ\u0018\u0010J\u001a\u00020\u00102\u0006\u0010.\u001a\u00020\u00102\u0006\u0010*\u001a\u00020\u0010H\u0002J\b\u0010K\u001a\u00020&H\u0002J\u0010\u0010L\u001a\u00020\u00102\u0006\u0010.\u001a\u00020\u0010H\u0002J\u0018\u0010M\u001a\u00020\u00102\u0006\u0010N\u001a\u00020\u00102\u0006\u0010O\u001a\u00020\u0010H\u0002J\r\u0010P\u001a\u00020&H\u0000¢\u0006\u0002\bQJ<\u0010R\u001a\u00020&2\f\u00108\u001a\b\u0012\u0004\u0012\u00020\u000b0\n2\u0006\u0010S\u001a\u00020\u00062\f\u00109\u001a\b\u0012\u0004\u0012\u00020\u000b0\n2\u0006\u0010T\u001a\u00020\u00062\u0006\u0010#\u001a\u00020\u0010H\u0002J\b\u0010U\u001a\u00020&H\u0002J.\u0010#\u001a\u0004\u0018\u0001H0\"\u0006\b\u0000\u00100\u0018\u00012\f\u00101\u001a\b\u0012\u0004\u0012\u0002H002H\u0080\bø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\bV\u0010CJ%\u0010W\u001a\u00020&2\u0012\u00103\u001a\u000e\u0012\u0004\u0012\u00020\u0010\u0012\u0004\u0012\u00020&04H\u0080\bø\u0001\u0000¢\u0006\u0002\bXJC\u0010W\u001a\u00020&\"\u0006\b\u0000\u00100\u0018\u00012\f\u00101\u001a\b\u0012\u0004\u0012\u0002H0022\u0012\u00103\u001a\u000e\u0012\u0004\u0012\u0002H0\u0012\u0004\u0012\u00020&04H\u0080\bø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\bY\u0010GJ-\u0010W\u001a\u00020&2\u0006\u0010@\u001a\u00020\u00062\u0012\u00103\u001a\u000e\u0012\u0004\u0012\u00020\u0010\u0012\u0004\u0012\u00020&04H\u0080\bø\u0001\u0000¢\u0006\u0002\bXJ\b\u0010Z\u001a\u00020[H\u0016J\b\u0010\\\u001a\u00020&H\u0002J\u0015\u0010]\u001a\u00020&2\u0006\u0010^\u001a\u00020_H\u0000¢\u0006\u0002\b`J \u0010a\u001a\u00020\u00102\u0006\u0010N\u001a\u00020\u000b2\u0006\u0010O\u001a\u00020\u000b2\u0006\u0010.\u001a\u00020\u0010H\u0002J\u0017\u0010b\u001a\u00020&2\b\u0010\u001d\u001a\u0004\u0018\u00010\u001eH\u0000¢\u0006\u0002\bcR\u0014\u0010\u0005\u001a\u00020\u00068BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u0007\u0010\bR\u0016\u0010\t\u001a\n\u0012\u0004\u0012\u00020\u000b\u0018\u00010\nX\u0082\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\f\u001a\b\u0018\u00010\rR\u00020\u0000X\u0082\u000e¢\u0006\u0002\n\u0000R\u0016\u0010\u000e\u001a\n\u0012\u0004\u0012\u00020\u000b\u0018\u00010\nX\u0082\u000e¢\u0006\u0002\n\u0000R\u001e\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u000f\u001a\u00020\u0010@BX\u0080\u000e¢\u0006\b\n\u0000\u001a\u0004\b\u0012\u0010\u0013R\u0014\u0010\u0014\u001a\u00020\u0015X\u0080\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0016\u0010\u0017R\u0014\u0010\u0018\u001a\u00020\u00198BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u0018\u0010\u001aR\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u001b\u0010\u001cR\u0010\u0010\u001d\u001a\u0004\u0018\u00010\u001eX\u0082\u000e¢\u0006\u0002\n\u0000R\u001e\u0010 \u001a\u00020\u001f2\u0006\u0010\u000f\u001a\u00020\u001f@BX\u0080\u000e¢\u0006\b\n\u0000\u001a\u0004\b!\u0010\"R\u0014\u0010#\u001a\u00020\u0010X\u0080\u0004¢\u0006\b\n\u0000\u001a\u0004\b$\u0010\u0013\u0082\u0002\u0012\n\u0005\b\u009920\u0001\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006f"}, d2 = {"Landroidx/compose/ui/node/NodeChain;", "", "layoutNode", "Landroidx/compose/ui/node/LayoutNode;", "(Landroidx/compose/ui/node/LayoutNode;)V", "aggregateChildKindSet", "", "getAggregateChildKindSet", "()I", "buffer", "Landroidx/compose/runtime/collection/MutableVector;", "Landroidx/compose/ui/Modifier$Element;", "cachedDiffer", "Landroidx/compose/ui/node/NodeChain$Differ;", "current", "<set-?>", "Landroidx/compose/ui/Modifier$Node;", "head", "getHead$ui_release", "()Landroidx/compose/ui/Modifier$Node;", "innerCoordinator", "Landroidx/compose/ui/node/InnerNodeCoordinator;", "getInnerCoordinator$ui_release", "()Landroidx/compose/ui/node/InnerNodeCoordinator;", "isUpdating", "", "()Z", "getLayoutNode", "()Landroidx/compose/ui/node/LayoutNode;", "logger", "Landroidx/compose/ui/node/NodeChain$Logger;", "Landroidx/compose/ui/node/NodeCoordinator;", "outerCoordinator", "getOuterCoordinator$ui_release", "()Landroidx/compose/ui/node/NodeCoordinator;", "tail", "getTail$ui_release", "attach", "", "performInvalidations", "createAndInsertNodeAsParent", "element", "child", "detach", "detach$ui_release", "detachAndRemoveNode", "node", "firstFromHead", "T", "type", "Landroidx/compose/ui/node/NodeKind;", "block", "Lkotlin/Function1;", "firstFromHead-aLcG6gQ$ui_release", "(ILkotlin/jvm/functions/Function1;)Ljava/lang/Object;", "getDiffer", "before", "after", "getModifierInfo", "", "Landroidx/compose/ui/layout/ModifierInfo;", "has", "has-H91voCI$ui_release", "(I)Z", "mask", "has$ui_release", "head-H91voCI$ui_release", "(I)Ljava/lang/Object;", "headToTail", "headToTail$ui_release", "headToTail-aLcG6gQ$ui_release", "(ILkotlin/jvm/functions/Function1;)V", "headToTailExclusive", "headToTailExclusive$ui_release", "insertParent", "padChain", "removeNode", "replaceNode", "prev", "next", "resetState", "resetState$ui_release", "structuralUpdate", "beforeSize", "afterSize", "syncCoordinators", "tail-H91voCI$ui_release", "tailToHead", "tailToHead$ui_release", "tailToHead-aLcG6gQ$ui_release", "toString", "", "trimChain", "updateFrom", "m", "Landroidx/compose/ui/Modifier;", "updateFrom$ui_release", "updateNodeAndReplaceIfNeeded", "useLogger", "useLogger$ui_release", "Differ", "Logger", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class NodeChain {
    private MutableVector<Modifier.Element> buffer;
    private Differ cachedDiffer;
    private MutableVector<Modifier.Element> current;
    private Modifier.Node head;
    private final InnerNodeCoordinator innerCoordinator;
    private final LayoutNode layoutNode;
    private Logger logger;
    private NodeCoordinator outerCoordinator;
    private final Modifier.Node tail;

    /* compiled from: NodeChain.kt */
    @Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\r\b`\u0018\u00002\u00020\u0001J(\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\nH&J0\u0010\u000b\u001a\u00020\u00032\u0006\u0010\f\u001a\u00020\u00052\u0006\u0010\r\u001a\u00020\u00052\u0006\u0010\u000e\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\n2\u0006\u0010\u0010\u001a\u00020\nH&J \u0010\u0011\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00052\u0006\u0010\u000e\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\nH&J0\u0010\u0013\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00052\u0006\u0010\r\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\nH&J8\u0010\u0014\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00052\u0006\u0010\r\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\u0015\u001a\u00020\n2\u0006\u0010\u0016\u001a\u00020\nH&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0017À\u0006\u0001"}, d2 = {"Landroidx/compose/ui/node/NodeChain$Logger;", "", "linearDiffAborted", "", "index", "", "prev", "Landroidx/compose/ui/Modifier$Element;", "next", "node", "Landroidx/compose/ui/Modifier$Node;", "nodeInserted", "atIndex", "newIndex", "element", "child", "inserted", "nodeRemoved", "oldIndex", "nodeReused", "nodeUpdated", "before", "after", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public interface Logger {
        void linearDiffAborted(int i, Modifier.Element element, Modifier.Element element2, Modifier.Node node);

        void nodeInserted(int i, int i2, Modifier.Element element, Modifier.Node node, Modifier.Node node2);

        void nodeRemoved(int i, Modifier.Element element, Modifier.Node node);

        void nodeReused(int i, int i2, Modifier.Element element, Modifier.Element element2, Modifier.Node node);

        void nodeUpdated(int i, int i2, Modifier.Element element, Modifier.Element element2, Modifier.Node node, Modifier.Node node2);
    }

    public NodeChain(LayoutNode layoutNode) {
        Intrinsics.checkNotNullParameter(layoutNode, "layoutNode");
        this.layoutNode = layoutNode;
        InnerNodeCoordinator innerNodeCoordinator = new InnerNodeCoordinator(layoutNode);
        this.innerCoordinator = innerNodeCoordinator;
        this.outerCoordinator = innerNodeCoordinator;
        Modifier.Node tail = innerNodeCoordinator.getTail();
        this.tail = tail;
        this.head = tail;
    }

    public static final /* synthetic */ int access$getAggregateChildKindSet(NodeChain $this) {
        return $this.getAggregateChildKindSet();
    }

    public final LayoutNode getLayoutNode() {
        return this.layoutNode;
    }

    public final InnerNodeCoordinator getInnerCoordinator$ui_release() {
        return this.innerCoordinator;
    }

    public final NodeCoordinator getOuterCoordinator$ui_release() {
        return this.outerCoordinator;
    }

    public final Modifier.Node getTail$ui_release() {
        return this.tail;
    }

    public final Modifier.Node getHead$ui_release() {
        return this.head;
    }

    private final boolean isUpdating() {
        NodeChainKt$SentinelHead$1 nodeChainKt$SentinelHead$1;
        Modifier.Node node = this.head;
        nodeChainKt$SentinelHead$1 = NodeChainKt.SentinelHead;
        return node == nodeChainKt$SentinelHead$1;
    }

    public final int getAggregateChildKindSet() {
        return this.head.getAggregateChildKindSet$ui_release();
    }

    public final void useLogger$ui_release(Logger logger) {
        this.logger = logger;
    }

    private final void padChain() {
        NodeChainKt$SentinelHead$1 nodeChainKt$SentinelHead$1;
        NodeChainKt$SentinelHead$1 nodeChainKt$SentinelHead$12;
        NodeChainKt$SentinelHead$1 nodeChainKt$SentinelHead$13;
        NodeChainKt$SentinelHead$1 nodeChainKt$SentinelHead$14;
        Modifier.Node node = this.head;
        nodeChainKt$SentinelHead$1 = NodeChainKt.SentinelHead;
        if (!(node != nodeChainKt$SentinelHead$1)) {
            throw new IllegalStateException("Check failed.".toString());
        }
        Modifier.Node currentHead = this.head;
        nodeChainKt$SentinelHead$12 = NodeChainKt.SentinelHead;
        currentHead.setParent$ui_release(nodeChainKt$SentinelHead$12);
        nodeChainKt$SentinelHead$13 = NodeChainKt.SentinelHead;
        nodeChainKt$SentinelHead$13.setChild$ui_release(currentHead);
        nodeChainKt$SentinelHead$14 = NodeChainKt.SentinelHead;
        this.head = nodeChainKt$SentinelHead$14;
    }

    private final void trimChain() {
        NodeChainKt$SentinelHead$1 nodeChainKt$SentinelHead$1;
        NodeChainKt$SentinelHead$1 nodeChainKt$SentinelHead$12;
        NodeChainKt$SentinelHead$1 nodeChainKt$SentinelHead$13;
        NodeChainKt$SentinelHead$1 nodeChainKt$SentinelHead$14;
        Modifier.Node node = this.head;
        nodeChainKt$SentinelHead$1 = NodeChainKt.SentinelHead;
        if (node == nodeChainKt$SentinelHead$1) {
            nodeChainKt$SentinelHead$12 = NodeChainKt.SentinelHead;
            Modifier.Node child$ui_release = nodeChainKt$SentinelHead$12.getChild$ui_release();
            if (child$ui_release == null) {
                child$ui_release = this.tail;
            }
            this.head = child$ui_release;
            child$ui_release.setParent$ui_release(null);
            nodeChainKt$SentinelHead$13 = NodeChainKt.SentinelHead;
            nodeChainKt$SentinelHead$13.setChild$ui_release(null);
            Modifier.Node node2 = this.head;
            nodeChainKt$SentinelHead$14 = NodeChainKt.SentinelHead;
            if (!(node2 != nodeChainKt$SentinelHead$14)) {
                throw new IllegalStateException("Check failed.".toString());
            }
            return;
        }
        throw new IllegalStateException("Check failed.".toString());
    }

    /* JADX WARN: Removed duplicated region for block: B:121:0x00e2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void updateFrom$ui_release(androidx.compose.ui.Modifier r23) {
        /*
            Method dump skipped, instructions count: 444
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.node.NodeChain.updateFrom$ui_release(androidx.compose.ui.Modifier):void");
    }

    public final void resetState$ui_release() {
        MutableVector current = this.current;
        if (current == null) {
            return;
        }
        int size = current.getSize();
        Modifier.Node node = this.tail.getParent$ui_release();
        for (int i = size - 1; node != null && i >= 0; i--) {
            if (node.isAttached()) {
                node.reset$ui_release();
                node.detach$ui_release();
            }
            node = node.getParent$ui_release();
        }
    }

    private final void syncCoordinators() {
        LayoutModifierNodeCoordinator c;
        NodeCoordinator coordinator = this.innerCoordinator;
        for (Modifier.Node node = this.tail.getParent$ui_release(); node != null; node = node.getParent$ui_release()) {
            Modifier.Node this_$iv = node;
            if (((this_$iv.getKindSet$ui_release() & NodeKind.m4327constructorimpl(2)) != 0) && (node instanceof LayoutModifierNode)) {
                if (node.getCoordinator$ui_release() != null) {
                    NodeCoordinator coordinator$ui_release = node.getCoordinator$ui_release();
                    Intrinsics.checkNotNull(coordinator$ui_release, "null cannot be cast to non-null type androidx.compose.ui.node.LayoutModifierNodeCoordinator");
                    c = (LayoutModifierNodeCoordinator) coordinator$ui_release;
                    LayoutModifierNode prevNode = c.getLayoutModifierNode();
                    c.setLayoutModifierNode$ui_release((LayoutModifierNode) node);
                    if (prevNode != node) {
                        c.onLayoutModifierNodeChanged();
                    }
                } else {
                    c = new LayoutModifierNodeCoordinator(this.layoutNode, (LayoutModifierNode) node);
                    node.updateCoordinator$ui_release(c);
                }
                coordinator.setWrappedBy$ui_release(c);
                c.setWrapped$ui_release(coordinator);
                NodeCoordinator coordinator2 = c;
                coordinator = coordinator2;
            } else {
                node.updateCoordinator$ui_release(coordinator);
            }
        }
        LayoutNode parent$ui_release = this.layoutNode.getParent$ui_release();
        coordinator.setWrappedBy$ui_release(parent$ui_release != null ? parent$ui_release.getInnerCoordinator$ui_release() : null);
        this.outerCoordinator = coordinator;
    }

    public final void attach(boolean performInvalidations) {
        for (Modifier.Node node$iv = getHead$ui_release(); node$iv != null; node$iv = node$iv.getChild$ui_release()) {
            Modifier.Node it = node$iv;
            if (!it.isAttached()) {
                it.attach$ui_release();
                if (performInvalidations) {
                    if (it.getInsertedNodeAwaitingAttachForInvalidation$ui_release()) {
                        NodeKindKt.autoInvalidateInsertedNode(it);
                    }
                    if (it.getUpdatedNodeAwaitingAttachForInvalidation$ui_release()) {
                        NodeKindKt.autoInvalidateUpdatedNode(it);
                    }
                }
                it.setInsertedNodeAwaitingAttachForInvalidation$ui_release(false);
                it.setUpdatedNodeAwaitingAttachForInvalidation$ui_release(false);
            }
        }
    }

    public final List<ModifierInfo> getModifierInfo() {
        MutableVector current = this.current;
        if (current == null) {
            return CollectionsKt.emptyList();
        }
        int capacity$iv = current.getSize();
        MutableVector infoList = new MutableVector(new ModifierInfo[capacity$iv], 0);
        int i = 0;
        Modifier.Node node$iv = getHead$ui_release();
        while (node$iv != null && node$iv != getTail$ui_release()) {
            Modifier.Node node = node$iv;
            NodeCoordinator coordinator = node.getCoordinator$ui_release();
            if (coordinator == null) {
                throw new IllegalArgumentException("Required value was null.".toString());
            }
            infoList.add(new ModifierInfo(current.getContent()[i], coordinator, coordinator.getLayer()));
            node$iv = node$iv.getChild$ui_release();
            i++;
        }
        return infoList.asMutableList();
    }

    public final void detach$ui_release() {
        for (Modifier.Node node$iv = getTail$ui_release(); node$iv != null; node$iv = node$iv.getParent$ui_release()) {
            Modifier.Node it = node$iv;
            if (it.isAttached()) {
                it.detach$ui_release();
            }
        }
    }

    private final Differ getDiffer(Modifier.Node tail, MutableVector<Modifier.Element> mutableVector, MutableVector<Modifier.Element> mutableVector2) {
        Differ current = this.cachedDiffer;
        if (current == null) {
            Differ it = new Differ(this, tail, tail.getAggregateChildKindSet$ui_release(), mutableVector, mutableVector2);
            this.cachedDiffer = it;
            return it;
        }
        current.setNode(tail);
        current.setAggregateChildKindSet(tail.getAggregateChildKindSet$ui_release());
        current.setBefore(mutableVector);
        current.setAfter(mutableVector2);
        return current;
    }

    /* compiled from: NodeChain.kt */
    @Metadata(d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0011\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0004\b\u0082\u0004\u0018\u00002\u00020\u0001B1\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\f\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\b0\u0007\u0012\f\u0010\t\u001a\b\u0012\u0004\u0012\u00020\b0\u0007¢\u0006\u0002\u0010\nJ\u0018\u0010\u0019\u001a\u00020\u001a2\u0006\u0010\u001b\u001a\u00020\u00052\u0006\u0010\u001c\u001a\u00020\u0005H\u0016J\u0018\u0010\u001d\u001a\u00020\u001e2\u0006\u0010\u001f\u001a\u00020\u00052\u0006\u0010\u001c\u001a\u00020\u0005H\u0016J\u0010\u0010 \u001a\u00020\u001e2\u0006\u0010\u001b\u001a\u00020\u0005H\u0016J\u0018\u0010!\u001a\u00020\u001e2\u0006\u0010\u001b\u001a\u00020\u00052\u0006\u0010\u001c\u001a\u00020\u0005H\u0016R \u0010\t\u001a\b\u0012\u0004\u0012\u00020\b0\u0007X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000eR\u001a\u0010\u0004\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000f\u0010\u0010\"\u0004\b\u0011\u0010\u0012R \u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\b0\u0007X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0013\u0010\f\"\u0004\b\u0014\u0010\u000eR\u001a\u0010\u0002\u001a\u00020\u0003X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0015\u0010\u0016\"\u0004\b\u0017\u0010\u0018¨\u0006\""}, d2 = {"Landroidx/compose/ui/node/NodeChain$Differ;", "Landroidx/compose/ui/node/DiffCallback;", "node", "Landroidx/compose/ui/Modifier$Node;", "aggregateChildKindSet", "", "before", "Landroidx/compose/runtime/collection/MutableVector;", "Landroidx/compose/ui/Modifier$Element;", "after", "(Landroidx/compose/ui/node/NodeChain;Landroidx/compose/ui/Modifier$Node;ILandroidx/compose/runtime/collection/MutableVector;Landroidx/compose/runtime/collection/MutableVector;)V", "getAfter", "()Landroidx/compose/runtime/collection/MutableVector;", "setAfter", "(Landroidx/compose/runtime/collection/MutableVector;)V", "getAggregateChildKindSet", "()I", "setAggregateChildKindSet", "(I)V", "getBefore", "setBefore", "getNode", "()Landroidx/compose/ui/Modifier$Node;", "setNode", "(Landroidx/compose/ui/Modifier$Node;)V", "areItemsTheSame", "", "oldIndex", "newIndex", "insert", "", "atIndex", "remove", "same", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public final class Differ implements DiffCallback {
        private MutableVector<Modifier.Element> after;
        private int aggregateChildKindSet;
        private MutableVector<Modifier.Element> before;
        private Modifier.Node node;
        final /* synthetic */ NodeChain this$0;

        public Differ(NodeChain this$0, Modifier.Node node, int aggregateChildKindSet, MutableVector<Modifier.Element> before, MutableVector<Modifier.Element> after) {
            Intrinsics.checkNotNullParameter(node, "node");
            Intrinsics.checkNotNullParameter(before, "before");
            Intrinsics.checkNotNullParameter(after, "after");
            this.this$0 = this$0;
            this.node = node;
            this.aggregateChildKindSet = aggregateChildKindSet;
            this.before = before;
            this.after = after;
        }

        public final Modifier.Node getNode() {
            return this.node;
        }

        public final void setNode(Modifier.Node node) {
            Intrinsics.checkNotNullParameter(node, "<set-?>");
            this.node = node;
        }

        public final int getAggregateChildKindSet() {
            return this.aggregateChildKindSet;
        }

        public final void setAggregateChildKindSet(int i) {
            this.aggregateChildKindSet = i;
        }

        public final MutableVector<Modifier.Element> getBefore() {
            return this.before;
        }

        public final void setBefore(MutableVector<Modifier.Element> mutableVector) {
            Intrinsics.checkNotNullParameter(mutableVector, "<set-?>");
            this.before = mutableVector;
        }

        public final MutableVector<Modifier.Element> getAfter() {
            return this.after;
        }

        public final void setAfter(MutableVector<Modifier.Element> mutableVector) {
            Intrinsics.checkNotNullParameter(mutableVector, "<set-?>");
            this.after = mutableVector;
        }

        @Override // androidx.compose.ui.node.DiffCallback
        public boolean areItemsTheSame(int oldIndex, int newIndex) {
            MutableVector this_$iv = this.before;
            MutableVector this_$iv2 = this.after;
            return NodeChainKt.actionForModifiers(this_$iv.getContent()[oldIndex], this_$iv2.getContent()[newIndex]) != 0;
        }

        @Override // androidx.compose.ui.node.DiffCallback
        public void insert(int atIndex, int newIndex) {
            Modifier.Node child = this.node;
            NodeChain nodeChain = this.this$0;
            MutableVector this_$iv = this.after;
            Modifier.Node createAndInsertNodeAsParent = nodeChain.createAndInsertNodeAsParent(this_$iv.getContent()[newIndex], child);
            this.node = createAndInsertNodeAsParent;
            if (!(!createAndInsertNodeAsParent.isAttached())) {
                throw new IllegalStateException("Check failed.".toString());
            }
            this.node.setInsertedNodeAwaitingAttachForInvalidation$ui_release(true);
            Logger logger = this.this$0.logger;
            if (logger != null) {
                MutableVector this_$iv2 = this.after;
                logger.nodeInserted(atIndex, newIndex, this_$iv2.getContent()[newIndex], child, this.node);
            }
            int kindSet$ui_release = this.aggregateChildKindSet | this.node.getKindSet$ui_release();
            this.aggregateChildKindSet = kindSet$ui_release;
            this.node.setAggregateChildKindSet$ui_release(kindSet$ui_release);
        }

        @Override // androidx.compose.ui.node.DiffCallback
        public void remove(int oldIndex) {
            Modifier.Node parent$ui_release = this.node.getParent$ui_release();
            Intrinsics.checkNotNull(parent$ui_release);
            this.node = parent$ui_release;
            Logger logger = this.this$0.logger;
            if (logger != null) {
                MutableVector this_$iv = this.before;
                logger.nodeRemoved(oldIndex, this_$iv.getContent()[oldIndex], this.node);
            }
            this.node = this.this$0.detachAndRemoveNode(this.node);
        }

        @Override // androidx.compose.ui.node.DiffCallback
        public void same(int oldIndex, int newIndex) {
            Modifier.Node parent$ui_release = this.node.getParent$ui_release();
            Intrinsics.checkNotNull(parent$ui_release);
            this.node = parent$ui_release;
            MutableVector this_$iv = this.before;
            Modifier.Element prev = this_$iv.getContent()[oldIndex];
            MutableVector this_$iv2 = this.after;
            Modifier.Element next = this_$iv2.getContent()[newIndex];
            if (Intrinsics.areEqual(prev, next)) {
                Logger logger = this.this$0.logger;
                if (logger != null) {
                    logger.nodeReused(oldIndex, newIndex, prev, next, this.node);
                }
            } else {
                Modifier.Node beforeUpdate = this.node;
                this.node = this.this$0.updateNodeAndReplaceIfNeeded(prev, next, beforeUpdate);
                Logger logger2 = this.this$0.logger;
                if (logger2 != null) {
                    logger2.nodeUpdated(oldIndex, newIndex, prev, next, beforeUpdate, this.node);
                }
            }
            int kindSet$ui_release = this.aggregateChildKindSet | this.node.getKindSet$ui_release();
            this.aggregateChildKindSet = kindSet$ui_release;
            this.node.setAggregateChildKindSet$ui_release(kindSet$ui_release);
        }
    }

    private final void structuralUpdate(MutableVector<Modifier.Element> mutableVector, int beforeSize, MutableVector<Modifier.Element> mutableVector2, int afterSize, Modifier.Node tail) {
        MyersDiffKt.executeDiff(beforeSize, afterSize, getDiffer(tail, mutableVector, mutableVector2));
    }

    private final Modifier.Node replaceNode(Modifier.Node prev, Modifier.Node next) {
        Modifier.Node parent = prev.getParent$ui_release();
        if (parent != null) {
            next.setParent$ui_release(parent);
            parent.setChild$ui_release(next);
            prev.setParent$ui_release(null);
        }
        Modifier.Node child = prev.getChild$ui_release();
        if (child != null) {
            next.setChild$ui_release(child);
            child.setParent$ui_release(next);
            prev.setChild$ui_release(null);
        }
        next.updateCoordinator$ui_release(prev.getCoordinator$ui_release());
        return next;
    }

    public final Modifier.Node detachAndRemoveNode(Modifier.Node node) {
        if (node.isAttached()) {
            NodeKindKt.autoInvalidateRemovedNode(node);
            node.detach$ui_release();
        }
        return removeNode(node);
    }

    private final Modifier.Node removeNode(Modifier.Node node) {
        Modifier.Node child = node.getChild$ui_release();
        Modifier.Node parent = node.getParent$ui_release();
        if (child != null) {
            child.setParent$ui_release(parent);
            node.setChild$ui_release(null);
        }
        if (parent != null) {
            parent.setChild$ui_release(child);
            node.setParent$ui_release(null);
        }
        Intrinsics.checkNotNull(child);
        return child;
    }

    public final Modifier.Node createAndInsertNodeAsParent(Modifier.Element element, Modifier.Node child) {
        BackwardsCompatNode it;
        if (element instanceof ModifierNodeElement) {
            it = ((ModifierNodeElement) element).create();
            it.setKindSet$ui_release(NodeKindKt.calculateNodeKindSetFrom(it));
        } else {
            it = new BackwardsCompatNode(element);
        }
        if (!(!it.isAttached())) {
            throw new IllegalStateException("Check failed.".toString());
        }
        it.setInsertedNodeAwaitingAttachForInvalidation$ui_release(true);
        return insertParent(it, child);
    }

    private final Modifier.Node insertParent(Modifier.Node node, Modifier.Node child) {
        Modifier.Node theParent = child.getParent$ui_release();
        if (theParent != null) {
            theParent.setChild$ui_release(node);
            node.setParent$ui_release(theParent);
        }
        child.setParent$ui_release(node);
        node.setChild$ui_release(child);
        return node;
    }

    public final Modifier.Node updateNodeAndReplaceIfNeeded(Modifier.Element prev, Modifier.Element next, Modifier.Node node) {
        Modifier.Node updated;
        if ((prev instanceof ModifierNodeElement) && (next instanceof ModifierNodeElement)) {
            updated = NodeChainKt.updateUnsafe((ModifierNodeElement) next, node);
            if (updated != node) {
                if (!(!updated.isAttached())) {
                    throw new IllegalStateException("Check failed.".toString());
                }
                updated.setInsertedNodeAwaitingAttachForInvalidation$ui_release(true);
                if (node.isAttached()) {
                    NodeKindKt.autoInvalidateRemovedNode(node);
                    node.detach$ui_release();
                }
                return replaceNode(node, updated);
            }
            if (((ModifierNodeElement) next).getAutoInvalidate()) {
                if (updated.isAttached()) {
                    NodeKindKt.autoInvalidateUpdatedNode(updated);
                } else {
                    updated.setUpdatedNodeAwaitingAttachForInvalidation$ui_release(true);
                }
            }
            return updated;
        } else if (node instanceof BackwardsCompatNode) {
            ((BackwardsCompatNode) node).setElement(next);
            if (node.isAttached()) {
                NodeKindKt.autoInvalidateUpdatedNode(node);
            } else {
                node.setUpdatedNodeAwaitingAttachForInvalidation$ui_release(true);
            }
            return node;
        } else {
            throw new IllegalStateException("Unknown Modifier.Node type".toString());
        }
    }

    /* JADX WARN: Type inference failed for: r12v5, types: [T, java.lang.Object, androidx.compose.ui.Modifier$Node] */
    /* renamed from: firstFromHead-aLcG6gQ$ui_release */
    public final /* synthetic */ <T> T m4289firstFromHeadaLcG6gQ$ui_release(int type, Function1<? super T, Boolean> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        if ((getAggregateChildKindSet() & type) == 0) {
            return null;
        }
        for (Modifier.Node node$iv$iv$iv = getHead$ui_release(); node$iv$iv$iv != null; node$iv$iv$iv = node$iv$iv$iv.getChild$ui_release()) {
            Modifier.Node it$iv$iv = node$iv$iv$iv;
            if ((it$iv$iv.getKindSet$ui_release() & type) != 0) {
                Modifier.Node node = it$iv$iv;
                Intrinsics.reifiedOperationMarker(3, "T");
                if ((node instanceof Object) && block.invoke(node).booleanValue()) {
                    return node;
                }
            }
            if ((it$iv$iv.getAggregateChildKindSet$ui_release() & type) == 0) {
                return null;
            }
        }
        return null;
    }

    /* renamed from: headToTail-aLcG6gQ$ui_release */
    public final /* synthetic */ <T> void m4292headToTailaLcG6gQ$ui_release(int type, Function1<? super T, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        if ((getAggregateChildKindSet() & type) == 0) {
            return;
        }
        for (Modifier.Node node$iv$iv = getHead$ui_release(); node$iv$iv != null; node$iv$iv = node$iv$iv.getChild$ui_release()) {
            Modifier.Node it$iv = node$iv$iv;
            if ((it$iv.getKindSet$ui_release() & type) != 0) {
                Modifier.Node it = it$iv;
                Intrinsics.reifiedOperationMarker(3, "T");
                if (it instanceof Object) {
                    block.invoke(it);
                }
            }
            if ((it$iv.getAggregateChildKindSet$ui_release() & type) == 0) {
                return;
            }
        }
    }

    public final void headToTail$ui_release(int mask, Function1<? super Modifier.Node, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        if ((getAggregateChildKindSet() & mask) == 0) {
            return;
        }
        for (Modifier.Node node$iv = getHead$ui_release(); node$iv != null; node$iv = node$iv.getChild$ui_release()) {
            Modifier.Node it = node$iv;
            if ((it.getKindSet$ui_release() & mask) != 0) {
                block.invoke(it);
            }
            if ((it.getAggregateChildKindSet$ui_release() & mask) == 0) {
                return;
            }
        }
    }

    public final void headToTail$ui_release(Function1<? super Modifier.Node, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        for (Modifier.Node node = getHead$ui_release(); node != null; node = node.getChild$ui_release()) {
            block.invoke(node);
        }
    }

    public final void headToTailExclusive$ui_release(Function1<? super Modifier.Node, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        for (Modifier.Node node = getHead$ui_release(); node != null && node != getTail$ui_release(); node = node.getChild$ui_release()) {
            block.invoke(node);
        }
    }

    /* renamed from: tailToHead-aLcG6gQ$ui_release */
    public final /* synthetic */ <T> void m4294tailToHeadaLcG6gQ$ui_release(int type, Function1<? super T, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        if ((getAggregateChildKindSet() & type) == 0) {
            return;
        }
        for (Modifier.Node node$iv$iv = getTail$ui_release(); node$iv$iv != null; node$iv$iv = node$iv$iv.getParent$ui_release()) {
            Modifier.Node it$iv = node$iv$iv;
            if ((it$iv.getKindSet$ui_release() & type) != 0) {
                Modifier.Node it = it$iv;
                Intrinsics.reifiedOperationMarker(3, "T");
                if (it instanceof Object) {
                    block.invoke(it);
                }
            }
        }
    }

    public final void tailToHead$ui_release(int mask, Function1<? super Modifier.Node, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        if ((getAggregateChildKindSet() & mask) == 0) {
            return;
        }
        for (Modifier.Node node$iv = getTail$ui_release(); node$iv != null; node$iv = node$iv.getParent$ui_release()) {
            Modifier.Node it = node$iv;
            if ((it.getKindSet$ui_release() & mask) != 0) {
                block.invoke(it);
            }
        }
    }

    public final void tailToHead$ui_release(Function1<? super Modifier.Node, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        for (Modifier.Node node = getTail$ui_release(); node != null; node = node.getParent$ui_release()) {
            block.invoke(node);
        }
    }

    /* renamed from: tail-H91voCI$ui_release */
    public final /* synthetic */ <T> T m4293tailH91voCI$ui_release(int type) {
        if ((getAggregateChildKindSet() & type) == 0) {
            return null;
        }
        for (Modifier.Node node$iv$iv$iv = getTail$ui_release(); node$iv$iv$iv != null; node$iv$iv$iv = node$iv$iv$iv.getParent$ui_release()) {
            Modifier.Node it$iv$iv = node$iv$iv$iv;
            if ((it$iv$iv.getKindSet$ui_release() & type) != 0) {
                T t = (T) it$iv$iv;
                Intrinsics.reifiedOperationMarker(3, "T");
                if (t instanceof Object) {
                    return t;
                }
            }
        }
        return null;
    }

    /* renamed from: head-H91voCI$ui_release */
    public final /* synthetic */ <T> T m4291headH91voCI$ui_release(int type) {
        if ((getAggregateChildKindSet() & type) == 0) {
            return null;
        }
        for (Modifier.Node node$iv$iv$iv = getHead$ui_release(); node$iv$iv$iv != null; node$iv$iv$iv = node$iv$iv$iv.getChild$ui_release()) {
            Modifier.Node it$iv$iv = node$iv$iv$iv;
            if ((it$iv$iv.getKindSet$ui_release() & type) != 0) {
                T t = (T) it$iv$iv;
                Intrinsics.reifiedOperationMarker(3, "T");
                if (t instanceof Object) {
                    return t;
                }
            }
            if ((it$iv$iv.getAggregateChildKindSet$ui_release() & type) == 0) {
                return null;
            }
        }
        return null;
    }

    /* renamed from: has-H91voCI$ui_release */
    public final boolean m4290hasH91voCI$ui_release(int type) {
        return (getAggregateChildKindSet() & type) != 0;
    }

    public final boolean has$ui_release(int mask) {
        return (getAggregateChildKindSet() & mask) != 0;
    }

    public String toString() {
        StringBuilder $this$toString_u24lambda_u2415 = new StringBuilder();
        $this$toString_u24lambda_u2415.append("[");
        if (this.head == this.tail) {
            $this$toString_u24lambda_u2415.append("]");
        } else {
            Modifier.Node node$iv = getHead$ui_release();
            while (true) {
                if (node$iv == null || node$iv == getTail$ui_release()) {
                    break;
                }
                Modifier.Node it = node$iv;
                $this$toString_u24lambda_u2415.append(String.valueOf(it));
                if (it.getChild$ui_release() == this.tail) {
                    $this$toString_u24lambda_u2415.append("]");
                    break;
                }
                $this$toString_u24lambda_u2415.append(",");
                node$iv = node$iv.getChild$ui_release();
            }
        }
        String sb = $this$toString_u24lambda_u2415.toString();
        Intrinsics.checkNotNullExpressionValue(sb, "StringBuilder().apply(builderAction).toString()");
        return sb;
    }
}
