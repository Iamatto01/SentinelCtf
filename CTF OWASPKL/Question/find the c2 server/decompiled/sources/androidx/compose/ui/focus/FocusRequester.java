package androidx.compose.ui.focus;

import androidx.compose.runtime.collection.MutableVector;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.node.DelegatableNode;
import androidx.compose.ui.node.DelegatableNodeKt;
import androidx.compose.ui.node.NodeKind;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: FocusRequester.kt */
@Metadata(d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0002\b\u0007\u0018\u0000 \u00132\u00020\u0001:\u0001\u0013B\u0005¢\u0006\u0002\u0010\u0002J\u0006\u0010\t\u001a\u00020\nJ!\u0010\u000b\u001a\u00020\n2\u0012\u0010\f\u001a\u000e\u0012\u0004\u0012\u00020\u000e\u0012\u0004\u0012\u00020\n0\rH\u0000¢\u0006\u0002\b\u000fJ\u0006\u0010\u0010\u001a\u00020\nJ\u0006\u0010\u0011\u001a\u00020\u0012R \u0010\u0003\u001a\b\u0012\u0004\u0012\u00020\u00050\u0004X\u0080\u0004¢\u0006\u000e\n\u0000\u0012\u0004\b\u0006\u0010\u0002\u001a\u0004\b\u0007\u0010\b¨\u0006\u0014"}, d2 = {"Landroidx/compose/ui/focus/FocusRequester;", "", "()V", "focusRequesterNodes", "Landroidx/compose/runtime/collection/MutableVector;", "Landroidx/compose/ui/focus/FocusRequesterModifierNode;", "getFocusRequesterNodes$ui_release$annotations", "getFocusRequesterNodes$ui_release", "()Landroidx/compose/runtime/collection/MutableVector;", "captureFocus", "", "findFocusTarget", "onFound", "Lkotlin/Function1;", "Landroidx/compose/ui/focus/FocusTargetModifierNode;", "findFocusTarget$ui_release", "freeFocus", "requestFocus", "", "Companion", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class FocusRequester {
    public static final int $stable = 0;
    private final MutableVector<FocusRequesterModifierNode> focusRequesterNodes = new MutableVector<>(new FocusRequesterModifierNode[16], 0);
    public static final Companion Companion = new Companion(null);
    private static final FocusRequester Default = new FocusRequester();
    private static final FocusRequester Cancel = new FocusRequester();

    public static /* synthetic */ void getFocusRequesterNodes$ui_release$annotations() {
    }

    public final MutableVector<FocusRequesterModifierNode> getFocusRequesterNodes$ui_release() {
        return this.focusRequesterNodes;
    }

    public final void requestFocus() {
        findFocusTarget$ui_release(new Function1<FocusTargetModifierNode, Boolean>() { // from class: androidx.compose.ui.focus.FocusRequester$requestFocus$1
            @Override // kotlin.jvm.functions.Function1
            public final Boolean invoke(FocusTargetModifierNode it) {
                Intrinsics.checkNotNullParameter(it, "it");
                return Boolean.valueOf(FocusTransactionsKt.requestFocus(it));
            }
        });
    }

    public final boolean findFocusTarget$ui_release(Function1<? super FocusTargetModifierNode, Boolean> onFound) {
        Intrinsics.checkNotNullParameter(onFound, "onFound");
        if (!Intrinsics.areEqual(this, Default)) {
            if (!Intrinsics.areEqual(this, Cancel)) {
                if (this.focusRequesterNodes.isNotEmpty()) {
                    boolean success = false;
                    MutableVector this_$iv = this.focusRequesterNodes;
                    int size$iv = this_$iv.getSize();
                    if (size$iv > 0) {
                        int i$iv = 0;
                        Object[] content$iv = this_$iv.getContent();
                        while (true) {
                            DelegatableNode node = (FocusRequesterModifierNode) content$iv[i$iv];
                            DelegatableNode $this$visitChildren_u2d6rFNWt0$iv = node;
                            int m4327constructorimpl = NodeKind.m4327constructorimpl(1024);
                            if (!$this$visitChildren_u2d6rFNWt0$iv.getNode().isAttached()) {
                                throw new IllegalStateException("Check failed.".toString());
                            }
                            boolean success2 = success;
                            MutableVector this_$iv2 = this_$iv;
                            MutableVector branches$iv$iv = new MutableVector(new Modifier.Node[16], 0);
                            Modifier.Node child$iv$iv = $this$visitChildren_u2d6rFNWt0$iv.getNode().getChild$ui_release();
                            if (child$iv$iv == null) {
                                DelegatableNodeKt.access$addLayoutNodeChildren(branches$iv$iv, $this$visitChildren_u2d6rFNWt0$iv.getNode());
                            } else {
                                branches$iv$iv.add(child$iv$iv);
                            }
                            while (true) {
                                if (!branches$iv$iv.isNotEmpty()) {
                                    success = success2;
                                    break;
                                }
                                MutableVector this_$iv$iv$iv = branches$iv$iv;
                                Modifier.Node branch$iv$iv = (Modifier.Node) branches$iv$iv.removeAt(this_$iv$iv$iv.getSize() - 1);
                                if ((branch$iv$iv.getAggregateChildKindSet$ui_release() & m4327constructorimpl) == 0) {
                                    DelegatableNodeKt.access$addLayoutNodeChildren(branches$iv$iv, branch$iv$iv);
                                } else {
                                    Modifier.Node node$iv$iv = branch$iv$iv;
                                    while (true) {
                                        if (node$iv$iv == null) {
                                            break;
                                        } else if ((node$iv$iv.getKindSet$ui_release() & m4327constructorimpl) != 0) {
                                            Modifier.Node it$iv = node$iv$iv;
                                            MutableVector branches$iv$iv2 = branches$iv$iv;
                                            Modifier.Node it$iv2 = child$iv$iv;
                                            if (it$iv instanceof FocusTargetModifierNode) {
                                                FocusTargetModifierNode it = (FocusTargetModifierNode) it$iv;
                                                if (onFound.invoke(it).booleanValue()) {
                                                    success = true;
                                                    break;
                                                }
                                            }
                                            child$iv$iv = it$iv2;
                                            branches$iv$iv = branches$iv$iv2;
                                        } else {
                                            node$iv$iv = node$iv$iv.getChild$ui_release();
                                        }
                                    }
                                }
                            }
                            i$iv++;
                            if (i$iv >= size$iv) {
                                break;
                            }
                            this_$iv = this_$iv2;
                        }
                    }
                    return success;
                }
                throw new IllegalStateException("\n   FocusRequester is not initialized. Here are some possible fixes:\n\n   1. Remember the FocusRequester: val focusRequester = remember { FocusRequester() }\n   2. Did you forget to add a Modifier.focusRequester() ?\n   3. Are you attempting to request focus during composition? Focus requests should be made in\n   response to some event. Eg Modifier.clickable { focusRequester.requestFocus() }\n".toString());
            }
            throw new IllegalStateException("\n    Please check whether the focusRequester is FocusRequester.Cancel or FocusRequester.Default\n    before invoking any functions on the focusRequester.\n".toString());
        }
        throw new IllegalStateException("\n    Please check whether the focusRequester is FocusRequester.Cancel or FocusRequester.Default\n    before invoking any functions on the focusRequester.\n".toString());
    }

    /* JADX WARN: Incorrect condition in loop: B:8:0x0020 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean captureFocus() {
        /*
            r8 = this;
            androidx.compose.runtime.collection.MutableVector<androidx.compose.ui.focus.FocusRequesterModifierNode> r0 = r8.focusRequesterNodes
            boolean r0 = r0.isNotEmpty()
            if (r0 == 0) goto L2d
            androidx.compose.runtime.collection.MutableVector<androidx.compose.ui.focus.FocusRequesterModifierNode> r0 = r8.focusRequesterNodes
            r1 = 0
            int r2 = r0.getSize()
            if (r2 <= 0) goto L2a
            r3 = 0
            java.lang.Object[] r4 = r0.getContent()
        L17:
            r5 = r4[r3]
            androidx.compose.ui.focus.FocusRequesterModifierNode r5 = (androidx.compose.ui.focus.FocusRequesterModifierNode) r5
            r6 = 0
            boolean r7 = androidx.compose.ui.focus.FocusRequesterModifierNodeKt.captureFocus(r5)
            if (r7 == 0) goto L24
            r7 = 1
            return r7
        L24:
            int r3 = r3 + 1
            if (r3 < r2) goto L17
        L2a:
        L2b:
            r0 = 0
            return r0
        L2d:
            r0 = 0
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "\n   FocusRequester is not initialized. Here are some possible fixes:\n\n   1. Remember the FocusRequester: val focusRequester = remember { FocusRequester() }\n   2. Did you forget to add a Modifier.focusRequester() ?\n   3. Are you attempting to request focus during composition? Focus requests should be made in\n   response to some event. Eg Modifier.clickable { focusRequester.requestFocus() }\n"
            java.lang.String r1 = r1.toString()
            r0.<init>(r1)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.FocusRequester.captureFocus():boolean");
    }

    /* JADX WARN: Incorrect condition in loop: B:8:0x0020 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean freeFocus() {
        /*
            r8 = this;
            androidx.compose.runtime.collection.MutableVector<androidx.compose.ui.focus.FocusRequesterModifierNode> r0 = r8.focusRequesterNodes
            boolean r0 = r0.isNotEmpty()
            if (r0 == 0) goto L2d
            androidx.compose.runtime.collection.MutableVector<androidx.compose.ui.focus.FocusRequesterModifierNode> r0 = r8.focusRequesterNodes
            r1 = 0
            int r2 = r0.getSize()
            if (r2 <= 0) goto L2a
            r3 = 0
            java.lang.Object[] r4 = r0.getContent()
        L17:
            r5 = r4[r3]
            androidx.compose.ui.focus.FocusRequesterModifierNode r5 = (androidx.compose.ui.focus.FocusRequesterModifierNode) r5
            r6 = 0
            boolean r7 = androidx.compose.ui.focus.FocusRequesterModifierNodeKt.freeFocus(r5)
            if (r7 == 0) goto L24
            r7 = 1
            return r7
        L24:
            int r3 = r3 + 1
            if (r3 < r2) goto L17
        L2a:
        L2b:
            r0 = 0
            return r0
        L2d:
            r0 = 0
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "\n   FocusRequester is not initialized. Here are some possible fixes:\n\n   1. Remember the FocusRequester: val focusRequester = remember { FocusRequester() }\n   2. Did you forget to add a Modifier.focusRequester() ?\n   3. Are you attempting to request focus during composition? Focus requests should be made in\n   response to some event. Eg Modifier.clickable { focusRequester.requestFocus() }\n"
            java.lang.String r1 = r1.toString()
            r0.<init>(r1)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.FocusRequester.freeFocus():boolean");
    }

    /* compiled from: FocusRequester.kt */
    @Metadata(d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001:\u0001\fB\u0007\b\u0002¢\u0006\u0002\u0010\u0002J\b\u0010\n\u001a\u00020\u000bH\u0007R\u001c\u0010\u0003\u001a\u00020\u00048GX\u0087\u0004¢\u0006\u000e\n\u0000\u0012\u0004\b\u0005\u0010\u0002\u001a\u0004\b\u0006\u0010\u0007R\u0011\u0010\b\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\t\u0010\u0007¨\u0006\r"}, d2 = {"Landroidx/compose/ui/focus/FocusRequester$Companion;", "", "()V", "Cancel", "Landroidx/compose/ui/focus/FocusRequester;", "getCancel$annotations", "getCancel", "()Landroidx/compose/ui/focus/FocusRequester;", "Default", "getDefault", "createRefs", "Landroidx/compose/ui/focus/FocusRequester$Companion$FocusRequesterFactory;", "FocusRequesterFactory", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ void getCancel$annotations() {
        }

        private Companion() {
        }

        public final FocusRequester getDefault() {
            return FocusRequester.Default;
        }

        public final FocusRequester getCancel() {
            return FocusRequester.Cancel;
        }

        /* compiled from: FocusRequester.kt */
        @Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0010\bÇ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J\t\u0010\u0003\u001a\u00020\u0004H\u0086\u0002J\t\u0010\u0005\u001a\u00020\u0004H\u0086\u0002J\t\u0010\u0006\u001a\u00020\u0004H\u0086\u0002J\t\u0010\u0007\u001a\u00020\u0004H\u0086\u0002J\t\u0010\b\u001a\u00020\u0004H\u0086\u0002J\t\u0010\t\u001a\u00020\u0004H\u0086\u0002J\t\u0010\n\u001a\u00020\u0004H\u0086\u0002J\t\u0010\u000b\u001a\u00020\u0004H\u0086\u0002J\t\u0010\f\u001a\u00020\u0004H\u0086\u0002J\t\u0010\r\u001a\u00020\u0004H\u0086\u0002J\t\u0010\u000e\u001a\u00020\u0004H\u0086\u0002J\t\u0010\u000f\u001a\u00020\u0004H\u0086\u0002J\t\u0010\u0010\u001a\u00020\u0004H\u0086\u0002J\t\u0010\u0011\u001a\u00020\u0004H\u0086\u0002J\t\u0010\u0012\u001a\u00020\u0004H\u0086\u0002J\t\u0010\u0013\u001a\u00020\u0004H\u0086\u0002¨\u0006\u0014"}, d2 = {"Landroidx/compose/ui/focus/FocusRequester$Companion$FocusRequesterFactory;", "", "()V", "component1", "Landroidx/compose/ui/focus/FocusRequester;", "component10", "component11", "component12", "component13", "component14", "component15", "component16", "component2", "component3", "component4", "component5", "component6", "component7", "component8", "component9", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
        /* loaded from: classes.dex */
        public static final class FocusRequesterFactory {
            public static final int $stable = 0;
            public static final FocusRequesterFactory INSTANCE = new FocusRequesterFactory();

            private FocusRequesterFactory() {
            }

            public final FocusRequester component1() {
                return new FocusRequester();
            }

            public final FocusRequester component2() {
                return new FocusRequester();
            }

            public final FocusRequester component3() {
                return new FocusRequester();
            }

            public final FocusRequester component4() {
                return new FocusRequester();
            }

            public final FocusRequester component5() {
                return new FocusRequester();
            }

            public final FocusRequester component6() {
                return new FocusRequester();
            }

            public final FocusRequester component7() {
                return new FocusRequester();
            }

            public final FocusRequester component8() {
                return new FocusRequester();
            }

            public final FocusRequester component9() {
                return new FocusRequester();
            }

            public final FocusRequester component10() {
                return new FocusRequester();
            }

            public final FocusRequester component11() {
                return new FocusRequester();
            }

            public final FocusRequester component12() {
                return new FocusRequester();
            }

            public final FocusRequester component13() {
                return new FocusRequester();
            }

            public final FocusRequester component14() {
                return new FocusRequester();
            }

            public final FocusRequester component15() {
                return new FocusRequester();
            }

            public final FocusRequester component16() {
                return new FocusRequester();
            }
        }

        public final FocusRequesterFactory createRefs() {
            return FocusRequesterFactory.INSTANCE;
        }
    }
}
