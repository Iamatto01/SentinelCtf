package androidx.compose.ui.node;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: LayoutNode.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\u001a\u0014\u0010\u0002\u001a\u00020\u0003*\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u0004H\u0000\u001a\f\u0010\u0006\u001a\u00020\u0007*\u00020\u0004H\u0000\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000¨\u0006\b"}, d2 = {"DebugChanges", "", "add", "", "Landroidx/compose/ui/node/LayoutNode;", "child", "requireOwner", "Landroidx/compose/ui/node/Owner;", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LayoutNodeKt {
    private static final boolean DebugChanges = false;

    public static final Owner requireOwner(LayoutNode $this$requireOwner) {
        Intrinsics.checkNotNullParameter($this$requireOwner, "<this>");
        Owner owner = $this$requireOwner.getOwner$ui_release();
        if (owner == null) {
            throw new IllegalStateException("LayoutNode should be attached to an owner".toString());
        }
        return owner;
    }

    public static final void add(LayoutNode $this$add, LayoutNode child) {
        Intrinsics.checkNotNullParameter($this$add, "<this>");
        Intrinsics.checkNotNullParameter(child, "child");
        $this$add.insertAt$ui_release($this$add.getChildren$ui_release().size(), child);
    }
}
