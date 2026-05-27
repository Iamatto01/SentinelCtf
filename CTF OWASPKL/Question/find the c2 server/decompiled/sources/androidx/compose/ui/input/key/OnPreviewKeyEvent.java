package androidx.compose.ui.input.key;

import androidx.compose.ui.node.ModifierNodeElement;
import androidx.compose.ui.platform.InspectorInfo;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: KeyInputModifierNode.kt */
@Metadata(d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\b\b\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\b\u0080\b\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B\u001c\u0012\u0012\u0010\u0003\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004ø\u0001\u0000¢\u0006\u0002\u0010\u0007J\u0018\u0010\n\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004HÆ\u0003ø\u0001\u0000J\"\u0010\u000b\u001a\u00020\u00002\u0014\b\u0002\u0010\u0003\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004HÆ\u0001ø\u0001\u0000J\b\u0010\f\u001a\u00020\u0002H\u0016J\u0013\u0010\r\u001a\u00020\u00062\b\u0010\u000e\u001a\u0004\u0018\u00010\u000fHÖ\u0003J\t\u0010\u0010\u001a\u00020\u0011HÖ\u0001J\t\u0010\u0012\u001a\u00020\u0013HÖ\u0001J\u0010\u0010\u0014\u001a\u00020\u00022\u0006\u0010\u0015\u001a\u00020\u0002H\u0016J\f\u0010\u0016\u001a\u00020\u0017*\u00020\u0018H\u0016R \u0010\u0003\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004ø\u0001\u0000¢\u0006\b\n\u0000\u001a\u0004\b\b\u0010\t\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\u0019"}, d2 = {"Landroidx/compose/ui/input/key/OnPreviewKeyEvent;", "Landroidx/compose/ui/node/ModifierNodeElement;", "Landroidx/compose/ui/input/key/KeyInputInputModifierNodeImpl;", "onPreviewKeyEvent", "Lkotlin/Function1;", "Landroidx/compose/ui/input/key/KeyEvent;", "", "(Lkotlin/jvm/functions/Function1;)V", "getOnPreviewKeyEvent", "()Lkotlin/jvm/functions/Function1;", "component1", "copy", "create", "equals", "other", "", "hashCode", "", "toString", "", "update", "node", "inspectableProperties", "", "Landroidx/compose/ui/platform/InspectorInfo;", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class OnPreviewKeyEvent extends ModifierNodeElement<KeyInputInputModifierNodeImpl> {
    private final Function1<KeyEvent, Boolean> onPreviewKeyEvent;

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ OnPreviewKeyEvent copy$default(OnPreviewKeyEvent onPreviewKeyEvent, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            function1 = onPreviewKeyEvent.onPreviewKeyEvent;
        }
        return onPreviewKeyEvent.copy(function1);
    }

    public final Function1<KeyEvent, Boolean> component1() {
        return this.onPreviewKeyEvent;
    }

    public final OnPreviewKeyEvent copy(Function1<? super KeyEvent, Boolean> onPreviewKeyEvent) {
        Intrinsics.checkNotNullParameter(onPreviewKeyEvent, "onPreviewKeyEvent");
        return new OnPreviewKeyEvent(onPreviewKeyEvent);
    }

    @Override // androidx.compose.ui.node.ModifierNodeElement
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof OnPreviewKeyEvent) && Intrinsics.areEqual(this.onPreviewKeyEvent, ((OnPreviewKeyEvent) obj).onPreviewKeyEvent);
    }

    @Override // androidx.compose.ui.node.ModifierNodeElement
    public int hashCode() {
        return this.onPreviewKeyEvent.hashCode();
    }

    public String toString() {
        return "OnPreviewKeyEvent(onPreviewKeyEvent=" + this.onPreviewKeyEvent + ')';
    }

    public final Function1<KeyEvent, Boolean> getOnPreviewKeyEvent() {
        return this.onPreviewKeyEvent;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public OnPreviewKeyEvent(Function1<? super KeyEvent, Boolean> onPreviewKeyEvent) {
        Intrinsics.checkNotNullParameter(onPreviewKeyEvent, "onPreviewKeyEvent");
        this.onPreviewKeyEvent = onPreviewKeyEvent;
    }

    @Override // androidx.compose.ui.node.ModifierNodeElement
    public KeyInputInputModifierNodeImpl create() {
        return new KeyInputInputModifierNodeImpl(null, this.onPreviewKeyEvent);
    }

    @Override // androidx.compose.ui.node.ModifierNodeElement
    public KeyInputInputModifierNodeImpl update(KeyInputInputModifierNodeImpl node) {
        Intrinsics.checkNotNullParameter(node, "node");
        node.setOnPreEvent(this.onPreviewKeyEvent);
        node.setOnEvent(null);
        return node;
    }

    @Override // androidx.compose.ui.node.ModifierNodeElement
    public void inspectableProperties(InspectorInfo $this$inspectableProperties) {
        Intrinsics.checkNotNullParameter($this$inspectableProperties, "<this>");
        $this$inspectableProperties.setName("onPreviewKeyEvent");
        $this$inspectableProperties.getProperties().set("onPreviewKeyEvent", this.onPreviewKeyEvent);
    }
}
