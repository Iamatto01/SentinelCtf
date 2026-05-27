package androidx.compose.ui.input.rotary;

import androidx.compose.ui.node.ModifierNodeElement;
import androidx.compose.ui.platform.InspectorInfo;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: RotaryInputModifierNode.kt */
@Metadata(d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\b\b\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\b\u0080\b\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B\u0019\u0012\u0012\u0010\u0003\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004¢\u0006\u0002\u0010\u0007J\u0015\u0010\n\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004HÆ\u0003J\u001f\u0010\u000b\u001a\u00020\u00002\u0014\b\u0002\u0010\u0003\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004HÆ\u0001J\b\u0010\f\u001a\u00020\u0002H\u0016J\u0013\u0010\r\u001a\u00020\u00062\b\u0010\u000e\u001a\u0004\u0018\u00010\u000fHÖ\u0003J\t\u0010\u0010\u001a\u00020\u0011HÖ\u0001J\t\u0010\u0012\u001a\u00020\u0013HÖ\u0001J\u0010\u0010\u0014\u001a\u00020\u00022\u0006\u0010\u0015\u001a\u00020\u0002H\u0016J\f\u0010\u0016\u001a\u00020\u0017*\u00020\u0018H\u0016R\u001d\u0010\u0003\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004¢\u0006\b\n\u0000\u001a\u0004\b\b\u0010\t¨\u0006\u0019"}, d2 = {"Landroidx/compose/ui/input/rotary/OnPreRotaryScrollEventElement;", "Landroidx/compose/ui/node/ModifierNodeElement;", "Landroidx/compose/ui/input/rotary/RotaryInputModifierNodeImpl;", "onPreRotaryScrollEvent", "Lkotlin/Function1;", "Landroidx/compose/ui/input/rotary/RotaryScrollEvent;", "", "(Lkotlin/jvm/functions/Function1;)V", "getOnPreRotaryScrollEvent", "()Lkotlin/jvm/functions/Function1;", "component1", "copy", "create", "equals", "other", "", "hashCode", "", "toString", "", "update", "node", "inspectableProperties", "", "Landroidx/compose/ui/platform/InspectorInfo;", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class OnPreRotaryScrollEventElement extends ModifierNodeElement<RotaryInputModifierNodeImpl> {
    private final Function1<RotaryScrollEvent, Boolean> onPreRotaryScrollEvent;

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ OnPreRotaryScrollEventElement copy$default(OnPreRotaryScrollEventElement onPreRotaryScrollEventElement, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            function1 = onPreRotaryScrollEventElement.onPreRotaryScrollEvent;
        }
        return onPreRotaryScrollEventElement.copy(function1);
    }

    public final Function1<RotaryScrollEvent, Boolean> component1() {
        return this.onPreRotaryScrollEvent;
    }

    public final OnPreRotaryScrollEventElement copy(Function1<? super RotaryScrollEvent, Boolean> onPreRotaryScrollEvent) {
        Intrinsics.checkNotNullParameter(onPreRotaryScrollEvent, "onPreRotaryScrollEvent");
        return new OnPreRotaryScrollEventElement(onPreRotaryScrollEvent);
    }

    @Override // androidx.compose.ui.node.ModifierNodeElement
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof OnPreRotaryScrollEventElement) && Intrinsics.areEqual(this.onPreRotaryScrollEvent, ((OnPreRotaryScrollEventElement) obj).onPreRotaryScrollEvent);
    }

    @Override // androidx.compose.ui.node.ModifierNodeElement
    public int hashCode() {
        return this.onPreRotaryScrollEvent.hashCode();
    }

    public String toString() {
        return "OnPreRotaryScrollEventElement(onPreRotaryScrollEvent=" + this.onPreRotaryScrollEvent + ')';
    }

    public final Function1<RotaryScrollEvent, Boolean> getOnPreRotaryScrollEvent() {
        return this.onPreRotaryScrollEvent;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public OnPreRotaryScrollEventElement(Function1<? super RotaryScrollEvent, Boolean> onPreRotaryScrollEvent) {
        Intrinsics.checkNotNullParameter(onPreRotaryScrollEvent, "onPreRotaryScrollEvent");
        this.onPreRotaryScrollEvent = onPreRotaryScrollEvent;
    }

    @Override // androidx.compose.ui.node.ModifierNodeElement
    public RotaryInputModifierNodeImpl create() {
        return new RotaryInputModifierNodeImpl(null, this.onPreRotaryScrollEvent);
    }

    @Override // androidx.compose.ui.node.ModifierNodeElement
    public RotaryInputModifierNodeImpl update(RotaryInputModifierNodeImpl node) {
        Intrinsics.checkNotNullParameter(node, "node");
        node.setOnPreEvent(this.onPreRotaryScrollEvent);
        node.setOnEvent(null);
        return node;
    }

    @Override // androidx.compose.ui.node.ModifierNodeElement
    public void inspectableProperties(InspectorInfo $this$inspectableProperties) {
        Intrinsics.checkNotNullParameter($this$inspectableProperties, "<this>");
        $this$inspectableProperties.setName("onPreRotaryScrollEvent");
        $this$inspectableProperties.getProperties().set("onPreRotaryScrollEvent", this.onPreRotaryScrollEvent);
    }
}
