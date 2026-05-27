package androidx.compose.ui.input.pointer;

import android.view.MotionEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: PointerEvent.android.kt */
@Metadata(d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\t\b\u0007\u0018\u00002\u00020\u0001B\u0015\b\u0016\u0012\f\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003¢\u0006\u0002\u0010\u0005B\u001f\b\u0000\u0012\f\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003\u0012\b\u0010\u0006\u001a\u0004\u0018\u00010\u0007¢\u0006\u0002\u0010\bJ\u0018\u0010\u001f\u001a\u00020\u001aH\u0002ø\u0001\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b \u0010\fJ\f\u0010!\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003J\u001e\u0010\"\u001a\u00020\u00002\f\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u00032\b\u0010\u0015\u001a\u0004\u0018\u00010\u0016R\u001c\u0010\t\u001a\u00020\nø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010\r\u001a\u0004\b\u000b\u0010\fR\u0017\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u000e\u0010\u000fR\u0016\u0010\u0006\u001a\u0004\u0018\u00010\u0007X\u0080\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0010\u0010\u0011R\u001c\u0010\u0012\u001a\u00020\u0013ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010\r\u001a\u0004\b\u0014\u0010\fR\u0016\u0010\u0015\u001a\u0004\u0018\u00010\u00168@X\u0080\u0004¢\u0006\u0006\u001a\u0004\b\u0017\u0010\u0018R/\u0010\u001b\u001a\u00020\u001a2\u0006\u0010\u0019\u001a\u00020\u001a@@X\u0086\u000eø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0010\n\u0002\u0010\r\u001a\u0004\b\u001c\u0010\f\"\u0004\b\u001d\u0010\u001e\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u0006#"}, d2 = {"Landroidx/compose/ui/input/pointer/PointerEvent;", "", "changes", "", "Landroidx/compose/ui/input/pointer/PointerInputChange;", "(Ljava/util/List;)V", "internalPointerEvent", "Landroidx/compose/ui/input/pointer/InternalPointerEvent;", "(Ljava/util/List;Landroidx/compose/ui/input/pointer/InternalPointerEvent;)V", "buttons", "Landroidx/compose/ui/input/pointer/PointerButtons;", "getButtons-ry648PA", "()I", "I", "getChanges", "()Ljava/util/List;", "getInternalPointerEvent$ui_release", "()Landroidx/compose/ui/input/pointer/InternalPointerEvent;", "keyboardModifiers", "Landroidx/compose/ui/input/pointer/PointerKeyboardModifiers;", "getKeyboardModifiers-k7X9c1A", "motionEvent", "Landroid/view/MotionEvent;", "getMotionEvent$ui_release", "()Landroid/view/MotionEvent;", "<set-?>", "Landroidx/compose/ui/input/pointer/PointerEventType;", "type", "getType-7fucELk", "setType-EhbLWgg$ui_release", "(I)V", "calculatePointerEventType", "calculatePointerEventType-7fucELk", "component1", "copy", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class PointerEvent {
    public static final int $stable = 8;
    private final int buttons;
    private final List<PointerInputChange> changes;
    private final InternalPointerEvent internalPointerEvent;
    private final int keyboardModifiers;
    private int type;

    public PointerEvent(List<PointerInputChange> changes, InternalPointerEvent internalPointerEvent) {
        Intrinsics.checkNotNullParameter(changes, "changes");
        this.changes = changes;
        this.internalPointerEvent = internalPointerEvent;
        MotionEvent motionEvent$ui_release = getMotionEvent$ui_release();
        this.buttons = PointerButtons.m3943constructorimpl(motionEvent$ui_release != null ? motionEvent$ui_release.getButtonState() : 0);
        MotionEvent motionEvent$ui_release2 = getMotionEvent$ui_release();
        this.keyboardModifiers = PointerKeyboardModifiers.m4069constructorimpl(motionEvent$ui_release2 != null ? motionEvent$ui_release2.getMetaState() : 0);
        this.type = m3949calculatePointerEventType7fucELk();
    }

    public final List<PointerInputChange> getChanges() {
        return this.changes;
    }

    public final InternalPointerEvent getInternalPointerEvent$ui_release() {
        return this.internalPointerEvent;
    }

    public final MotionEvent getMotionEvent$ui_release() {
        InternalPointerEvent internalPointerEvent = this.internalPointerEvent;
        if (internalPointerEvent != null) {
            return internalPointerEvent.getMotionEvent();
        }
        return null;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public PointerEvent(List<PointerInputChange> changes) {
        this(changes, null);
        Intrinsics.checkNotNullParameter(changes, "changes");
    }

    /* renamed from: getButtons-ry648PA  reason: not valid java name */
    public final int m3950getButtonsry648PA() {
        return this.buttons;
    }

    /* renamed from: getKeyboardModifiers-k7X9c1A  reason: not valid java name */
    public final int m3951getKeyboardModifiersk7X9c1A() {
        return this.keyboardModifiers;
    }

    /* renamed from: getType-7fucELk  reason: not valid java name */
    public final int m3952getType7fucELk() {
        return this.type;
    }

    /* renamed from: setType-EhbLWgg$ui_release  reason: not valid java name */
    public final void m3953setTypeEhbLWgg$ui_release(int i) {
        this.type = i;
    }

    /* renamed from: calculatePointerEventType-7fucELk  reason: not valid java name */
    private final int m3949calculatePointerEventType7fucELk() {
        MotionEvent motionEvent = getMotionEvent$ui_release();
        if (motionEvent != null) {
            switch (motionEvent.getActionMasked()) {
                case 0:
                case 5:
                    return PointerEventType.Companion.m3966getPress7fucELk();
                case 1:
                case 6:
                    return PointerEventType.Companion.m3967getRelease7fucELk();
                case 2:
                case 7:
                    return PointerEventType.Companion.m3965getMove7fucELk();
                case 3:
                case 4:
                default:
                    return PointerEventType.Companion.m3969getUnknown7fucELk();
                case 8:
                    return PointerEventType.Companion.m3968getScroll7fucELk();
                case 9:
                    return PointerEventType.Companion.m3963getEnter7fucELk();
                case 10:
                    return PointerEventType.Companion.m3964getExit7fucELk();
            }
        }
        List $this$fastForEach$iv = this.changes;
        int size = $this$fastForEach$iv.size();
        for (int index$iv = 0; index$iv < size; index$iv++) {
            Object item$iv = $this$fastForEach$iv.get(index$iv);
            PointerInputChange it = (PointerInputChange) item$iv;
            if (PointerEventKt.changedToUpIgnoreConsumed(it)) {
                return PointerEventType.Companion.m3967getRelease7fucELk();
            }
            if (PointerEventKt.changedToDownIgnoreConsumed(it)) {
                return PointerEventType.Companion.m3966getPress7fucELk();
            }
        }
        return PointerEventType.Companion.m3965getMove7fucELk();
    }

    public final List<PointerInputChange> component1() {
        return this.changes;
    }

    public final PointerEvent copy(List<PointerInputChange> changes, MotionEvent motionEvent) {
        List $this$fastForEach$iv$iv;
        boolean z;
        boolean z2;
        Intrinsics.checkNotNullParameter(changes, "changes");
        if (motionEvent == null) {
            return new PointerEvent(changes, null);
        }
        if (Intrinsics.areEqual(motionEvent, getMotionEvent$ui_release())) {
            return new PointerEvent(changes, this.internalPointerEvent);
        }
        Map map = new LinkedHashMap();
        int size = changes.size();
        for (int index$iv = 0; index$iv < size; index$iv++) {
            Object item$iv = changes.get(index$iv);
            PointerInputChange change = (PointerInputChange) item$iv;
            map.put(PointerId.m3989boximpl(change.m4006getIdJ3iCeTQ()), change);
        }
        List $this$fastMap$iv = changes;
        boolean z3 = false;
        List target$iv = new ArrayList($this$fastMap$iv.size());
        List $this$fastForEach$iv$iv2 = $this$fastMap$iv;
        boolean z4 = false;
        int index$iv$iv = 0;
        int size2 = $this$fastForEach$iv$iv2.size();
        while (index$iv$iv < size2) {
            Object item$iv$iv = $this$fastForEach$iv$iv2.get(index$iv$iv);
            List list = target$iv;
            PointerInputChange it = (PointerInputChange) item$iv$iv;
            List $this$fastMap$iv2 = $this$fastMap$iv;
            long m4006getIdJ3iCeTQ = it.m4006getIdJ3iCeTQ();
            long uptimeMillis = it.getUptimeMillis();
            long m4007getPositionF1C5BW0 = it.m4007getPositionF1C5BW0();
            long m4007getPositionF1C5BW02 = it.m4007getPositionF1C5BW0();
            boolean pressed = it.getPressed();
            float pressure = it.getPressure();
            int m4010getTypeT8wyACA = it.m4010getTypeT8wyACA();
            boolean z5 = z3;
            InternalPointerEvent internalPointerEvent = this.internalPointerEvent;
            if (internalPointerEvent != null) {
                $this$fastForEach$iv$iv = $this$fastForEach$iv$iv2;
                z = z4;
                if (internalPointerEvent.m3939issuesEnterExitEvent0FcD4WY(it.m4006getIdJ3iCeTQ())) {
                    z2 = true;
                    list.add(new PointerInputEventData(m4006getIdJ3iCeTQ, uptimeMillis, m4007getPositionF1C5BW0, m4007getPositionF1C5BW02, pressed, pressure, m4010getTypeT8wyACA, z2, null, 0L, 768, null));
                    index$iv$iv++;
                    $this$fastMap$iv = $this$fastMap$iv2;
                    z3 = z5;
                    $this$fastForEach$iv$iv2 = $this$fastForEach$iv$iv;
                    z4 = z;
                }
            } else {
                $this$fastForEach$iv$iv = $this$fastForEach$iv$iv2;
                z = z4;
            }
            z2 = false;
            list.add(new PointerInputEventData(m4006getIdJ3iCeTQ, uptimeMillis, m4007getPositionF1C5BW0, m4007getPositionF1C5BW02, pressed, pressure, m4010getTypeT8wyACA, z2, null, 0L, 768, null));
            index$iv$iv++;
            $this$fastMap$iv = $this$fastMap$iv2;
            z3 = z5;
            $this$fastForEach$iv$iv2 = $this$fastForEach$iv$iv;
            z4 = z;
        }
        List pointerEventData = target$iv;
        PointerInputEvent pointerInputEvent = new PointerInputEvent(motionEvent.getEventTime(), pointerEventData, motionEvent);
        InternalPointerEvent event = new InternalPointerEvent(map, pointerInputEvent);
        return new PointerEvent(changes, event);
    }
}
