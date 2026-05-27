package androidx.compose.ui.input.pointer.util;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: VelocityTracker.kt */
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0011\n\u0002\u0010\u0007\n\u0002\b\t\n\u0002\u0010\u0002\n\u0002\b\u0004\b\u0002\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0011\u0010\r\u001a\u00020\u00072\u0006\u0010\u000e\u001a\u00020\u0003H\u0086\u0002J\u0006\u0010\u000f\u001a\u00020\u0007J\u0019\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u000e\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u0007H\u0086\u0002J\u0011\u0010\u0013\u001a\u00020\u00072\u0006\u0010\u0014\u001a\u00020\u0000H\u0086\u0002R\u0019\u0010\u0005\u001a\b\u0012\u0004\u0012\u00020\u00070\u0006¢\u0006\n\n\u0002\u0010\n\u001a\u0004\b\b\u0010\tR\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u000b\u0010\f¨\u0006\u0015"}, d2 = {"Landroidx/compose/ui/input/pointer/util/Vector;", "", "length", "", "(I)V", "elements", "", "", "getElements", "()[Ljava/lang/Float;", "[Ljava/lang/Float;", "getLength", "()I", "get", "i", "norm", "set", "", "value", "times", "a", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
final class Vector {
    private final Float[] elements;
    private final int length;

    public Vector(int length) {
        this.length = length;
        Float[] fArr = new Float[length];
        for (int i = 0; i < length; i++) {
            fArr[i] = Float.valueOf(0.0f);
        }
        this.elements = fArr;
    }

    public final int getLength() {
        return this.length;
    }

    public final Float[] getElements() {
        return this.elements;
    }

    public final float get(int i) {
        return this.elements[i].floatValue();
    }

    public final void set(int i, float value) {
        this.elements[i] = Float.valueOf(value);
    }

    public final float times(Vector a) {
        Intrinsics.checkNotNullParameter(a, "a");
        float result = 0.0f;
        int i = this.length;
        for (int i2 = 0; i2 < i; i2++) {
            result += get(i2) * a.get(i2);
        }
        return result;
    }

    public final float norm() {
        return (float) Math.sqrt(times(this));
    }
}
