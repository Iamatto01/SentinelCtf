package androidx.compose.material3;

import androidx.compose.runtime.MutableState;
import androidx.compose.runtime.SnapshotStateKt__SnapshotStateKt;
import androidx.compose.runtime.State;
import java.util.Arrays;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: Slider.kt */
@ExperimentalMaterial3Api
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0007\n\u0000\n\u0002\u0010\u0014\n\u0002\b\u0010\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\u0015\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005¢\u0006\u0002\u0010\u0006J\u0013\u0010\u0015\u001a\u00020\u00162\b\u0010\u0017\u001a\u0004\u0018\u00010\u0001H\u0096\u0002J\b\u0010\u0018\u001a\u00020\u0019H\u0016R+\u0010\b\u001a\u00020\u00032\u0006\u0010\u0007\u001a\u00020\u00038F@@X\u0086\u008e\u0002¢\u0006\u0012\n\u0004\b\r\u0010\u000e\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\fR+\u0010\u000f\u001a\u00020\u00052\u0006\u0010\u0007\u001a\u00020\u00058F@@X\u0086\u008e\u0002¢\u0006\u0012\n\u0004\b\u0014\u0010\u000e\u001a\u0004\b\u0010\u0010\u0011\"\u0004\b\u0012\u0010\u0013¨\u0006\u001a"}, d2 = {"Landroidx/compose/material3/SliderPositions;", "", "initialPositionFraction", "", "initialTickFractions", "", "(F[F)V", "<set-?>", "positionFraction", "getPositionFraction", "()F", "setPositionFraction$material3_release", "(F)V", "positionFraction$delegate", "Landroidx/compose/runtime/MutableState;", "tickFractions", "getTickFractions", "()[F", "setTickFractions$material3_release", "([F)V", "tickFractions$delegate", "equals", "", "other", "hashCode", "", "material3_release"}, k = 1, mv = {1, 7, 1}, xi = 48)
/* loaded from: classes.dex */
public final class SliderPositions {
    private final MutableState positionFraction$delegate;
    private final MutableState tickFractions$delegate;

    public SliderPositions(float initialPositionFraction, float[] initialTickFractions) {
        MutableState mutableStateOf$default;
        MutableState mutableStateOf$default2;
        Intrinsics.checkNotNullParameter(initialTickFractions, "initialTickFractions");
        mutableStateOf$default = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(Float.valueOf(initialPositionFraction), null, 2, null);
        this.positionFraction$delegate = mutableStateOf$default;
        mutableStateOf$default2 = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(initialTickFractions, null, 2, null);
        this.tickFractions$delegate = mutableStateOf$default2;
    }

    public final float getPositionFraction() {
        State $this$getValue$iv = this.positionFraction$delegate;
        return ((Number) $this$getValue$iv.getValue()).floatValue();
    }

    public final void setPositionFraction$material3_release(float f) {
        MutableState $this$setValue$iv = this.positionFraction$delegate;
        $this$setValue$iv.setValue(Float.valueOf(f));
    }

    public final float[] getTickFractions() {
        State $this$getValue$iv = this.tickFractions$delegate;
        return (float[]) $this$getValue$iv.getValue();
    }

    public final void setTickFractions$material3_release(float[] fArr) {
        Intrinsics.checkNotNullParameter(fArr, "<set-?>");
        MutableState $this$setValue$iv = this.tickFractions$delegate;
        $this$setValue$iv.setValue(fArr);
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other instanceof SliderPositions) {
            return ((getPositionFraction() > ((SliderPositions) other).getPositionFraction() ? 1 : (getPositionFraction() == ((SliderPositions) other).getPositionFraction() ? 0 : -1)) == 0) && Arrays.equals(getTickFractions(), ((SliderPositions) other).getTickFractions());
        }
        return false;
    }

    public int hashCode() {
        int result = Float.hashCode(getPositionFraction());
        return (result * 31) + Arrays.hashCode(getTickFractions());
    }
}
