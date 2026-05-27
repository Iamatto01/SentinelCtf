package androidx.compose.ui.input.pointer.util;

import androidx.compose.ui.geometry.Offset;
import androidx.compose.ui.input.pointer.HistoricalChange;
import androidx.compose.ui.input.pointer.PointerEventKt;
import androidx.compose.ui.input.pointer.PointerInputChange;
import androidx.core.app.NotificationCompat;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: VelocityTracker.kt */
@Metadata(d1 = {"\u0000B\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u0004\n\u0002\u0010 \n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0007\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0002\b\u0003\u001a,\u0010\u0006\u001a\u00020\u00032\f\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\u00030\b2\f\u0010\t\u001a\b\u0012\u0004\u0012\u00020\u00030\b2\u0006\u0010\n\u001a\u00020\u000bH\u0002\u001a\u0010\u0010\f\u001a\u00020\u00032\u0006\u0010\r\u001a\u00020\u0003H\u0002\u001a2\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\u00030\b2\f\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00030\b2\f\u0010\u0010\u001a\b\u0012\u0004\u0012\u00020\u00030\b2\u0006\u0010\u0011\u001a\u00020\u0001H\u0000\u001a\u0012\u0010\u0012\u001a\u00020\u0013*\u00020\u00142\u0006\u0010\u0015\u001a\u00020\u0016\u001a1\u0010\u0017\u001a\u00020\u0013*\n\u0012\u0006\u0012\u0004\u0018\u00010\u00190\u00182\u0006\u0010\u001a\u001a\u00020\u00012\u0006\u0010\t\u001a\u00020\u001b2\u0006\u0010\u001c\u001a\u00020\u0003H\u0002¢\u0006\u0002\u0010\u001d\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0002\u001a\u00020\u0003X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0004\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0005\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000¨\u0006\u001e"}, d2 = {"AssumePointerMoveStoppedMilliseconds", "", "DefaultWeight", "", "HistorySize", "HorizonMilliseconds", "calculateImpulseVelocity", "dataPoints", "", "time", "isDataDifferential", "", "kineticEnergyToVelocity", "kineticEnergy", "polyFitLeastSquares", "x", "y", "degree", "addPointerInputChange", "", "Landroidx/compose/ui/input/pointer/util/VelocityTracker;", NotificationCompat.CATEGORY_EVENT, "Landroidx/compose/ui/input/pointer/PointerInputChange;", "set", "", "Landroidx/compose/ui/input/pointer/util/DataPointAtTime;", "index", "", "dataPoint", "([Landroidx/compose/ui/input/pointer/util/DataPointAtTime;IJF)V", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class VelocityTrackerKt {
    private static final int AssumePointerMoveStoppedMilliseconds = 40;
    private static final float DefaultWeight = 1.0f;
    private static final int HistorySize = 20;
    private static final int HorizonMilliseconds = 100;

    /* JADX INFO: Access modifiers changed from: private */
    public static final void set(DataPointAtTime[] $this$set, int index, long time, float dataPoint) {
        DataPointAtTime currentEntry = $this$set[index];
        if (currentEntry == null) {
            $this$set[index] = new DataPointAtTime(time, dataPoint);
            return;
        }
        currentEntry.setTime(time);
        currentEntry.setDataPoint(dataPoint);
    }

    public static final void addPointerInputChange(VelocityTracker $this$addPointerInputChange, PointerInputChange event) {
        Intrinsics.checkNotNullParameter($this$addPointerInputChange, "<this>");
        Intrinsics.checkNotNullParameter(event, "event");
        if (PointerEventKt.changedToDownIgnoreConsumed(event)) {
            $this$addPointerInputChange.m4101setCurrentPointerPositionAccumulatork4lQ0M$ui_release(event.m4007getPositionF1C5BW0());
            $this$addPointerInputChange.resetTracking();
        }
        long previousPointerPosition = event.m4008getPreviousPositionF1C5BW0();
        List $this$fastForEach$iv = event.getHistorical();
        int index$iv = 0;
        int size = $this$fastForEach$iv.size();
        while (index$iv < size) {
            Object item$iv = $this$fastForEach$iv.get(index$iv);
            HistoricalChange it = (HistoricalChange) item$iv;
            long historicalDelta = Offset.m2372minusMKHz9U(it.m3937getPositionF1C5BW0(), previousPointerPosition);
            previousPointerPosition = it.m3937getPositionF1C5BW0();
            $this$addPointerInputChange.m4101setCurrentPointerPositionAccumulatork4lQ0M$ui_release(Offset.m2373plusMKHz9U($this$addPointerInputChange.m4100getCurrentPointerPositionAccumulatorF1C5BW0$ui_release(), historicalDelta));
            $this$addPointerInputChange.m4098addPositionUv8p0NA(it.getUptimeMillis(), $this$addPointerInputChange.m4100getCurrentPointerPositionAccumulatorF1C5BW0$ui_release());
            index$iv++;
            $this$fastForEach$iv = $this$fastForEach$iv;
        }
        long delta = Offset.m2372minusMKHz9U(event.m4007getPositionF1C5BW0(), previousPointerPosition);
        $this$addPointerInputChange.m4101setCurrentPointerPositionAccumulatork4lQ0M$ui_release(Offset.m2373plusMKHz9U($this$addPointerInputChange.m4100getCurrentPointerPositionAccumulatorF1C5BW0$ui_release(), delta));
        $this$addPointerInputChange.m4098addPositionUv8p0NA(event.getUptimeMillis(), $this$addPointerInputChange.m4100getCurrentPointerPositionAccumulatorF1C5BW0$ui_release());
    }

    public static final List<Float> polyFitLeastSquares(List<Float> x, List<Float> y, int degree) {
        int i;
        float f;
        Intrinsics.checkNotNullParameter(x, "x");
        Intrinsics.checkNotNullParameter(y, "y");
        if (degree < 1) {
            throw new IllegalArgumentException("The degree must be at positive integer");
        }
        if (x.size() != y.size()) {
            throw new IllegalArgumentException("x and y must be the same length");
        }
        if (x.isEmpty()) {
            throw new IllegalArgumentException("At least one point must be provided");
        }
        if (degree >= x.size()) {
            i = x.size() - 1;
        } else {
            i = degree;
        }
        int truncatedDegree = i;
        int i2 = degree + 1;
        ArrayList arrayList = new ArrayList(i2);
        for (int i3 = 0; i3 < i2; i3++) {
            arrayList.add(Float.valueOf(0.0f));
        }
        ArrayList coefficients = arrayList;
        int m = x.size();
        int n = truncatedDegree + 1;
        Matrix a = new Matrix(n, m);
        int h = 0;
        while (true) {
            f = 1.0f;
            if (h >= m) {
                break;
            }
            a.set(0, h, 1.0f);
            for (int i4 = 1; i4 < n; i4++) {
                a.set(i4, h, a.get(i4 - 1, h) * x.get(h).floatValue());
            }
            h++;
        }
        Matrix q = new Matrix(n, m);
        Matrix r = new Matrix(n, n);
        int j = 0;
        while (j < n) {
            for (int h2 = 0; h2 < m; h2++) {
                q.set(j, h2, a.get(j, h2));
            }
            for (int i5 = 0; i5 < j; i5++) {
                float dot = q.getRow(j).times(q.getRow(i5));
                for (int h3 = 0; h3 < m; h3++) {
                    q.set(j, h3, q.get(j, h3) - (q.get(i5, h3) * dot));
                }
            }
            float norm = q.getRow(j).norm();
            if (norm < 1.0E-6d) {
                throw new IllegalArgumentException("Vectors are linearly dependent or zero so no solution. TODO(shepshapard), actually determine what this means");
            }
            float inverseNorm = f / norm;
            for (int h4 = 0; h4 < m; h4++) {
                q.set(j, h4, q.get(j, h4) * inverseNorm);
            }
            int i6 = 0;
            while (i6 < n) {
                r.set(j, i6, i6 < j ? 0.0f : q.getRow(j).times(a.getRow(i6)));
                i6++;
            }
            j++;
            f = 1.0f;
        }
        Vector wy = new Vector(m);
        for (int h5 = 0; h5 < m; h5++) {
            wy.set(h5, y.get(h5).floatValue() * 1.0f);
        }
        for (int i7 = n - 1; -1 < i7; i7--) {
            coefficients.set(i7, Float.valueOf(q.getRow(i7).times(wy)));
            int j2 = n - 1;
            int i8 = i7 + 1;
            if (i8 <= j2) {
                while (true) {
                    coefficients.set(i7, Float.valueOf(((Number) coefficients.get(i7)).floatValue() - (r.get(i7, j2) * ((Number) coefficients.get(j2)).floatValue())));
                    if (j2 != i8) {
                        j2--;
                    }
                }
            }
            coefficients.set(i7, Float.valueOf(((Number) coefficients.get(i7)).floatValue() / r.get(i7, i7)));
        }
        return coefficients;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final float calculateImpulseVelocity(List<Float> list, List<Float> list2, boolean isDataDifferential) {
        float dataPointsDelta;
        int numDataPoints = list.size();
        if (numDataPoints < 2) {
            return 0.0f;
        }
        if (numDataPoints == 2) {
            if (list2.get(0).floatValue() == list2.get(1).floatValue()) {
                return 0.0f;
            }
            if (isDataDifferential) {
                dataPointsDelta = list.get(0).floatValue();
            } else {
                dataPointsDelta = list.get(0).floatValue() - list.get(1).floatValue();
            }
            return dataPointsDelta / (list2.get(0).floatValue() - list2.get(1).floatValue());
        }
        float work = 0.0f;
        for (int i = numDataPoints - 1; i > 0; i--) {
            if (!(list2.get(i).floatValue() == list2.get(i + (-1)).floatValue())) {
                float vPrev = kineticEnergyToVelocity(work);
                float dataPointsDelta2 = isDataDifferential ? -list.get(i - 1).floatValue() : list.get(i).floatValue() - list.get(i - 1).floatValue();
                float vCurr = dataPointsDelta2 / (list2.get(i).floatValue() - list2.get(i - 1).floatValue());
                work += (vCurr - vPrev) * Math.abs(vCurr);
                if (i == numDataPoints - 1) {
                    work *= 0.5f;
                }
            }
        }
        return kineticEnergyToVelocity(work);
    }

    private static final float kineticEnergyToVelocity(float kineticEnergy) {
        return Math.signum(kineticEnergy) * ((float) Math.sqrt(2 * Math.abs(kineticEnergy)));
    }
}
