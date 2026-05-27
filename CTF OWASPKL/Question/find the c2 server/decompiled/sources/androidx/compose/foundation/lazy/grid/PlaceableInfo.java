package androidx.compose.foundation.lazy.grid;

import androidx.compose.animation.core.Animatable;
import androidx.compose.animation.core.AnimationVector2D;
import androidx.compose.animation.core.VectorConvertersKt;
import androidx.compose.runtime.MutableState;
import androidx.compose.runtime.SnapshotStateKt__SnapshotStateKt;
import androidx.compose.runtime.State;
import androidx.compose.ui.unit.IntOffset;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: LazyGridItemPlacementAnimator.kt */
@Metadata(d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0012\b\u0002\u0018\u00002\u00020\u0001B\u0018\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005ø\u0001\u0000¢\u0006\u0002\u0010\u0006R \u0010\u0007\u001a\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\t0\bø\u0001\u0000¢\u0006\b\n\u0000\u001a\u0004\b\n\u0010\u000bR+\u0010\u000e\u001a\u00020\r2\u0006\u0010\f\u001a\u00020\r8F@FX\u0086\u008e\u0002¢\u0006\u0012\n\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u000f\u0010\u0010\"\u0004\b\u0011\u0010\u0012R\u001a\u0010\u0004\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0015\u0010\u0016\"\u0004\b\u0017\u0010\u0018R%\u0010\u0019\u001a\u00020\u0003X\u0086\u000eø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0010\n\u0002\u0010\u001e\u001a\u0004\b\u001a\u0010\u001b\"\u0004\b\u001c\u0010\u001d\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u0006\u001f"}, d2 = {"Landroidx/compose/foundation/lazy/grid/PlaceableInfo;", "", "initialOffset", "Landroidx/compose/ui/unit/IntOffset;", "mainAxisSize", "", "(JILkotlin/jvm/internal/DefaultConstructorMarker;)V", "animatedOffset", "Landroidx/compose/animation/core/Animatable;", "Landroidx/compose/animation/core/AnimationVector2D;", "getAnimatedOffset", "()Landroidx/compose/animation/core/Animatable;", "<set-?>", "", "inProgress", "getInProgress", "()Z", "setInProgress", "(Z)V", "inProgress$delegate", "Landroidx/compose/runtime/MutableState;", "getMainAxisSize", "()I", "setMainAxisSize", "(I)V", "targetOffset", "getTargetOffset-nOcc-ac", "()J", "setTargetOffset--gyyYBs", "(J)V", "J", "foundation_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class PlaceableInfo {
    private final Animatable<IntOffset, AnimationVector2D> animatedOffset;
    private final MutableState inProgress$delegate;
    private int mainAxisSize;
    private long targetOffset;

    public /* synthetic */ PlaceableInfo(long j, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, i);
    }

    private PlaceableInfo(long initialOffset, int mainAxisSize) {
        MutableState mutableStateOf$default;
        this.mainAxisSize = mainAxisSize;
        this.animatedOffset = new Animatable<>(IntOffset.m5231boximpl(initialOffset), VectorConvertersKt.getVectorConverter(IntOffset.Companion), null, 4, null);
        this.targetOffset = initialOffset;
        mutableStateOf$default = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(false, null, 2, null);
        this.inProgress$delegate = mutableStateOf$default;
    }

    public final int getMainAxisSize() {
        return this.mainAxisSize;
    }

    public final void setMainAxisSize(int i) {
        this.mainAxisSize = i;
    }

    public final Animatable<IntOffset, AnimationVector2D> getAnimatedOffset() {
        return this.animatedOffset;
    }

    /* renamed from: getTargetOffset-nOcc-ac  reason: not valid java name */
    public final long m609getTargetOffsetnOccac() {
        return this.targetOffset;
    }

    /* renamed from: setTargetOffset--gyyYBs  reason: not valid java name */
    public final void m610setTargetOffsetgyyYBs(long j) {
        this.targetOffset = j;
    }

    public final boolean getInProgress() {
        State $this$getValue$iv = this.inProgress$delegate;
        return ((Boolean) $this$getValue$iv.getValue()).booleanValue();
    }

    public final void setInProgress(boolean z) {
        MutableState $this$setValue$iv = this.inProgress$delegate;
        $this$setValue$iv.setValue(Boolean.valueOf(z));
    }
}
