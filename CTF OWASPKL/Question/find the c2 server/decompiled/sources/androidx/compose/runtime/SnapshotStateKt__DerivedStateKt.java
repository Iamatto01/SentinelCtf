package androidx.compose.runtime;

import androidx.autofill.HintConstants;
import androidx.compose.runtime.collection.MutableVector;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.TuplesKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: DerivedState.kt */
@Metadata(d1 = {"\u0000D\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0004\u001a \u0010\n\u001a\b\u0012\u0004\u0012\u0002H\f0\u000b\"\u0004\b\u0000\u0010\f2\f\u0010\r\u001a\b\u0012\u0004\u0012\u0002H\f0\u000e\u001a.\u0010\n\u001a\b\u0012\u0004\u0012\u0002H\f0\u000b\"\u0004\b\u0000\u0010\f2\f\u0010\u000f\u001a\b\u0012\u0004\u0012\u0002H\f0\u00102\f\u0010\r\u001a\b\u0012\u0004\u0012\u0002H\f0\u000e\u001a0\u0010\u0011\u001a\u0002H\u0012\"\u0004\b\u0000\u0010\u00122\n\u0010\u0013\u001a\u0006\u0012\u0002\b\u00030\u00072\f\u0010\u0014\u001a\b\u0012\u0004\u0012\u0002H\u00120\u000eH\u0082\b¢\u0006\u0004\b\u0015\u0010\u0016\u001aj\u0010\u0017\u001a\u00020\b\"\u0004\b\u0000\u0010\u00122%\u0010\u0018\u001a!\u0012\u0017\u0012\u0015\u0012\u0002\b\u00030\u000b¢\u0006\f\b\u0019\u0012\b\b\u001a\u0012\u0004\b\b(\u0013\u0012\u0004\u0012\u00020\b0\u00062%\u0010\u001b\u001a!\u0012\u0017\u0012\u0015\u0012\u0002\b\u00030\u000b¢\u0006\f\b\u0019\u0012\b\b\u001a\u0012\u0004\b\b(\u0013\u0012\u0004\u0012\u00020\b0\u00062\f\u0010\u0014\u001a\b\u0012\u0004\u0012\u0002H\u00120\u000eH\u0000\"\u0014\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\u00020\u0001X\u0082\u0004¢\u0006\u0002\n\u0000\"J\u0010\u0003\u001a>\u0012:\u00128\u00124\u00122\u0012\u0014\u0012\u0012\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u0007\u0012\u0004\u0012\u00020\b0\u0006\u0012\u0014\u0012\u0012\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u0007\u0012\u0004\u0012\u00020\b0\u00060\u0005j\u0002`\t0\u00040\u0001X\u0082\u0004¢\u0006\u0002\n\u0000*d\b\u0002\u0010\u001c\".\u0012\u0014\u0012\u0012\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u0007\u0012\u0004\u0012\u00020\b0\u0006\u0012\u0014\u0012\u0012\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u0007\u0012\u0004\u0012\u00020\b0\u00060\u00052.\u0012\u0014\u0012\u0012\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u0007\u0012\u0004\u0012\u00020\b0\u0006\u0012\u0014\u0012\u0012\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u0007\u0012\u0004\u0012\u00020\b0\u00060\u0005¨\u0006\u001d"}, d2 = {"calculationBlockNestedLevel", "Landroidx/compose/runtime/SnapshotThreadLocal;", "", "derivedStateObservers", "Landroidx/compose/runtime/collection/MutableVector;", "Lkotlin/Pair;", "Lkotlin/Function1;", "Landroidx/compose/runtime/DerivedState;", "", "Landroidx/compose/runtime/DerivedStateObservers;", "derivedStateOf", "Landroidx/compose/runtime/State;", "T", "calculation", "Lkotlin/Function0;", "policy", "Landroidx/compose/runtime/SnapshotMutationPolicy;", "notifyObservers", "R", "derivedState", "block", "notifyObservers$SnapshotStateKt__DerivedStateKt", "(Landroidx/compose/runtime/DerivedState;Lkotlin/jvm/functions/Function0;)Ljava/lang/Object;", "observeDerivedStateRecalculations", "start", "Lkotlin/ParameterName;", HintConstants.AUTOFILL_HINT_NAME, "done", "DerivedStateObservers", "runtime_release"}, k = 5, mv = {1, 8, 0}, xi = 48, xs = "androidx/compose/runtime/SnapshotStateKt")
/* loaded from: classes.dex */
public final /* synthetic */ class SnapshotStateKt__DerivedStateKt {
    private static final SnapshotThreadLocal<Integer> calculationBlockNestedLevel = new SnapshotThreadLocal<>();
    private static final SnapshotThreadLocal<MutableVector<Pair<Function1<DerivedState<?>, Unit>, Function1<DerivedState<?>, Unit>>>> derivedStateObservers = new SnapshotThreadLocal<>();

    public static final <T> State<T> derivedStateOf(Function0<? extends T> calculation) {
        Intrinsics.checkNotNullParameter(calculation, "calculation");
        return new DerivedSnapshotState(calculation, null);
    }

    public static final <T> State<T> derivedStateOf(SnapshotMutationPolicy<T> policy, Function0<? extends T> calculation) {
        Intrinsics.checkNotNullParameter(policy, "policy");
        Intrinsics.checkNotNullParameter(calculation, "calculation");
        return new DerivedSnapshotState(calculation, policy);
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x004c  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0064  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static final <R> R notifyObservers$SnapshotStateKt__DerivedStateKt(androidx.compose.runtime.DerivedState<?> r11, kotlin.jvm.functions.Function0<? extends R> r12) {
        /*
            r0 = 0
            androidx.compose.runtime.SnapshotThreadLocal r1 = access$getDerivedStateObservers$p()
            java.lang.Object r1 = r1.get()
            androidx.compose.runtime.collection.MutableVector r1 = (androidx.compose.runtime.collection.MutableVector) r1
            if (r1 != 0) goto L18
            r1 = 0
            r2 = 0
            androidx.compose.runtime.collection.MutableVector r3 = new androidx.compose.runtime.collection.MutableVector
            kotlin.Pair[] r4 = new kotlin.Pair[r1]
            r5 = 0
            r3.<init>(r4, r5)
            r1 = r3
        L18:
            r2 = r1
            r3 = 0
            int r4 = r2.getSize()
            r5 = 1
            if (r4 <= 0) goto L3a
            r6 = 0
            java.lang.Object[] r7 = r2.getContent()
        L28:
            r8 = r7[r6]
            kotlin.Pair r8 = (kotlin.Pair) r8
            r9 = 0
            java.lang.Object r8 = r8.component1()
            kotlin.jvm.functions.Function1 r8 = (kotlin.jvm.functions.Function1) r8
            r8.invoke(r11)
            int r6 = r6 + r5
            if (r6 < r4) goto L28
        L3a:
        L3c:
            java.lang.Object r2 = r12.invoke()     // Catch: java.lang.Throwable -> L69
            kotlin.jvm.internal.InlineMarker.finallyStart(r5)
            r3 = r1
            r4 = 0
            int r6 = r3.getSize()
            if (r6 <= 0) goto L63
            r7 = 0
            java.lang.Object[] r8 = r3.getContent()
        L51:
            r9 = r8[r7]
            kotlin.Pair r9 = (kotlin.Pair) r9
            r10 = 0
            java.lang.Object r9 = r9.component2()
            kotlin.jvm.functions.Function1 r9 = (kotlin.jvm.functions.Function1) r9
            r9.invoke(r11)
            int r7 = r7 + r5
            if (r7 < r6) goto L51
        L63:
        L64:
            kotlin.jvm.internal.InlineMarker.finallyEnd(r5)
            return r2
        L69:
            r2 = move-exception
            kotlin.jvm.internal.InlineMarker.finallyStart(r5)
            r3 = r1
            r4 = 0
            int r6 = r3.getSize()
            if (r6 <= 0) goto L8e
            r7 = 0
            java.lang.Object[] r8 = r3.getContent()
        L7b:
            r9 = r8[r7]
            kotlin.Pair r9 = (kotlin.Pair) r9
            r10 = 0
            java.lang.Object r9 = r9.component2()
            kotlin.jvm.functions.Function1 r9 = (kotlin.jvm.functions.Function1) r9
            r9.invoke(r11)
            int r7 = r7 + r5
            if (r7 >= r6) goto L8e
            goto L7b
        L8e:
            kotlin.jvm.internal.InlineMarker.finallyEnd(r5)
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.SnapshotStateKt__DerivedStateKt.notifyObservers$SnapshotStateKt__DerivedStateKt(androidx.compose.runtime.DerivedState, kotlin.jvm.functions.Function0):java.lang.Object");
    }

    public static final <R> void observeDerivedStateRecalculations(Function1<? super State<?>, Unit> start, Function1<? super State<?>, Unit> done, Function0<? extends R> block) {
        Intrinsics.checkNotNullParameter(start, "start");
        Intrinsics.checkNotNullParameter(done, "done");
        Intrinsics.checkNotNullParameter(block, "block");
        SnapshotThreadLocal<MutableVector<Pair<Function1<DerivedState<?>, Unit>, Function1<DerivedState<?>, Unit>>>> snapshotThreadLocal = derivedStateObservers;
        MutableVector it = snapshotThreadLocal.get();
        if (it == null) {
            it = new MutableVector(new Pair[16], 0);
            snapshotThreadLocal.set(it);
        }
        MutableVector observers = it;
        Pair observer = TuplesKt.to(start, done);
        try {
            observers.add(observer);
            block.invoke();
        } finally {
            observers.removeAt(observers.getSize() - 1);
        }
    }
}
