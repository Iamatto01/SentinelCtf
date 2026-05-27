package androidx.compose.runtime.snapshots;

import androidx.autofill.HintConstants;
import androidx.compose.runtime.SnapshotThreadLocal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.KotlinNothingValueException;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.InlineMarker;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: Snapshot.kt */
@Metadata(d1 = {"\u0000\u008a\u0001\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0002\u0010\"\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010$\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0001\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0017\n\u0002\u0018\u0002\n\u0002\b\n\u001a\b\u0010$\u001a\u00020\bH\u0002\u001a6\u0010$\u001a\u0002H%\"\u0004\b\u0000\u0010%2!\u0010&\u001a\u001d\u0012\u0013\u0012\u00110\u0010¢\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(\u0013\u0012\u0004\u0012\u0002H%0\u000fH\u0002¢\u0006\u0002\u0010'\u001a4\u0010(\u001a\u00020\u00072\b\u0010)\u001a\u0004\u0018\u00010\u00072\u0016\b\u0002\u0010*\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\b\u0018\u00010\u000f2\b\b\u0002\u0010+\u001a\u00020,H\u0002\u001a\u001f\u0010-\u001a\u0002H%\"\b\b\u0000\u0010%*\u00020.2\u0006\u0010/\u001a\u0002H%H\u0001¢\u0006\u0002\u00100\u001a'\u0010-\u001a\u0002H%\"\b\b\u0000\u0010%*\u00020.2\u0006\u0010/\u001a\u0002H%2\u0006\u00101\u001a\u00020\u0007H\u0001¢\u0006\u0002\u00102\u001a\b\u00103\u001a\u00020\u0007H\u0000\u001aL\u00104\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\b\u0018\u00010\u000f2\u0014\u0010*\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\b\u0018\u00010\u000f2\u0014\u00105\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\b\u0018\u00010\u000f2\b\b\u0002\u00106\u001a\u00020,H\u0002\u001aB\u00107\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\b\u0018\u00010\u000f2\u0014\u00108\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\b\u0018\u00010\u000f2\u0014\u00105\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\b\u0018\u00010\u000fH\u0002\u001a\u0018\u00109\u001a\u00020\b2\u0006\u00101\u001a\u00020\u00072\u0006\u0010:\u001a\u00020;H\u0001\u001a.\u0010<\u001a\u0010\u0012\u0004\u0012\u00020.\u0012\u0004\u0012\u00020.\u0018\u00010=2\u0006\u00103\u001a\u00020>2\u0006\u0010?\u001a\u00020>2\u0006\u0010@\u001a\u00020\u0010H\u0002\u001a\u0010\u0010A\u001a\u00020,2\u0006\u0010:\u001a\u00020;H\u0002\u001a\b\u0010B\u001a\u00020CH\u0002\u001a1\u0010D\u001a\u0004\u0018\u0001H%\"\b\b\u0000\u0010%*\u00020.2\u0006\u0010/\u001a\u0002H%2\u0006\u0010E\u001a\u00020\u00012\u0006\u0010\u0013\u001a\u00020\u0010H\u0002¢\u0006\u0002\u0010F\u001a\u0010\u0010G\u001a\u00020\b2\u0006\u0010H\u001a\u00020\u0001H\u0000\u001a\b\u0010I\u001a\u00020CH\u0002\u001a%\u0010J\u001a\u0002H%\"\u0004\b\u0000\u0010%2\f\u0010&\u001a\b\u0012\u0004\u0012\u0002H%0KH\u0081\bø\u0001\u0000¢\u0006\u0002\u0010L\u001a>\u0010M\u001a\u0002H%\"\u0004\b\u0000\u0010%2\u0006\u0010N\u001a\u00020\u00072!\u0010&\u001a\u001d\u0012\u0013\u0012\u00110\u0010¢\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(\u0013\u0012\u0004\u0012\u0002H%0\u000fH\u0002¢\u0006\u0002\u0010O\u001a:\u0010P\u001a\u0002H%\"\b\b\u0000\u0010%*\u00020\u00072!\u0010&\u001a\u001d\u0012\u0013\u0012\u00110\u0010¢\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(\u0013\u0012\u0004\u0012\u0002H%0\u000fH\u0002¢\u0006\u0002\u0010Q\u001a\u0018\u0010R\u001a\u00020\u00012\u0006\u0010E\u001a\u00020\u00012\u0006\u0010\u0013\u001a\u00020\u0010H\u0000\u001a\u0012\u0010S\u001a\u0004\u0018\u00010.2\u0006\u0010:\u001a\u00020;H\u0002\u001a \u0010T\u001a\u00020,2\u0006\u0010U\u001a\u00020.2\u0006\u00101\u001a\u00020\u00012\u0006\u0010\u0013\u001a\u00020\u0010H\u0002\u001a \u0010T\u001a\u00020,2\u0006\u00103\u001a\u00020\u00012\u0006\u0010V\u001a\u00020\u00012\u0006\u0010\u0013\u001a\u00020\u0010H\u0002\u001a\u0010\u0010W\u001a\u00020\b2\u0006\u00101\u001a\u00020\u0007H\u0002\u001a\u001c\u0010X\u001a\u00020\u0010*\u00020\u00102\u0006\u0010Y\u001a\u00020\u00012\u0006\u0010Z\u001a\u00020\u0001H\u0000\u001a#\u0010[\u001a\u0002H%\"\b\b\u0000\u0010%*\u00020.*\u0002H%2\u0006\u0010:\u001a\u00020;H\u0000¢\u0006\u0002\u0010\\\u001a+\u0010]\u001a\u0002H%\"\b\b\u0000\u0010%*\u00020.*\u0002H%2\u0006\u0010:\u001a\u00020;2\u0006\u00101\u001a\u00020\u0007H\u0000¢\u0006\u0002\u0010^\u001a+\u0010_\u001a\u0002H%\"\b\b\u0000\u0010%*\u00020.*\u0002H%2\u0006\u0010:\u001a\u00020;2\u0006\u00101\u001a\u00020\u0007H\u0002¢\u0006\u0002\u0010^\u001aN\u0010`\u001a\u0002Ha\"\b\b\u0000\u0010%*\u00020.\"\u0004\b\u0001\u0010a*\u0002H%2\u0006\u0010:\u001a\u00020;2\u0006\u0010b\u001a\u0002H%2\u0017\u0010&\u001a\u0013\u0012\u0004\u0012\u0002H%\u0012\u0004\u0012\u0002Ha0\u000f¢\u0006\u0002\bcH\u0080\bø\u0001\u0000¢\u0006\u0002\u0010d\u001a3\u0010e\u001a\u0002H%\"\b\b\u0000\u0010%*\u00020.*\u0002H%2\u0006\u0010:\u001a\u00020;2\u0006\u00101\u001a\u00020\u00072\u0006\u0010b\u001a\u0002H%H\u0000¢\u0006\u0002\u0010f\u001a!\u0010D\u001a\u0002H%\"\b\b\u0000\u0010%*\u00020.*\u0002H%2\u0006\u0010:\u001a\u00020;¢\u0006\u0002\u0010\\\u001a)\u0010D\u001a\u0002H%\"\b\b\u0000\u0010%*\u00020.*\u0002H%2\u0006\u0010:\u001a\u00020;2\u0006\u00101\u001a\u00020\u0007¢\u0006\u0002\u0010^\u001aH\u0010g\u001a\u0002Ha\"\b\b\u0000\u0010%*\u00020.\"\u0004\b\u0001\u0010a*\u0002H%2!\u0010&\u001a\u001d\u0012\u0013\u0012\u0011H%¢\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(/\u0012\u0004\u0012\u0002Ha0\u000fH\u0086\bø\u0001\u0000¢\u0006\u0002\u0010h\u001aF\u0010i\u001a\u0002Ha\"\b\b\u0000\u0010%*\u00020.\"\u0004\b\u0001\u0010a*\u0002H%2\u0006\u0010:\u001a\u00020;2\u0017\u0010&\u001a\u0013\u0012\u0004\u0012\u0002H%\u0012\u0004\u0012\u0002Ha0\u000f¢\u0006\u0002\bcH\u0086\bø\u0001\u0000¢\u0006\u0002\u0010j\u001aN\u0010i\u001a\u0002Ha\"\b\b\u0000\u0010%*\u00020.\"\u0004\b\u0001\u0010a*\u0002H%2\u0006\u0010:\u001a\u00020;2\u0006\u00101\u001a\u00020\u00072\u0017\u0010&\u001a\u0013\u0012\u0004\u0012\u0002H%\u0012\u0004\u0012\u0002Ha0\u000f¢\u0006\u0002\bcH\u0086\bø\u0001\u0000¢\u0006\u0002\u0010k\u001a+\u0010l\u001a\u0002H%\"\b\b\u0000\u0010%*\u00020.*\u0002H%2\u0006\u0010:\u001a\u00020;2\u0006\u00101\u001a\u00020\u0007H\u0001¢\u0006\u0002\u0010^\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\",\u0010\u0002\u001a \u0012\u001c\u0012\u001a\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00060\u0005\u0012\u0004\u0012\u00020\u0007\u0012\u0004\u0012\u00020\b0\u00040\u0003X\u0082\u0004¢\u0006\u0002\n\u0000\".\u0010\t\u001a\"\u0012\f\u0012\n \f*\u0004\u0018\u00010\u000b0\u000b0\nj\u0010\u0012\f\u0012\n \f*\u0004\u0018\u00010\u000b0\u000b`\rX\u0082\u0004¢\u0006\u0002\n\u0000\")\u0010\u000e\u001a\u001d\u0012\u0013\u0012\u00110\u0010¢\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(\u0013\u0012\u0004\u0012\u00020\b0\u000fX\u0082\u0004¢\u0006\u0002\n\u0000\" \u0010\u0014\u001a\u0014\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\b0\u000f0\u0003X\u0082\u0004¢\u0006\u0002\n\u0000\"\u001c\u0010\u0015\u001a\u00020\u00068\u0000X\u0081\u0004¢\u0006\u000e\n\u0000\u0012\u0004\b\u0016\u0010\u0017\u001a\u0004\b\u0018\u0010\u0019\"\u000e\u0010\u001a\u001a\u00020\u0001X\u0082\u000e¢\u0006\u0002\n\u0000\"\u000e\u0010\u001b\u001a\u00020\u0010X\u0082\u000e¢\u0006\u0002\n\u0000\"\u000e\u0010\u001c\u001a\u00020\u001dX\u0082\u0004¢\u0006\u0002\n\u0000\"\u001c\u0010\u001e\u001a\u00020\u00078\u0000X\u0081\u0004¢\u0006\u000e\n\u0000\u0012\u0004\b\u001f\u0010\u0017\u001a\u0004\b \u0010!\"\u0014\u0010\"\u001a\b\u0012\u0004\u0012\u00020\u00070#X\u0082\u0004¢\u0006\u0002\n\u0000\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006m"}, d2 = {"INVALID_SNAPSHOT", "", "applyObservers", "", "Lkotlin/Function2;", "", "", "Landroidx/compose/runtime/snapshots/Snapshot;", "", "currentGlobalSnapshot", "Ljava/util/concurrent/atomic/AtomicReference;", "Landroidx/compose/runtime/snapshots/GlobalSnapshot;", "kotlin.jvm.PlatformType", "Landroidx/compose/runtime/AtomicReference;", "emptyLambda", "Lkotlin/Function1;", "Landroidx/compose/runtime/snapshots/SnapshotIdSet;", "Lkotlin/ParameterName;", HintConstants.AUTOFILL_HINT_NAME, "invalid", "globalWriteObservers", "lock", "getLock$annotations", "()V", "getLock", "()Ljava/lang/Object;", "nextSnapshotId", "openSnapshots", "pinningTable", "Landroidx/compose/runtime/snapshots/SnapshotDoubleIndexHeap;", "snapshotInitializer", "getSnapshotInitializer$annotations", "getSnapshotInitializer", "()Landroidx/compose/runtime/snapshots/Snapshot;", "threadSnapshot", "Landroidx/compose/runtime/SnapshotThreadLocal;", "advanceGlobalSnapshot", "T", "block", "(Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;", "createTransparentSnapshotWithNoParentReadObserver", "previousSnapshot", "readObserver", "ownsPreviousSnapshot", "", "current", "Landroidx/compose/runtime/snapshots/StateRecord;", "r", "(Landroidx/compose/runtime/snapshots/StateRecord;)Landroidx/compose/runtime/snapshots/StateRecord;", "snapshot", "(Landroidx/compose/runtime/snapshots/StateRecord;Landroidx/compose/runtime/snapshots/Snapshot;)Landroidx/compose/runtime/snapshots/StateRecord;", "currentSnapshot", "mergedReadObserver", "parentObserver", "mergeReadObserver", "mergedWriteObserver", "writeObserver", "notifyWrite", "state", "Landroidx/compose/runtime/snapshots/StateObject;", "optimisticMerges", "", "Landroidx/compose/runtime/snapshots/MutableSnapshot;", "applyingSnapshot", "invalidSnapshots", "overwriteUnusedRecordsLocked", "readError", "", "readable", "id", "(Landroidx/compose/runtime/snapshots/StateRecord;ILandroidx/compose/runtime/snapshots/SnapshotIdSet;)Landroidx/compose/runtime/snapshots/StateRecord;", "releasePinningLocked", "handle", "reportReadonlySnapshotWrite", "sync", "Lkotlin/Function0;", "(Lkotlin/jvm/functions/Function0;)Ljava/lang/Object;", "takeNewGlobalSnapshot", "previousGlobalSnapshot", "(Landroidx/compose/runtime/snapshots/Snapshot;Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;", "takeNewSnapshot", "(Lkotlin/jvm/functions/Function1;)Landroidx/compose/runtime/snapshots/Snapshot;", "trackPinning", "usedLocked", "valid", "data", "candidateSnapshot", "validateOpen", "addRange", "from", "until", "newOverwritableRecordLocked", "(Landroidx/compose/runtime/snapshots/StateRecord;Landroidx/compose/runtime/snapshots/StateObject;)Landroidx/compose/runtime/snapshots/StateRecord;", "newWritableRecord", "(Landroidx/compose/runtime/snapshots/StateRecord;Landroidx/compose/runtime/snapshots/StateObject;Landroidx/compose/runtime/snapshots/Snapshot;)Landroidx/compose/runtime/snapshots/StateRecord;", "newWritableRecordLocked", "overwritable", "R", "candidate", "Lkotlin/ExtensionFunctionType;", "(Landroidx/compose/runtime/snapshots/StateRecord;Landroidx/compose/runtime/snapshots/StateObject;Landroidx/compose/runtime/snapshots/StateRecord;Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;", "overwritableRecord", "(Landroidx/compose/runtime/snapshots/StateRecord;Landroidx/compose/runtime/snapshots/StateObject;Landroidx/compose/runtime/snapshots/Snapshot;Landroidx/compose/runtime/snapshots/StateRecord;)Landroidx/compose/runtime/snapshots/StateRecord;", "withCurrent", "(Landroidx/compose/runtime/snapshots/StateRecord;Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;", "writable", "(Landroidx/compose/runtime/snapshots/StateRecord;Landroidx/compose/runtime/snapshots/StateObject;Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;", "(Landroidx/compose/runtime/snapshots/StateRecord;Landroidx/compose/runtime/snapshots/StateObject;Landroidx/compose/runtime/snapshots/Snapshot;Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;", "writableRecord", "runtime_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class SnapshotKt {
    private static final int INVALID_SNAPSHOT = 0;
    private static final AtomicReference<GlobalSnapshot> currentGlobalSnapshot;
    private static int nextSnapshotId;
    private static SnapshotIdSet openSnapshots;
    private static final Snapshot snapshotInitializer;
    private static final Function1<SnapshotIdSet, Unit> emptyLambda = new Function1<SnapshotIdSet, Unit>() { // from class: androidx.compose.runtime.snapshots.SnapshotKt$emptyLambda$1
        @Override // kotlin.jvm.functions.Function1
        public /* bridge */ /* synthetic */ Unit invoke(SnapshotIdSet snapshotIdSet) {
            invoke2(snapshotIdSet);
            return Unit.INSTANCE;
        }

        /* renamed from: invoke  reason: avoid collision after fix types in other method */
        public final void invoke2(SnapshotIdSet it) {
            Intrinsics.checkNotNullParameter(it, "it");
        }
    };
    private static final SnapshotThreadLocal<Snapshot> threadSnapshot = new SnapshotThreadLocal<>();
    private static final Object lock = new Object();
    private static final SnapshotDoubleIndexHeap pinningTable = new SnapshotDoubleIndexHeap();
    private static final List<Function2<Set<? extends Object>, Snapshot, Unit>> applyObservers = new ArrayList();
    private static final List<Function1<Object, Unit>> globalWriteObservers = new ArrayList();

    public static /* synthetic */ void getLock$annotations() {
    }

    public static /* synthetic */ void getSnapshotInitializer$annotations() {
    }

    public static final int trackPinning(int id, SnapshotIdSet invalid) {
        int add;
        Intrinsics.checkNotNullParameter(invalid, "invalid");
        int pinned = invalid.lowest(id);
        Object lock$iv$iv = getLock();
        synchronized (lock$iv$iv) {
            add = pinningTable.add(pinned);
        }
        return add;
    }

    public static final void releasePinningLocked(int handle) {
        pinningTable.remove(handle);
    }

    public static final Snapshot currentSnapshot() {
        Snapshot snapshot = threadSnapshot.get();
        if (snapshot == null) {
            GlobalSnapshot globalSnapshot = currentGlobalSnapshot.get();
            Intrinsics.checkNotNullExpressionValue(globalSnapshot, "currentGlobalSnapshot.get()");
            return globalSnapshot;
        }
        return snapshot;
    }

    static {
        openSnapshots = SnapshotIdSet.Companion.getEMPTY();
        nextSnapshotId = 1;
        int i = nextSnapshotId;
        nextSnapshotId = i + 1;
        GlobalSnapshot it = new GlobalSnapshot(i, SnapshotIdSet.Companion.getEMPTY());
        openSnapshots = openSnapshots.set(it.getId());
        AtomicReference<GlobalSnapshot> atomicReference = new AtomicReference<>(it);
        currentGlobalSnapshot = atomicReference;
        GlobalSnapshot globalSnapshot = atomicReference.get();
        Intrinsics.checkNotNullExpressionValue(globalSnapshot, "currentGlobalSnapshot.get()");
        snapshotInitializer = globalSnapshot;
    }

    public static /* synthetic */ Snapshot createTransparentSnapshotWithNoParentReadObserver$default(Snapshot snapshot, Function1 function1, boolean z, int i, Object obj) {
        if ((i & 2) != 0) {
            function1 = null;
        }
        if ((i & 4) != 0) {
            z = false;
        }
        return createTransparentSnapshotWithNoParentReadObserver(snapshot, function1, z);
    }

    public static final Snapshot createTransparentSnapshotWithNoParentReadObserver(Snapshot previousSnapshot, Function1<Object, Unit> function1, boolean ownsPreviousSnapshot) {
        if ((previousSnapshot instanceof MutableSnapshot) || previousSnapshot == null) {
            return new TransparentObserverMutableSnapshot(previousSnapshot instanceof MutableSnapshot ? (MutableSnapshot) previousSnapshot : null, function1, null, false, ownsPreviousSnapshot);
        }
        return new TransparentObserverSnapshot(previousSnapshot, function1, false, ownsPreviousSnapshot);
    }

    public static /* synthetic */ Function1 mergedReadObserver$default(Function1 function1, Function1 function12, boolean z, int i, Object obj) {
        if ((i & 4) != 0) {
            z = true;
        }
        return mergedReadObserver(function1, function12, z);
    }

    public static final Function1<Object, Unit> mergedReadObserver(final Function1<Object, Unit> function1, Function1<Object, Unit> function12, boolean mergeReadObserver) {
        final Function1 parentObserver = mergeReadObserver ? function12 : null;
        if (function1 == null || parentObserver == null || Intrinsics.areEqual(function1, parentObserver)) {
            return function1 == null ? parentObserver : function1;
        }
        return new Function1<Object, Unit>() { // from class: androidx.compose.runtime.snapshots.SnapshotKt$mergedReadObserver$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Object p1) {
                invoke2(p1);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke  reason: avoid collision after fix types in other method */
            public final void invoke2(Object state) {
                Intrinsics.checkNotNullParameter(state, "state");
                function1.invoke(state);
                parentObserver.invoke(state);
            }
        };
    }

    public static final Function1<Object, Unit> mergedWriteObserver(final Function1<Object, Unit> function1, final Function1<Object, Unit> function12) {
        if (function1 == null || function12 == null || Intrinsics.areEqual(function1, function12)) {
            return function1 == null ? function12 : function1;
        }
        return new Function1<Object, Unit>() { // from class: androidx.compose.runtime.snapshots.SnapshotKt$mergedWriteObserver$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Object p1) {
                invoke2(p1);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke  reason: avoid collision after fix types in other method */
            public final void invoke2(Object state) {
                Intrinsics.checkNotNullParameter(state, "state");
                function1.invoke(state);
                function12.invoke(state);
            }
        };
    }

    public static final Object getLock() {
        return lock;
    }

    public static final <T> T sync(Function0<? extends T> block) {
        T invoke;
        Intrinsics.checkNotNullParameter(block, "block");
        Object lock$iv = getLock();
        synchronized (lock$iv) {
            try {
                invoke = block.invoke();
                InlineMarker.finallyStart(1);
            } catch (Throwable th) {
                InlineMarker.finallyStart(1);
                InlineMarker.finallyEnd(1);
                throw th;
            }
        }
        InlineMarker.finallyEnd(1);
        return invoke;
    }

    public static final Snapshot getSnapshotInitializer() {
        return snapshotInitializer;
    }

    public static final <T> T takeNewGlobalSnapshot(Snapshot previousGlobalSnapshot, Function1<? super SnapshotIdSet, ? extends T> function1) {
        T invoke = function1.invoke(openSnapshots.clear(previousGlobalSnapshot.getId()));
        Object lock$iv$iv = getLock();
        synchronized (lock$iv$iv) {
            int globalId = nextSnapshotId;
            nextSnapshotId = globalId + 1;
            openSnapshots = openSnapshots.clear(previousGlobalSnapshot.getId());
            currentGlobalSnapshot.set(new GlobalSnapshot(globalId, openSnapshots));
            previousGlobalSnapshot.dispose();
            openSnapshots = openSnapshots.set(globalId);
            Unit unit = Unit.INSTANCE;
        }
        return invoke;
    }

    public static final <T> T advanceGlobalSnapshot(Function1<? super SnapshotIdSet, ? extends T> function1) {
        GlobalSnapshot globalSnapshot;
        T t;
        List observers;
        Object previousGlobalSnapshot = snapshotInitializer;
        Intrinsics.checkNotNull(previousGlobalSnapshot, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.GlobalSnapshot");
        GlobalSnapshot globalSnapshot2 = (GlobalSnapshot) previousGlobalSnapshot;
        Object lock$iv$iv = getLock();
        synchronized (lock$iv$iv) {
            globalSnapshot = currentGlobalSnapshot.get();
            Intrinsics.checkNotNullExpressionValue(globalSnapshot, "currentGlobalSnapshot.get()");
            t = (T) takeNewGlobalSnapshot(globalSnapshot, function1);
        }
        Set modified = globalSnapshot.getModified$runtime_release();
        if (modified != null) {
            Object lock$iv$iv2 = getLock();
            synchronized (lock$iv$iv2) {
                observers = CollectionsKt.toMutableList((Collection) applyObservers);
            }
            int size = observers.size();
            for (int index$iv = 0; index$iv < size; index$iv++) {
                Object item$iv = observers.get(index$iv);
                Function2 observer = (Function2) item$iv;
                observer.invoke(modified, globalSnapshot);
            }
        }
        Object lock$iv$iv3 = getLock();
        synchronized (lock$iv$iv3) {
            if (modified != null) {
                Set $this$forEach$iv = modified;
                for (Object element$iv : $this$forEach$iv) {
                    StateObject p0 = (StateObject) element$iv;
                    overwriteUnusedRecordsLocked(p0);
                }
                Unit unit = Unit.INSTANCE;
            }
        }
        return t;
    }

    public static final void advanceGlobalSnapshot() {
        advanceGlobalSnapshot(new Function1<SnapshotIdSet, Unit>() { // from class: androidx.compose.runtime.snapshots.SnapshotKt$advanceGlobalSnapshot$3
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(SnapshotIdSet snapshotIdSet) {
                invoke2(snapshotIdSet);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke  reason: avoid collision after fix types in other method */
            public final void invoke2(SnapshotIdSet it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        });
    }

    public static final <T extends Snapshot> T takeNewSnapshot(final Function1<? super SnapshotIdSet, ? extends T> function1) {
        return (T) advanceGlobalSnapshot(new Function1<SnapshotIdSet, T>() { // from class: androidx.compose.runtime.snapshots.SnapshotKt$takeNewSnapshot$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            /* JADX WARN: Incorrect return type in method signature: (Landroidx/compose/runtime/snapshots/SnapshotIdSet;)TT; */
            @Override // kotlin.jvm.functions.Function1
            public final Snapshot invoke(SnapshotIdSet invalid) {
                SnapshotIdSet snapshotIdSet;
                Intrinsics.checkNotNullParameter(invalid, "invalid");
                Snapshot result = (Snapshot) function1.invoke(invalid);
                Object lock$iv$iv = SnapshotKt.getLock();
                synchronized (lock$iv$iv) {
                    snapshotIdSet = SnapshotKt.openSnapshots;
                    SnapshotKt.openSnapshots = snapshotIdSet.set(result.getId());
                    Unit unit = Unit.INSTANCE;
                }
                return result;
            }
        });
    }

    public static final void validateOpen(Snapshot snapshot) {
        if (!openSnapshots.get(snapshot.getId())) {
            throw new IllegalStateException("Snapshot is not open".toString());
        }
    }

    private static final boolean valid(int currentSnapshot, int candidateSnapshot, SnapshotIdSet invalid) {
        return (candidateSnapshot == 0 || candidateSnapshot > currentSnapshot || invalid.get(candidateSnapshot)) ? false : true;
    }

    private static final boolean valid(StateRecord data, int snapshot, SnapshotIdSet invalid) {
        return valid(snapshot, data.getSnapshotId$runtime_release(), invalid);
    }

    public static final <T extends StateRecord> T readable(T t, int id, SnapshotIdSet invalid) {
        T t2;
        StateRecord candidate = (T) null;
        for (StateRecord current = t; current != null; current = current.getNext$runtime_release()) {
            if (valid(current, id, invalid)) {
                if (candidate == null || candidate.getSnapshotId$runtime_release() < current.getSnapshotId$runtime_release()) {
                    t2 = current;
                } else {
                    t2 = candidate;
                }
                StateRecord candidate2 = t2;
                candidate = (T) candidate2;
            }
        }
        if (candidate != null) {
            return (T) candidate;
        }
        return null;
    }

    public static final <T extends StateRecord> T readable(T t, StateObject state) {
        T t2;
        Intrinsics.checkNotNullParameter(t, "<this>");
        Intrinsics.checkNotNullParameter(state, "state");
        Snapshot snapshot = Snapshot.Companion.getCurrent();
        Function1<Object, Unit> readObserver$runtime_release = snapshot.getReadObserver$runtime_release();
        if (readObserver$runtime_release != null) {
            readObserver$runtime_release.invoke(state);
        }
        T t3 = (T) readable(t, snapshot.getId(), snapshot.getInvalid$runtime_release());
        if (t3 != null) {
            return t3;
        }
        Object lock$iv$iv = getLock();
        synchronized (lock$iv$iv) {
            Snapshot syncSnapshot = Snapshot.Companion.getCurrent();
            StateRecord firstStateRecord = state.getFirstStateRecord();
            Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type T of androidx.compose.runtime.snapshots.SnapshotKt.readable$lambda$7");
            t2 = (T) readable(firstStateRecord, syncSnapshot.getId(), syncSnapshot.getInvalid$runtime_release());
            if (t2 == null) {
                readError();
                throw new KotlinNothingValueException();
            }
        }
        return t2;
    }

    public static final <T extends StateRecord> T readable(T t, StateObject state, Snapshot snapshot) {
        Intrinsics.checkNotNullParameter(t, "<this>");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(snapshot, "snapshot");
        Function1<Object, Unit> readObserver$runtime_release = snapshot.getReadObserver$runtime_release();
        if (readObserver$runtime_release != null) {
            readObserver$runtime_release.invoke(state);
        }
        T t2 = (T) readable(t, snapshot.getId(), snapshot.getInvalid$runtime_release());
        if (t2 != null) {
            return t2;
        }
        readError();
        throw new KotlinNothingValueException();
    }

    public static final Void readError() {
        throw new IllegalStateException("Reading a state that was created after the snapshot was taken or in a snapshot that has not yet been applied".toString());
    }

    private static final StateRecord usedLocked(StateObject state) {
        StateRecord validRecord = null;
        int reuseLimit = pinningTable.lowestOrDefault(nextSnapshotId) - 1;
        SnapshotIdSet invalid = SnapshotIdSet.Companion.getEMPTY();
        for (StateRecord current = state.getFirstStateRecord(); current != null; current = current.getNext$runtime_release()) {
            int currentId = current.getSnapshotId$runtime_release();
            if (currentId == 0) {
                return current;
            }
            if (valid(current, reuseLimit, invalid)) {
                if (validRecord != null) {
                    return current.getSnapshotId$runtime_release() < validRecord.getSnapshotId$runtime_release() ? current : validRecord;
                }
                validRecord = current;
            }
        }
        return null;
    }

    public static final boolean overwriteUnusedRecordsLocked(StateObject state) {
        StateRecord it;
        StateRecord recordToOverwrite = null;
        int reuseLimit = pinningTable.lowestOrDefault(nextSnapshotId) - 1;
        int uncertainRecords = 0;
        for (StateRecord firstStateRecord = state.getFirstStateRecord(); firstStateRecord != null; firstStateRecord = firstStateRecord.getNext$runtime_release()) {
            int currentId = firstStateRecord.getSnapshotId$runtime_release();
            if (currentId != 0) {
                if (currentId <= reuseLimit) {
                    if (recordToOverwrite == null) {
                        recordToOverwrite = firstStateRecord;
                    } else {
                        if (firstStateRecord.getSnapshotId$runtime_release() < recordToOverwrite.getSnapshotId$runtime_release()) {
                            it = recordToOverwrite;
                            recordToOverwrite = firstStateRecord;
                        } else {
                            it = firstStateRecord;
                        }
                        recordToOverwrite.setSnapshotId$runtime_release(0);
                        recordToOverwrite.assign(it);
                        recordToOverwrite = it;
                    }
                } else {
                    uncertainRecords++;
                }
            }
        }
        return uncertainRecords < 1;
    }

    public static final <T extends StateRecord> T writableRecord(T t, StateObject state, Snapshot snapshot) {
        Intrinsics.checkNotNullParameter(t, "<this>");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(snapshot, "snapshot");
        if (snapshot.getReadOnly()) {
            snapshot.mo2263recordModified$runtime_release(state);
        }
        int id = snapshot.getId();
        T t2 = (T) readable(t, id, snapshot.getInvalid$runtime_release());
        if (t2 == null) {
            readError();
            throw new KotlinNothingValueException();
        } else if (t2.getSnapshotId$runtime_release() == snapshot.getId()) {
            return t2;
        } else {
            T t3 = (T) newWritableRecord(t2, state, snapshot);
            snapshot.mo2263recordModified$runtime_release(state);
            return t3;
        }
    }

    public static final <T extends StateRecord> T overwritableRecord(T t, StateObject state, Snapshot snapshot, T candidate) {
        T t2;
        Intrinsics.checkNotNullParameter(t, "<this>");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(snapshot, "snapshot");
        Intrinsics.checkNotNullParameter(candidate, "candidate");
        if (snapshot.getReadOnly()) {
            snapshot.mo2263recordModified$runtime_release(state);
        }
        int id = snapshot.getId();
        if (candidate.getSnapshotId$runtime_release() == id) {
            return candidate;
        }
        Object lock$iv$iv = getLock();
        synchronized (lock$iv$iv) {
            t2 = (T) newOverwritableRecordLocked(t, state);
        }
        t2.setSnapshotId$runtime_release(id);
        snapshot.mo2263recordModified$runtime_release(state);
        return t2;
    }

    public static final <T extends StateRecord> T newWritableRecord(T t, StateObject state, Snapshot snapshot) {
        T t2;
        Intrinsics.checkNotNullParameter(t, "<this>");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(snapshot, "snapshot");
        Object lock$iv$iv = getLock();
        synchronized (lock$iv$iv) {
            t2 = (T) newWritableRecordLocked(t, state, snapshot);
        }
        return t2;
    }

    private static final <T extends StateRecord> T newWritableRecordLocked(T t, StateObject state, Snapshot snapshot) {
        T t2 = (T) newOverwritableRecordLocked(t, state);
        t2.assign(t);
        t2.setSnapshotId$runtime_release(snapshot.getId());
        return t2;
    }

    public static final <T extends StateRecord> T newOverwritableRecordLocked(T t, StateObject state) {
        Intrinsics.checkNotNullParameter(t, "<this>");
        Intrinsics.checkNotNullParameter(state, "state");
        T t2 = (T) usedLocked(state);
        if (t2 != null) {
            t2.setSnapshotId$runtime_release(Integer.MAX_VALUE);
            return t2;
        }
        T t3 = (T) t.create();
        t3.setSnapshotId$runtime_release(Integer.MAX_VALUE);
        t3.setNext$runtime_release(state.getFirstStateRecord());
        Intrinsics.checkNotNull(t3, "null cannot be cast to non-null type T of androidx.compose.runtime.snapshots.SnapshotKt.newOverwritableRecordLocked$lambda$13");
        state.prependStateRecord(t3);
        Intrinsics.checkNotNull(t3, "null cannot be cast to non-null type T of androidx.compose.runtime.snapshots.SnapshotKt.newOverwritableRecordLocked");
        return t3;
    }

    public static final void notifyWrite(Snapshot snapshot, StateObject state) {
        Intrinsics.checkNotNullParameter(snapshot, "snapshot");
        Intrinsics.checkNotNullParameter(state, "state");
        Function1<Object, Unit> writeObserver$runtime_release = snapshot.getWriteObserver$runtime_release();
        if (writeObserver$runtime_release != null) {
            writeObserver$runtime_release.invoke(state);
        }
    }

    public static final <T extends StateRecord, R> R writable(T t, StateObject state, Snapshot snapshot, Function1<? super T, ? extends R> block) {
        R invoke;
        Intrinsics.checkNotNullParameter(t, "<this>");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(snapshot, "snapshot");
        Intrinsics.checkNotNullParameter(block, "block");
        Object lock$iv$iv = getLock();
        synchronized (lock$iv$iv) {
            try {
                invoke = block.invoke(writableRecord(t, state, snapshot));
                InlineMarker.finallyStart(1);
            } catch (Throwable th) {
                InlineMarker.finallyStart(1);
                InlineMarker.finallyEnd(1);
                throw th;
            }
        }
        InlineMarker.finallyEnd(1);
        notifyWrite(snapshot, state);
        return invoke;
    }

    public static final <T extends StateRecord, R> R writable(T t, StateObject state, Function1<? super T, ? extends R> block) {
        Snapshot current;
        R invoke;
        Intrinsics.checkNotNullParameter(t, "<this>");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(block, "block");
        getSnapshotInitializer();
        Object lock$iv$iv = getLock();
        synchronized (lock$iv$iv) {
            try {
                current = Snapshot.Companion.getCurrent();
                invoke = block.invoke(writableRecord(t, state, current));
                InlineMarker.finallyStart(1);
            } catch (Throwable th) {
                InlineMarker.finallyStart(1);
                InlineMarker.finallyEnd(1);
                throw th;
            }
        }
        InlineMarker.finallyEnd(1);
        notifyWrite(current, state);
        return invoke;
    }

    public static final <T extends StateRecord, R> R overwritable(T t, StateObject state, T candidate, Function1<? super T, ? extends R> block) {
        Snapshot current;
        R invoke;
        Intrinsics.checkNotNullParameter(t, "<this>");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(candidate, "candidate");
        Intrinsics.checkNotNullParameter(block, "block");
        getSnapshotInitializer();
        Object lock$iv$iv = getLock();
        synchronized (lock$iv$iv) {
            try {
                current = Snapshot.Companion.getCurrent();
                invoke = block.invoke(overwritableRecord(t, state, current, candidate));
                InlineMarker.finallyStart(1);
            } catch (Throwable th) {
                InlineMarker.finallyStart(1);
                InlineMarker.finallyEnd(1);
                throw th;
            }
        }
        InlineMarker.finallyEnd(1);
        notifyWrite(current, state);
        return invoke;
    }

    public static final Map<StateRecord, StateRecord> optimisticMerges(MutableSnapshot currentSnapshot, MutableSnapshot applyingSnapshot, SnapshotIdSet invalidSnapshots) {
        StateRecord previous;
        Set modified = applyingSnapshot.getModified$runtime_release();
        int id = currentSnapshot.getId();
        if (modified == null) {
            return null;
        }
        SnapshotIdSet start = applyingSnapshot.getInvalid$runtime_release().set(applyingSnapshot.getId()).or(applyingSnapshot.getPreviousIds$runtime_release());
        Object result = null;
        for (StateObject state : modified) {
            StateRecord first = state.getFirstStateRecord();
            StateRecord current = readable(first, id, invalidSnapshots);
            if (current != null && (previous = readable(first, id, start)) != null && !Intrinsics.areEqual(current, previous)) {
                StateRecord applied = readable(first, applyingSnapshot.getId(), applyingSnapshot.getInvalid$runtime_release());
                if (applied == null) {
                    readError();
                    throw new KotlinNothingValueException();
                }
                StateRecord merged = state.mergeRecords(previous, current, applied);
                if (merged == null) {
                    return null;
                }
                HashMap hashMap = (Map) result;
                if (hashMap == null) {
                    Object it = new HashMap();
                    result = it;
                    hashMap = (Map) it;
                }
                hashMap.put(current, merged);
            }
        }
        return (Map) result;
    }

    public static final Void reportReadonlySnapshotWrite() {
        throw new IllegalStateException("Cannot modify a state object in a read-only snapshot".toString());
    }

    public static final <T extends StateRecord> T current(T r, Snapshot snapshot) {
        Intrinsics.checkNotNullParameter(r, "r");
        Intrinsics.checkNotNullParameter(snapshot, "snapshot");
        T t = (T) readable(r, snapshot.getId(), snapshot.getInvalid$runtime_release());
        if (t != null) {
            return t;
        }
        readError();
        throw new KotlinNothingValueException();
    }

    public static final <T extends StateRecord> T current(T r) {
        T t;
        Intrinsics.checkNotNullParameter(r, "r");
        Snapshot snapshot = Snapshot.Companion.getCurrent();
        T t2 = (T) readable(r, snapshot.getId(), snapshot.getInvalid$runtime_release());
        if (t2 != null) {
            return t2;
        }
        Object lock$iv$iv = getLock();
        synchronized (lock$iv$iv) {
            Snapshot syncSnapshot = Snapshot.Companion.getCurrent();
            t = (T) readable(r, syncSnapshot.getId(), syncSnapshot.getInvalid$runtime_release());
        }
        if (t != null) {
            return t;
        }
        readError();
        throw new KotlinNothingValueException();
    }

    public static final <T extends StateRecord, R> R withCurrent(T t, Function1<? super T, ? extends R> block) {
        Intrinsics.checkNotNullParameter(t, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        return block.invoke(current(t));
    }

    public static final SnapshotIdSet addRange(SnapshotIdSet $this$addRange, int from, int until) {
        Intrinsics.checkNotNullParameter($this$addRange, "<this>");
        SnapshotIdSet result = $this$addRange;
        for (int invalidId = from; invalidId < until; invalidId++) {
            result = result.set(invalidId);
        }
        return result;
    }
}
