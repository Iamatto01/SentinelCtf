package androidx.compose.runtime.snapshots;

import androidx.compose.runtime.external.kotlinx.collections.immutable.ExtensionsKt;
import androidx.compose.runtime.external.kotlinx.collections.immutable.ImmutableSet;
import androidx.compose.runtime.external.kotlinx.collections.immutable.PersistentMap;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.InlineMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.markers.KMutableMap;
/* compiled from: SnapshotStateMap.kt */
@Metadata(d1 = {"\u0000p\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010%\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010$\n\u0002\b\u0004\n\u0002\u0010#\n\u0002\u0010'\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u001f\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010&\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0002\b\u0018\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\b\u0007\u0018\u0000*\u0004\b\u0000\u0010\u0001*\u0004\b\u0001\u0010\u00022\u000e\u0012\u0004\u0012\u0002H\u0001\u0012\u0004\u0012\u0002H\u00020\u00032\u00020\u0004:\u0001LB\u0005¢\u0006\u0002\u0010\u0005J1\u0010&\u001a\u00020'2\u001e\u0010(\u001a\u001a\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010*\u0012\u0004\u0012\u00020'0)H\u0080\bø\u0001\u0000¢\u0006\u0002\b+J1\u0010,\u001a\u00020'2\u001e\u0010(\u001a\u001a\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010*\u0012\u0004\u0012\u00020'0)H\u0080\bø\u0001\u0000¢\u0006\u0002\b-J\b\u0010.\u001a\u00020/H\u0016J\u0015\u00100\u001a\u00020'2\u0006\u00101\u001a\u00028\u0000H\u0016¢\u0006\u0002\u00102J\u0015\u00103\u001a\u00020'2\u0006\u00104\u001a\u00028\u0001H\u0016¢\u0006\u0002\u00102J\u0018\u00105\u001a\u0004\u0018\u00018\u00012\u0006\u00101\u001a\u00028\u0000H\u0096\u0002¢\u0006\u0002\u00106J\b\u00107\u001a\u00020'H\u0016J4\u00108\u001a\u0002H9\"\u0004\b\u0002\u001092\u001e\u0010:\u001a\u001a\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u0003\u0012\u0004\u0012\u0002H90)H\u0082\b¢\u0006\u0002\u0010;J\u0010\u0010<\u001a\u00020/2\u0006\u00104\u001a\u00020\u0011H\u0016J\u001f\u0010=\u001a\u0004\u0018\u00018\u00012\u0006\u00101\u001a\u00028\u00002\u0006\u00104\u001a\u00028\u0001H\u0016¢\u0006\u0002\u0010>J\u001e\u0010?\u001a\u00020/2\u0014\u0010@\u001a\u0010\u0012\u0006\b\u0001\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u0007H\u0016J\u0017\u0010A\u001a\u0004\u0018\u00018\u00012\u0006\u00101\u001a\u00028\u0000H\u0016¢\u0006\u0002\u00106J1\u0010B\u001a\u00020'2\u001e\u0010(\u001a\u001a\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\r\u0012\u0004\u0012\u00020'0)H\u0080\bø\u0001\u0000¢\u0006\u0002\bCJ\u0017\u0010D\u001a\u00020'2\u0006\u00104\u001a\u00028\u0001H\u0000¢\u0006\u0004\bE\u00102J\u0012\u0010F\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u0007J5\u0010G\u001a\u00020/2*\u0010:\u001a&\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010H\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010H0)H\u0082\bJ9\u0010I\u001a\u0002H9\"\u0004\b\u0002\u001092#\u0010:\u001a\u001f\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u001c\u0012\u0004\u0012\u0002H90)¢\u0006\u0002\bJH\u0082\b¢\u0006\u0002\u0010;J9\u0010K\u001a\u0002H9\"\u0004\b\u0002\u001092#\u0010:\u001a\u001f\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u001c\u0012\u0004\u0012\u0002H90)¢\u0006\u0002\bJH\u0082\b¢\u0006\u0002\u0010;R&\u0010\u0006\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00078AX\u0080\u0004¢\u0006\f\u0012\u0004\b\b\u0010\u0005\u001a\u0004\b\t\u0010\nR&\u0010\u000b\u001a\u0014\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\r0\fX\u0096\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u000e\u0010\u000fR\u001e\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u0010\u001a\u00020\u0011@RX\u0096\u000e¢\u0006\b\n\u0000\u001a\u0004\b\u0013\u0010\u0014R\u001a\u0010\u0015\u001a\b\u0012\u0004\u0012\u00028\u00000\fX\u0096\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0016\u0010\u000fR\u0014\u0010\u0017\u001a\u00020\u00188@X\u0080\u0004¢\u0006\u0006\u001a\u0004\b\u0019\u0010\u001aR&\u0010\u001b\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u001c8@X\u0080\u0004¢\u0006\f\u0012\u0004\b\u001d\u0010\u0005\u001a\u0004\b\u001e\u0010\u001fR\u0014\u0010 \u001a\u00020\u00188VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b!\u0010\u001aR\u001a\u0010\"\u001a\b\u0012\u0004\u0012\u00028\u00010#X\u0096\u0004¢\u0006\b\n\u0000\u001a\u0004\b$\u0010%\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006M"}, d2 = {"Landroidx/compose/runtime/snapshots/SnapshotStateMap;", "K", "V", "", "Landroidx/compose/runtime/snapshots/StateObject;", "()V", "debuggerDisplayValue", "", "getDebuggerDisplayValue$annotations", "getDebuggerDisplayValue", "()Ljava/util/Map;", "entries", "", "", "getEntries", "()Ljava/util/Set;", "<set-?>", "Landroidx/compose/runtime/snapshots/StateRecord;", "firstStateRecord", "getFirstStateRecord", "()Landroidx/compose/runtime/snapshots/StateRecord;", "keys", "getKeys", "modification", "", "getModification$runtime_release", "()I", "readable", "Landroidx/compose/runtime/snapshots/SnapshotStateMap$StateMapStateRecord;", "getReadable$runtime_release$annotations", "getReadable$runtime_release", "()Landroidx/compose/runtime/snapshots/SnapshotStateMap$StateMapStateRecord;", "size", "getSize", "values", "", "getValues", "()Ljava/util/Collection;", "all", "", "predicate", "Lkotlin/Function1;", "", "all$runtime_release", "any", "any$runtime_release", "clear", "", "containsKey", "key", "(Ljava/lang/Object;)Z", "containsValue", "value", "get", "(Ljava/lang/Object;)Ljava/lang/Object;", "isEmpty", "mutate", "R", "block", "(Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;", "prependStateRecord", "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", "putAll", "from", "remove", "removeIf", "removeIf$runtime_release", "removeValue", "removeValue$runtime_release", "toMap", "update", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/PersistentMap;", "withCurrent", "Lkotlin/ExtensionFunctionType;", "writable", "StateMapStateRecord", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class SnapshotStateMap<K, V> implements Map<K, V>, StateObject, KMutableMap {
    public static final int $stable = 0;
    private StateRecord firstStateRecord = new StateMapStateRecord(ExtensionsKt.persistentHashMapOf());
    private final Set<Map.Entry<K, V>> entries = new SnapshotMapEntrySet(this);
    private final Set<K> keys = new SnapshotMapKeySet(this);
    private final Collection<V> values = new SnapshotMapValueSet(this);

    public static /* synthetic */ void getDebuggerDisplayValue$annotations() {
    }

    public static /* synthetic */ void getReadable$runtime_release$annotations() {
    }

    @Override // java.util.Map
    public final /* bridge */ Set<Map.Entry<K, V>> entrySet() {
        return getEntries();
    }

    @Override // java.util.Map
    public final /* bridge */ Set<K> keySet() {
        return getKeys();
    }

    @Override // java.util.Map
    public final /* bridge */ int size() {
        return getSize();
    }

    @Override // java.util.Map
    public final /* bridge */ Collection<V> values() {
        return getValues();
    }

    @Override // androidx.compose.runtime.snapshots.StateObject
    public StateRecord getFirstStateRecord() {
        return this.firstStateRecord;
    }

    @Override // androidx.compose.runtime.snapshots.StateObject
    public void prependStateRecord(StateRecord value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.firstStateRecord = (StateMapStateRecord) value;
    }

    public final Map<K, V> toMap() {
        return getReadable$runtime_release().getMap$runtime_release();
    }

    public int getSize() {
        return getReadable$runtime_release().getMap$runtime_release().size();
    }

    @Override // java.util.Map
    public boolean containsKey(Object key) {
        return getReadable$runtime_release().getMap$runtime_release().containsKey(key);
    }

    @Override // java.util.Map
    public boolean containsValue(Object value) {
        return getReadable$runtime_release().getMap$runtime_release().containsValue(value);
    }

    @Override // java.util.Map
    public V get(Object key) {
        return (V) getReadable$runtime_release().getMap$runtime_release().get(key);
    }

    @Override // java.util.Map
    public boolean isEmpty() {
        return getReadable$runtime_release().getMap$runtime_release().isEmpty();
    }

    public Set<Map.Entry<K, V>> getEntries() {
        return this.entries;
    }

    public Set<K> getKeys() {
        return this.keys;
    }

    public Collection<V> getValues() {
        return this.values;
    }

    @Override // java.util.Map
    public void clear() {
        Object lock$iv$iv;
        StateRecord firstStateRecord = getFirstStateRecord();
        Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
        StateRecord $this$withCurrent$iv$iv$iv = (StateMapStateRecord) firstStateRecord;
        StateMapStateRecord $this$update_u24lambda_u2414$iv = (StateMapStateRecord) SnapshotKt.current($this$withCurrent$iv$iv$iv);
        $this$update_u24lambda_u2414$iv.getMap$runtime_release();
        PersistentMap it = ExtensionsKt.persistentHashMapOf();
        if (it == $this$update_u24lambda_u2414$iv.getMap$runtime_release()) {
            return;
        }
        lock$iv$iv = SnapshotStateMapKt.sync;
        synchronized (lock$iv$iv) {
            try {
                StateRecord firstStateRecord2 = getFirstStateRecord();
                Intrinsics.checkNotNull(firstStateRecord2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                StateRecord $this$writable$iv$iv$iv = (StateMapStateRecord) firstStateRecord2;
                SnapshotKt.getSnapshotInitializer();
                Object lock$iv$iv$iv$iv$iv = SnapshotKt.getLock();
                synchronized (lock$iv$iv$iv$iv$iv) {
                    try {
                        try {
                            Snapshot current = Snapshot.Companion.getCurrent();
                            try {
                                try {
                                    StateMapStateRecord $this$update_u24lambda_u2414_u24lambda_u2413_u24lambda_u2412$iv = (StateMapStateRecord) SnapshotKt.writableRecord($this$writable$iv$iv$iv, this, current);
                                    $this$update_u24lambda_u2414_u24lambda_u2413_u24lambda_u2412$iv.setMap$runtime_release(it);
                                    int $i$f$update = $this$update_u24lambda_u2414_u24lambda_u2413_u24lambda_u2412$iv.getModification$runtime_release() + 1;
                                    try {
                                        $this$update_u24lambda_u2414_u24lambda_u2413_u24lambda_u2412$iv.setModification$runtime_release($i$f$update);
                                        SnapshotKt.notifyWrite(current, this);
                                    } catch (Throwable th) {
                                        th = th;
                                        throw th;
                                    }
                                } catch (Throwable th2) {
                                    th = th2;
                                }
                            } catch (Throwable th3) {
                                th = th3;
                            }
                        } catch (Throwable th4) {
                            th = th4;
                        }
                    } catch (Throwable th5) {
                        th = th5;
                        throw th;
                    }
                }
            } catch (Throwable th6) {
                th = th6;
            }
        }
    }

    @Override // java.util.Map
    public V put(K k, V v) {
        Object lock$iv$iv;
        PersistentMap<K, V> map$runtime_release;
        int currentModification$iv;
        V put;
        Object lock$iv$iv2;
        boolean z;
        SnapshotStateMap this_$iv = this;
        boolean z2 = false;
        while (true) {
            lock$iv$iv = SnapshotStateMapKt.sync;
            synchronized (lock$iv$iv) {
                try {
                    StateRecord firstStateRecord = this_$iv.getFirstStateRecord();
                    Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                    StateRecord $this$withCurrent$iv$iv$iv = (StateMapStateRecord) firstStateRecord;
                    StateMapStateRecord current$iv = (StateMapStateRecord) SnapshotKt.current($this$withCurrent$iv$iv$iv);
                    map$runtime_release = current$iv.getMap$runtime_release();
                    currentModification$iv = current$iv.getModification$runtime_release();
                    Unit unit = Unit.INSTANCE;
                } catch (Throwable th) {
                    throw th;
                }
            }
            Intrinsics.checkNotNull(map$runtime_release);
            PersistentMap.Builder builder$iv = map$runtime_release.builder();
            PersistentMap.Builder it = builder$iv;
            put = it.put(k, v);
            PersistentMap newMap$iv = builder$iv.build();
            if (Intrinsics.areEqual(newMap$iv, map$runtime_release)) {
                break;
            }
            lock$iv$iv2 = SnapshotStateMapKt.sync;
            synchronized (lock$iv$iv2) {
                SnapshotStateMap this_$iv$iv = this_$iv;
                try {
                    StateRecord firstStateRecord2 = this_$iv$iv.getFirstStateRecord();
                    Intrinsics.checkNotNull(firstStateRecord2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                    StateRecord $this$writable$iv$iv$iv = (StateMapStateRecord) firstStateRecord2;
                    SnapshotKt.getSnapshotInitializer();
                    Object lock$iv$iv$iv$iv$iv = SnapshotKt.getLock();
                    synchronized (lock$iv$iv$iv$iv$iv) {
                        try {
                            Snapshot current = Snapshot.Companion.getCurrent();
                            try {
                                SnapshotStateMap this_$iv2 = this_$iv;
                                try {
                                    StateMapStateRecord $this$mutate_u24lambda_u2411_u24lambda_u2410$iv = (StateMapStateRecord) SnapshotKt.writableRecord($this$writable$iv$iv$iv, this_$iv$iv, current);
                                    boolean z3 = z2;
                                    try {
                                        int $i$f$mutate = $this$mutate_u24lambda_u2411_u24lambda_u2410$iv.getModification$runtime_release();
                                        if ($i$f$mutate == currentModification$iv) {
                                            $this$mutate_u24lambda_u2411_u24lambda_u2410$iv.setMap$runtime_release(newMap$iv);
                                            z = true;
                                            $this$mutate_u24lambda_u2411_u24lambda_u2410$iv.setModification$runtime_release($this$mutate_u24lambda_u2411_u24lambda_u2410$iv.getModification$runtime_release() + 1);
                                        } else {
                                            z = false;
                                        }
                                        try {
                                            SnapshotKt.notifyWrite(current, this_$iv$iv);
                                            if (z) {
                                                break;
                                            }
                                            this_$iv = this_$iv2;
                                            z2 = z3;
                                        } catch (Throwable th2) {
                                            th = th2;
                                            throw th;
                                        }
                                    } catch (Throwable th3) {
                                        th = th3;
                                        throw th;
                                    }
                                } catch (Throwable th4) {
                                    th = th4;
                                }
                            } catch (Throwable th5) {
                                th = th5;
                            }
                        } catch (Throwable th6) {
                            th = th6;
                        }
                    }
                } catch (Throwable th7) {
                    th = th7;
                }
            }
        }
        return put;
    }

    /* JADX WARN: Code restructure failed: missing block: B:29:0x00b9, code lost:
        androidx.compose.runtime.snapshots.SnapshotKt.notifyWrite(r20, r12);
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x00ca, code lost:
        if (r22 == false) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:?, code lost:
        return;
     */
    @Override // java.util.Map
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void putAll(java.util.Map<? extends K, ? extends V> r24) {
        /*
            Method dump skipped, instructions count: 249
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.SnapshotStateMap.putAll(java.util.Map):void");
    }

    @Override // java.util.Map
    public V remove(Object key) {
        Object lock$iv$iv;
        PersistentMap<K, V> map$runtime_release;
        int currentModification$iv;
        V remove;
        Object lock$iv$iv2;
        Snapshot current;
        SnapshotStateMap this_$iv;
        StateMapStateRecord $this$mutate_u24lambda_u2411_u24lambda_u2410$iv;
        boolean z;
        boolean z2;
        SnapshotStateMap this_$iv2 = this;
        boolean z3 = false;
        while (true) {
            lock$iv$iv = SnapshotStateMapKt.sync;
            synchronized (lock$iv$iv) {
                try {
                    StateRecord firstStateRecord = this_$iv2.getFirstStateRecord();
                    Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                    StateRecord $this$withCurrent$iv$iv$iv = (StateMapStateRecord) firstStateRecord;
                    StateMapStateRecord current$iv = (StateMapStateRecord) SnapshotKt.current($this$withCurrent$iv$iv$iv);
                    map$runtime_release = current$iv.getMap$runtime_release();
                    currentModification$iv = current$iv.getModification$runtime_release();
                    Unit unit = Unit.INSTANCE;
                } catch (Throwable th) {
                    throw th;
                }
            }
            Intrinsics.checkNotNull(map$runtime_release);
            PersistentMap.Builder builder$iv = map$runtime_release.builder();
            PersistentMap.Builder it = builder$iv;
            remove = it.remove(key);
            PersistentMap newMap$iv = builder$iv.build();
            if (Intrinsics.areEqual(newMap$iv, map$runtime_release)) {
                break;
            }
            lock$iv$iv2 = SnapshotStateMapKt.sync;
            synchronized (lock$iv$iv2) {
                SnapshotStateMap this_$iv$iv = this_$iv2;
                try {
                    StateRecord firstStateRecord2 = this_$iv$iv.getFirstStateRecord();
                    Intrinsics.checkNotNull(firstStateRecord2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                    StateRecord $this$writable$iv$iv$iv = (StateMapStateRecord) firstStateRecord2;
                    SnapshotKt.getSnapshotInitializer();
                    Object lock$iv$iv$iv$iv$iv = SnapshotKt.getLock();
                    synchronized (lock$iv$iv$iv$iv$iv) {
                        try {
                            current = Snapshot.Companion.getCurrent();
                            try {
                                this_$iv = this_$iv2;
                                try {
                                    $this$mutate_u24lambda_u2411_u24lambda_u2410$iv = (StateMapStateRecord) SnapshotKt.writableRecord($this$writable$iv$iv$iv, this_$iv$iv, current);
                                    z = z3;
                                } catch (Throwable th2) {
                                    th = th2;
                                }
                            } catch (Throwable th3) {
                                th = th3;
                            }
                        } catch (Throwable th4) {
                            th = th4;
                        }
                        try {
                            int $i$f$mutate = $this$mutate_u24lambda_u2411_u24lambda_u2410$iv.getModification$runtime_release();
                            if ($i$f$mutate == currentModification$iv) {
                                $this$mutate_u24lambda_u2411_u24lambda_u2410$iv.setMap$runtime_release(newMap$iv);
                                z2 = true;
                                $this$mutate_u24lambda_u2411_u24lambda_u2410$iv.setModification$runtime_release($this$mutate_u24lambda_u2411_u24lambda_u2410$iv.getModification$runtime_release() + 1);
                            } else {
                                z2 = false;
                            }
                            try {
                                SnapshotKt.notifyWrite(current, this_$iv$iv);
                                if (z2) {
                                    break;
                                }
                                this_$iv2 = this_$iv;
                                z3 = z;
                            } catch (Throwable th5) {
                                th = th5;
                                throw th;
                            }
                        } catch (Throwable th6) {
                            th = th6;
                            throw th;
                        }
                    }
                } catch (Throwable th7) {
                    th = th7;
                }
            }
        }
        return remove;
    }

    public final int getModification$runtime_release() {
        return getReadable$runtime_release().getModification$runtime_release();
    }

    public final boolean removeValue$runtime_release(V v) {
        Object element$iv;
        Iterable $this$firstOrNull$iv = entrySet();
        Iterator<T> it = $this$firstOrNull$iv.iterator();
        while (true) {
            if (!it.hasNext()) {
                element$iv = null;
                break;
            }
            element$iv = it.next();
            if (Intrinsics.areEqual(((Map.Entry) element$iv).getValue(), v)) {
                break;
            }
        }
        Map.Entry it2 = (Map.Entry) element$iv;
        if (it2 != null) {
            remove(it2.getKey());
            return true;
        }
        return false;
    }

    public final StateMapStateRecord<K, V> getReadable$runtime_release() {
        StateRecord firstStateRecord = getFirstStateRecord();
        Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
        return (StateMapStateRecord) SnapshotKt.readable((StateMapStateRecord) firstStateRecord, this);
    }

    public final boolean removeIf$runtime_release(Function1<? super Map.Entry<K, V>, Boolean> function1) {
        Object lock$iv$iv;
        PersistentMap<K, V> map$runtime_release;
        int currentModification$iv;
        Object lock$iv$iv2;
        boolean z;
        Function1<? super Map.Entry<K, V>, Boolean> predicate = function1;
        Intrinsics.checkNotNullParameter(predicate, "predicate");
        boolean z2 = false;
        boolean removed = false;
        while (true) {
            lock$iv$iv = SnapshotStateMapKt.sync;
            synchronized (lock$iv$iv) {
                try {
                    StateRecord firstStateRecord = getFirstStateRecord();
                    Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                    StateRecord $this$withCurrent$iv$iv$iv = (StateMapStateRecord) firstStateRecord;
                    StateMapStateRecord current$iv = (StateMapStateRecord) SnapshotKt.current($this$withCurrent$iv$iv$iv);
                    map$runtime_release = current$iv.getMap$runtime_release();
                    currentModification$iv = current$iv.getModification$runtime_release();
                    Unit unit = Unit.INSTANCE;
                    InlineMarker.finallyStart(1);
                } catch (Throwable th) {
                    InlineMarker.finallyStart(1);
                    InlineMarker.finallyEnd(1);
                    throw th;
                }
            }
            InlineMarker.finallyEnd(1);
            Intrinsics.checkNotNull(map$runtime_release);
            PersistentMap.Builder builder$iv = map$runtime_release.builder();
            PersistentMap.Builder it = builder$iv;
            for (Map.Entry entry : entrySet()) {
                if (predicate.invoke(entry).booleanValue()) {
                    it.remove(entry.getKey());
                    removed = true;
                }
            }
            Unit unit2 = Unit.INSTANCE;
            PersistentMap newMap$iv = builder$iv.build();
            if (Intrinsics.areEqual(newMap$iv, map$runtime_release)) {
                break;
            }
            lock$iv$iv2 = SnapshotStateMapKt.sync;
            synchronized (lock$iv$iv2) {
                try {
                    StateRecord firstStateRecord2 = getFirstStateRecord();
                    Intrinsics.checkNotNull(firstStateRecord2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                    StateRecord $this$writable$iv$iv$iv = (StateMapStateRecord) firstStateRecord2;
                    SnapshotKt.getSnapshotInitializer();
                    Object lock$iv$iv$iv$iv$iv = SnapshotKt.getLock();
                    synchronized (lock$iv$iv$iv$iv$iv) {
                        try {
                            Snapshot current = Snapshot.Companion.getCurrent();
                            try {
                                try {
                                    StateMapStateRecord $this$mutate_u24lambda_u2411_u24lambda_u2410$iv = (StateMapStateRecord) SnapshotKt.writableRecord($this$writable$iv$iv$iv, this, current);
                                    boolean z3 = z2;
                                    try {
                                        int $i$f$removeIf$runtime_release = $this$mutate_u24lambda_u2411_u24lambda_u2410$iv.getModification$runtime_release();
                                        if ($i$f$removeIf$runtime_release == currentModification$iv) {
                                            $this$mutate_u24lambda_u2411_u24lambda_u2410$iv.setMap$runtime_release(newMap$iv);
                                            $this$mutate_u24lambda_u2411_u24lambda_u2410$iv.setModification$runtime_release($this$mutate_u24lambda_u2411_u24lambda_u2410$iv.getModification$runtime_release() + 1);
                                            z = true;
                                        } else {
                                            z = false;
                                        }
                                        try {
                                            InlineMarker.finallyStart(1);
                                            InlineMarker.finallyEnd(1);
                                            SnapshotKt.notifyWrite(current, this);
                                            InlineMarker.finallyStart(1);
                                            InlineMarker.finallyEnd(1);
                                            if (z) {
                                                break;
                                            }
                                            predicate = function1;
                                            z2 = z3;
                                        } catch (Throwable th2) {
                                            th = th2;
                                            InlineMarker.finallyStart(1);
                                            InlineMarker.finallyEnd(1);
                                            throw th;
                                        }
                                    } catch (Throwable th3) {
                                        th = th3;
                                        InlineMarker.finallyStart(1);
                                        InlineMarker.finallyEnd(1);
                                        throw th;
                                    }
                                } catch (Throwable th4) {
                                    th = th4;
                                }
                            } catch (Throwable th5) {
                                th = th5;
                            }
                        } catch (Throwable th6) {
                            th = th6;
                        }
                    }
                } catch (Throwable th7) {
                    th = th7;
                }
            }
        }
        return removed;
    }

    public final boolean any$runtime_release(Function1<? super Map.Entry<? extends K, ? extends V>, Boolean> predicate) {
        Intrinsics.checkNotNullParameter(predicate, "predicate");
        for (Map.Entry entry : (ImmutableSet) getReadable$runtime_release().getMap$runtime_release().entrySet()) {
            if (predicate.invoke(entry).booleanValue()) {
                return true;
            }
        }
        return false;
    }

    public final boolean all$runtime_release(Function1<? super Map.Entry<? extends K, ? extends V>, Boolean> predicate) {
        Intrinsics.checkNotNullParameter(predicate, "predicate");
        for (Map.Entry entry : (ImmutableSet) getReadable$runtime_release().getMap$runtime_release().entrySet()) {
            if (!predicate.invoke(entry).booleanValue()) {
                return false;
            }
        }
        return true;
    }

    public final Map<K, V> getDebuggerDisplayValue() {
        StateRecord firstStateRecord = getFirstStateRecord();
        Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
        StateRecord $this$withCurrent$iv$iv = (StateMapStateRecord) firstStateRecord;
        StateMapStateRecord $this$_get_debuggerDisplayValue__u24lambda_u247 = (StateMapStateRecord) SnapshotKt.current($this$withCurrent$iv$iv);
        return $this$_get_debuggerDisplayValue__u24lambda_u247.getMap$runtime_release();
    }

    private final <R> R withCurrent(Function1<? super StateMapStateRecord<K, V>, ? extends R> function1) {
        StateRecord firstStateRecord = getFirstStateRecord();
        Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
        StateRecord $this$withCurrent$iv = (StateMapStateRecord) firstStateRecord;
        return function1.invoke(SnapshotKt.current($this$withCurrent$iv));
    }

    private final <R> R writable(Function1<? super StateMapStateRecord<K, V>, ? extends R> function1) {
        Snapshot current;
        R invoke;
        StateRecord firstStateRecord = getFirstStateRecord();
        Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
        StateRecord $this$writable$iv = (StateMapStateRecord) firstStateRecord;
        SnapshotKt.getSnapshotInitializer();
        Object lock$iv$iv$iv = SnapshotKt.getLock();
        synchronized (lock$iv$iv$iv) {
            try {
                current = Snapshot.Companion.getCurrent();
                invoke = function1.invoke(SnapshotKt.writableRecord($this$writable$iv, this, current));
                InlineMarker.finallyStart(1);
            } catch (Throwable th) {
                InlineMarker.finallyStart(1);
                InlineMarker.finallyEnd(1);
                throw th;
            }
        }
        InlineMarker.finallyEnd(1);
        SnapshotKt.notifyWrite(current, this);
        return invoke;
    }

    private final <R> R mutate(Function1<? super Map<K, V>, ? extends R> function1) {
        Object lock$iv;
        R invoke;
        Object lock$iv2;
        boolean z;
        boolean z2 = false;
        while (true) {
            lock$iv = SnapshotStateMapKt.sync;
            synchronized (lock$iv) {
                try {
                    StateRecord firstStateRecord = getFirstStateRecord();
                    Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                    StateRecord $this$withCurrent$iv$iv = (StateMapStateRecord) firstStateRecord;
                    StateMapStateRecord current = (StateMapStateRecord) SnapshotKt.current($this$withCurrent$iv$iv);
                    PersistentMap<K, V> map$runtime_release = current.getMap$runtime_release();
                    try {
                        int currentModification = current.getModification$runtime_release();
                        Unit unit = Unit.INSTANCE;
                        InlineMarker.finallyStart(1);
                        InlineMarker.finallyEnd(1);
                        Intrinsics.checkNotNull(map$runtime_release);
                        PersistentMap.Builder builder = map$runtime_release.builder();
                        invoke = function1.invoke(builder);
                        PersistentMap newMap = builder.build();
                        if (Intrinsics.areEqual(newMap, map$runtime_release)) {
                            break;
                        }
                        lock$iv2 = SnapshotStateMapKt.sync;
                        synchronized (lock$iv2) {
                            try {
                                StateRecord firstStateRecord2 = getFirstStateRecord();
                                Intrinsics.checkNotNull(firstStateRecord2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                                StateRecord $this$writable$iv$iv = (StateMapStateRecord) firstStateRecord2;
                                SnapshotKt.getSnapshotInitializer();
                                Object lock$iv$iv$iv$iv = SnapshotKt.getLock();
                                synchronized (lock$iv$iv$iv$iv) {
                                    try {
                                        Snapshot current2 = Snapshot.Companion.getCurrent();
                                        try {
                                            boolean z3 = z2;
                                            try {
                                                StateMapStateRecord $this$mutate_u24lambda_u2411_u24lambda_u2410 = (StateMapStateRecord) SnapshotKt.writableRecord($this$writable$iv$iv, this, current2);
                                                if ($this$mutate_u24lambda_u2411_u24lambda_u2410.getModification$runtime_release() == currentModification) {
                                                    try {
                                                        $this$mutate_u24lambda_u2411_u24lambda_u2410.setMap$runtime_release(newMap);
                                                        $this$mutate_u24lambda_u2411_u24lambda_u2410.setModification$runtime_release($this$mutate_u24lambda_u2411_u24lambda_u2410.getModification$runtime_release() + 1);
                                                        z = true;
                                                    } catch (Throwable th) {
                                                        th = th;
                                                        InlineMarker.finallyStart(1);
                                                        InlineMarker.finallyEnd(1);
                                                        throw th;
                                                    }
                                                } else {
                                                    z = false;
                                                }
                                                try {
                                                    InlineMarker.finallyStart(1);
                                                    InlineMarker.finallyEnd(1);
                                                    try {
                                                        SnapshotKt.notifyWrite(current2, this);
                                                        InlineMarker.finallyStart(1);
                                                        InlineMarker.finallyEnd(1);
                                                        if (z) {
                                                            break;
                                                        }
                                                        z2 = z3;
                                                    } catch (Throwable th2) {
                                                        th = th2;
                                                        InlineMarker.finallyStart(1);
                                                        InlineMarker.finallyEnd(1);
                                                        throw th;
                                                    }
                                                } catch (Throwable th3) {
                                                    th = th3;
                                                    InlineMarker.finallyStart(1);
                                                    InlineMarker.finallyEnd(1);
                                                    throw th;
                                                }
                                            } catch (Throwable th4) {
                                                th = th4;
                                            }
                                        } catch (Throwable th5) {
                                            th = th5;
                                        }
                                    } catch (Throwable th6) {
                                        th = th6;
                                    }
                                }
                            } catch (Throwable th7) {
                                th = th7;
                            }
                        }
                    } catch (Throwable th8) {
                        th = th8;
                        InlineMarker.finallyStart(1);
                        InlineMarker.finallyEnd(1);
                        throw th;
                    }
                } catch (Throwable th9) {
                    th = th9;
                }
            }
        }
        return invoke;
    }

    private final void update(Function1<? super PersistentMap<K, ? extends V>, ? extends PersistentMap<K, ? extends V>> function1) {
        Object lock$iv;
        StateRecord firstStateRecord = getFirstStateRecord();
        Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
        StateRecord $this$withCurrent$iv$iv = (StateMapStateRecord) firstStateRecord;
        StateMapStateRecord $this$update_u24lambda_u2414 = (StateMapStateRecord) SnapshotKt.current($this$withCurrent$iv$iv);
        PersistentMap newMap = (PersistentMap<K, ? extends V>) function1.invoke($this$update_u24lambda_u2414.getMap$runtime_release());
        if (newMap != $this$update_u24lambda_u2414.getMap$runtime_release()) {
            lock$iv = SnapshotStateMapKt.sync;
            synchronized (lock$iv) {
                try {
                    StateRecord firstStateRecord2 = getFirstStateRecord();
                    Intrinsics.checkNotNull(firstStateRecord2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateMap.StateMapStateRecord<K of androidx.compose.runtime.snapshots.SnapshotStateMap, V of androidx.compose.runtime.snapshots.SnapshotStateMap>");
                    StateRecord $this$writable$iv$iv = (StateMapStateRecord) firstStateRecord2;
                    SnapshotKt.getSnapshotInitializer();
                    Object lock$iv$iv$iv$iv = SnapshotKt.getLock();
                    synchronized (lock$iv$iv$iv$iv) {
                        try {
                            try {
                                Snapshot current = Snapshot.Companion.getCurrent();
                                try {
                                    try {
                                        StateMapStateRecord $this$update_u24lambda_u2414_u24lambda_u2413_u24lambda_u2412 = (StateMapStateRecord) SnapshotKt.writableRecord($this$writable$iv$iv, this, current);
                                        $this$update_u24lambda_u2414_u24lambda_u2413_u24lambda_u2412.setMap$runtime_release(newMap);
                                        try {
                                            $this$update_u24lambda_u2414_u24lambda_u2413_u24lambda_u2412.setModification$runtime_release($this$update_u24lambda_u2414_u24lambda_u2413_u24lambda_u2412.getModification$runtime_release() + 1);
                                            InlineMarker.finallyStart(1);
                                            InlineMarker.finallyEnd(1);
                                            SnapshotKt.notifyWrite(current, this);
                                            InlineMarker.finallyStart(1);
                                            InlineMarker.finallyEnd(1);
                                        } catch (Throwable th) {
                                            th = th;
                                            InlineMarker.finallyStart(1);
                                            InlineMarker.finallyEnd(1);
                                            throw th;
                                        }
                                    } catch (Throwable th2) {
                                        th = th2;
                                    }
                                } catch (Throwable th3) {
                                    th = th3;
                                }
                            } catch (Throwable th4) {
                                th = th4;
                                InlineMarker.finallyStart(1);
                                InlineMarker.finallyEnd(1);
                                throw th;
                            }
                        } catch (Throwable th5) {
                            th = th5;
                        }
                    }
                } catch (Throwable th6) {
                    th = th6;
                }
            }
        }
    }

    /* compiled from: SnapshotStateMap.kt */
    @Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0002\b\u0003\b\u0000\u0018\u0000*\u0004\b\u0002\u0010\u0001*\u0004\b\u0003\u0010\u00022\u00020\u0003B\u001b\b\u0000\u0012\u0012\u0010\u0004\u001a\u000e\u0012\u0004\u0012\u00028\u0002\u0012\u0004\u0012\u00028\u00030\u0005¢\u0006\u0002\u0010\u0006J\u0010\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u0003H\u0016J\b\u0010\u0013\u001a\u00020\u0003H\u0016R&\u0010\u0004\u001a\u000e\u0012\u0004\u0012\u00028\u0002\u0012\u0004\u0012\u00028\u00030\u0005X\u0080\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0007\u0010\b\"\u0004\b\t\u0010\u0006R\u001a\u0010\n\u001a\u00020\u000bX\u0080\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000f¨\u0006\u0014"}, d2 = {"Landroidx/compose/runtime/snapshots/SnapshotStateMap$StateMapStateRecord;", "K", "V", "Landroidx/compose/runtime/snapshots/StateRecord;", "map", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/PersistentMap;", "(Landroidx/compose/runtime/external/kotlinx/collections/immutable/PersistentMap;)V", "getMap$runtime_release", "()Landroidx/compose/runtime/external/kotlinx/collections/immutable/PersistentMap;", "setMap$runtime_release", "modification", "", "getModification$runtime_release", "()I", "setModification$runtime_release", "(I)V", "assign", "", "value", "create", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class StateMapStateRecord<K, V> extends StateRecord {
        private PersistentMap<K, ? extends V> map;
        private int modification;

        public final PersistentMap<K, V> getMap$runtime_release() {
            return (PersistentMap<K, ? extends V>) this.map;
        }

        public final void setMap$runtime_release(PersistentMap<K, ? extends V> persistentMap) {
            Intrinsics.checkNotNullParameter(persistentMap, "<set-?>");
            this.map = persistentMap;
        }

        public StateMapStateRecord(PersistentMap<K, ? extends V> map) {
            Intrinsics.checkNotNullParameter(map, "map");
            this.map = map;
        }

        public final int getModification$runtime_release() {
            return this.modification;
        }

        public final void setModification$runtime_release(int i) {
            this.modification = i;
        }

        @Override // androidx.compose.runtime.snapshots.StateRecord
        public void assign(StateRecord value) {
            Object lock$iv;
            Intrinsics.checkNotNullParameter(value, "value");
            StateMapStateRecord other = (StateMapStateRecord) value;
            lock$iv = SnapshotStateMapKt.sync;
            synchronized (lock$iv) {
                this.map = other.map;
                this.modification = other.modification;
                Unit unit = Unit.INSTANCE;
            }
        }

        @Override // androidx.compose.runtime.snapshots.StateRecord
        public StateRecord create() {
            return new StateMapStateRecord(this.map);
        }
    }
}
