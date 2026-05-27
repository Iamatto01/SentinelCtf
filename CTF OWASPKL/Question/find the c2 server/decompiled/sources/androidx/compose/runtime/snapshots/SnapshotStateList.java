package androidx.compose.runtime.snapshots;

import androidx.compose.runtime.external.kotlinx.collections.immutable.ExtensionsKt;
import androidx.compose.runtime.external.kotlinx.collections.immutable.PersistentList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.CollectionToArray;
import kotlin.jvm.internal.InlineMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.markers.KMutableList;
/* compiled from: SnapshotStateList.kt */
@Metadata(d1 = {"\u0000n\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u001e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010)\n\u0002\b\u0002\n\u0002\u0010+\n\u0002\b\u0017\n\u0002\u0018\u0002\n\u0002\b\u0003\b\u0007\u0018\u0000*\u0004\b\u0000\u0010\u00012\b\u0012\u0004\u0012\u0002H\u00010\u00022\u00020\u0003:\u0001NB\u0005¢\u0006\u0002\u0010\u0004J\u0015\u0010\u001a\u001a\u00020\u001b2\u0006\u0010\u001c\u001a\u00028\u0000H\u0016¢\u0006\u0002\u0010\u001dJ\u001d\u0010\u001a\u001a\u00020\u001e2\u0006\u0010\u001f\u001a\u00020\u00102\u0006\u0010\u001c\u001a\u00028\u0000H\u0016¢\u0006\u0002\u0010 J\u001e\u0010!\u001a\u00020\u001b2\u0006\u0010\u001f\u001a\u00020\u00102\f\u0010\"\u001a\b\u0012\u0004\u0012\u00028\u00000#H\u0016J\u0016\u0010!\u001a\u00020\u001b2\f\u0010\"\u001a\b\u0012\u0004\u0012\u00028\u00000#H\u0016J\b\u0010$\u001a\u00020\u001eH\u0016J)\u0010%\u001a\u00020\u001b2\u001e\u0010&\u001a\u001a\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000(\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000(0'H\u0082\bJ\u0016\u0010)\u001a\u00020\u001b2\u0006\u0010\u001c\u001a\u00028\u0000H\u0096\u0002¢\u0006\u0002\u0010\u001dJ\u0016\u0010*\u001a\u00020\u001b2\f\u0010\"\u001a\b\u0012\u0004\u0012\u00028\u00000#H\u0016J\u0016\u0010+\u001a\u00028\u00002\u0006\u0010\u001f\u001a\u00020\u0010H\u0096\u0002¢\u0006\u0002\u0010,J\u0015\u0010-\u001a\u00020\u00102\u0006\u0010\u001c\u001a\u00028\u0000H\u0016¢\u0006\u0002\u0010.J\b\u0010/\u001a\u00020\u001bH\u0016J\u000f\u00100\u001a\b\u0012\u0004\u0012\u00028\u000001H\u0096\u0002J\u0015\u00102\u001a\u00020\u00102\u0006\u0010\u001c\u001a\u00028\u0000H\u0016¢\u0006\u0002\u0010.J\u000e\u00103\u001a\b\u0012\u0004\u0012\u00028\u000004H\u0016J\u0016\u00103\u001a\b\u0012\u0004\u0012\u00028\u0000042\u0006\u0010\u001f\u001a\u00020\u0010H\u0016J.\u00105\u001a\u0002H6\"\u0004\b\u0001\u001062\u0018\u0010&\u001a\u0014\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000\u0002\u0012\u0004\u0012\u0002H60'H\u0082\b¢\u0006\u0002\u00107J\"\u00108\u001a\u00020\u001b2\u0018\u0010&\u001a\u0014\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000\u0002\u0012\u0004\u0012\u00020\u001b0'H\u0002J\u0010\u00109\u001a\u00020\u001e2\u0006\u0010:\u001a\u00020\u000bH\u0016J\u0015\u0010;\u001a\u00020\u001b2\u0006\u0010\u001c\u001a\u00028\u0000H\u0016¢\u0006\u0002\u0010\u001dJ\u0016\u0010<\u001a\u00020\u001b2\f\u0010\"\u001a\b\u0012\u0004\u0012\u00028\u00000#H\u0016J\u0015\u0010=\u001a\u00028\u00002\u0006\u0010\u001f\u001a\u00020\u0010H\u0016¢\u0006\u0002\u0010,J\u0016\u0010>\u001a\u00020\u001e2\u0006\u0010?\u001a\u00020\u00102\u0006\u0010@\u001a\u00020\u0010J\u0016\u0010A\u001a\u00020\u001b2\f\u0010\"\u001a\b\u0012\u0004\u0012\u00028\u00000#H\u0016J+\u0010B\u001a\u00020\u00102\f\u0010\"\u001a\b\u0012\u0004\u0012\u00028\u00000#2\u0006\u0010C\u001a\u00020\u00102\u0006\u0010D\u001a\u00020\u0010H\u0000¢\u0006\u0002\bEJ\u001e\u0010F\u001a\u00028\u00002\u0006\u0010\u001f\u001a\u00020\u00102\u0006\u0010\u001c\u001a\u00028\u0000H\u0096\u0002¢\u0006\u0002\u0010GJ\u001e\u0010H\u001a\b\u0012\u0004\u0012\u00028\u00000\u00022\u0006\u0010?\u001a\u00020\u00102\u0006\u0010@\u001a\u00020\u0010H\u0016J\f\u0010I\u001a\b\u0012\u0004\u0012\u00028\u00000\u0006J)\u0010J\u001a\u00020\u001e2\u001e\u0010&\u001a\u001a\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000(\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000(0'H\u0082\bJ3\u0010K\u001a\u0002H6\"\u0004\b\u0001\u001062\u001d\u0010&\u001a\u0019\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000\u0014\u0012\u0004\u0012\u0002H60'¢\u0006\u0002\bLH\u0082\b¢\u0006\u0002\u00107J3\u0010M\u001a\u0002H6\"\u0004\b\u0001\u001062\u001d\u0010&\u001a\u0019\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000\u0014\u0012\u0004\u0012\u0002H60'¢\u0006\u0002\bLH\u0082\b¢\u0006\u0002\u00107R \u0010\u0005\u001a\b\u0012\u0004\u0012\u00028\u00000\u00068AX\u0080\u0004¢\u0006\f\u0012\u0004\b\u0007\u0010\u0004\u001a\u0004\b\b\u0010\tR\u001e\u0010\f\u001a\u00020\u000b2\u0006\u0010\n\u001a\u00020\u000b@RX\u0096\u000e¢\u0006\b\n\u0000\u001a\u0004\b\r\u0010\u000eR\u0014\u0010\u000f\u001a\u00020\u00108@X\u0080\u0004¢\u0006\u0006\u001a\u0004\b\u0011\u0010\u0012R \u0010\u0013\u001a\b\u0012\u0004\u0012\u00028\u00000\u00148@X\u0080\u0004¢\u0006\f\u0012\u0004\b\u0015\u0010\u0004\u001a\u0004\b\u0016\u0010\u0017R\u0014\u0010\u0018\u001a\u00020\u00108VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0019\u0010\u0012¨\u0006O"}, d2 = {"Landroidx/compose/runtime/snapshots/SnapshotStateList;", "T", "", "Landroidx/compose/runtime/snapshots/StateObject;", "()V", "debuggerDisplayValue", "", "getDebuggerDisplayValue$annotations", "getDebuggerDisplayValue", "()Ljava/util/List;", "<set-?>", "Landroidx/compose/runtime/snapshots/StateRecord;", "firstStateRecord", "getFirstStateRecord", "()Landroidx/compose/runtime/snapshots/StateRecord;", "modification", "", "getModification$runtime_release", "()I", "readable", "Landroidx/compose/runtime/snapshots/SnapshotStateList$StateListStateRecord;", "getReadable$runtime_release$annotations", "getReadable$runtime_release", "()Landroidx/compose/runtime/snapshots/SnapshotStateList$StateListStateRecord;", "size", "getSize", "add", "", "element", "(Ljava/lang/Object;)Z", "", "index", "(ILjava/lang/Object;)V", "addAll", "elements", "", "clear", "conditionalUpdate", "block", "Lkotlin/Function1;", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/PersistentList;", "contains", "containsAll", "get", "(I)Ljava/lang/Object;", "indexOf", "(Ljava/lang/Object;)I", "isEmpty", "iterator", "", "lastIndexOf", "listIterator", "", "mutate", "R", "(Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;", "mutateBoolean", "prependStateRecord", "value", "remove", "removeAll", "removeAt", "removeRange", "fromIndex", "toIndex", "retainAll", "retainAllInRange", "start", "end", "retainAllInRange$runtime_release", "set", "(ILjava/lang/Object;)Ljava/lang/Object;", "subList", "toList", "update", "withCurrent", "Lkotlin/ExtensionFunctionType;", "writable", "StateListStateRecord", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class SnapshotStateList<T> implements List<T>, StateObject, KMutableList {
    public static final int $stable = 0;
    private StateRecord firstStateRecord = new StateListStateRecord(ExtensionsKt.persistentListOf());

    public static /* synthetic */ void getDebuggerDisplayValue$annotations() {
    }

    public static /* synthetic */ void getReadable$runtime_release$annotations() {
    }

    @Override // java.util.List, java.util.Collection
    public Object[] toArray() {
        return CollectionToArray.toArray(this);
    }

    @Override // java.util.List, java.util.Collection
    public <T> T[] toArray(T[] array) {
        Intrinsics.checkNotNullParameter(array, "array");
        return (T[]) CollectionToArray.toArray(this, array);
    }

    @Override // java.util.List
    public final /* bridge */ T remove(int index) {
        return removeAt(index);
    }

    @Override // java.util.List, java.util.Collection
    public final /* bridge */ int size() {
        return getSize();
    }

    @Override // androidx.compose.runtime.snapshots.StateObject
    public StateRecord getFirstStateRecord() {
        return this.firstStateRecord;
    }

    @Override // androidx.compose.runtime.snapshots.StateObject
    public void prependStateRecord(StateRecord value) {
        Intrinsics.checkNotNullParameter(value, "value");
        value.setNext$runtime_release(getFirstStateRecord());
        this.firstStateRecord = (StateListStateRecord) value;
    }

    public final List<T> toList() {
        return getReadable$runtime_release().getList$runtime_release();
    }

    public final int getModification$runtime_release() {
        StateRecord firstStateRecord = getFirstStateRecord();
        Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
        StateRecord $this$withCurrent$iv$iv = (StateListStateRecord) firstStateRecord;
        StateListStateRecord $this$_get_modification__u24lambda_u240 = (StateListStateRecord) SnapshotKt.current($this$withCurrent$iv$iv);
        return $this$_get_modification__u24lambda_u240.getModification$runtime_release();
    }

    public final StateListStateRecord<T> getReadable$runtime_release() {
        StateRecord firstStateRecord = getFirstStateRecord();
        Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
        return (StateListStateRecord) SnapshotKt.readable((StateListStateRecord) firstStateRecord, this);
    }

    /* compiled from: SnapshotStateList.kt */
    @Metadata(d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0002\b\u0003\b\u0000\u0018\u0000*\u0004\b\u0001\u0010\u00012\u00020\u0002B\u0015\b\u0000\u0012\f\u0010\u0003\u001a\b\u0012\u0004\u0012\u00028\u00010\u0004¢\u0006\u0002\u0010\u0005J\u0010\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u0011\u001a\u00020\u0002H\u0016J\b\u0010\u0012\u001a\u00020\u0002H\u0016R \u0010\u0003\u001a\b\u0012\u0004\u0012\u00028\u00010\u0004X\u0080\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0006\u0010\u0007\"\u0004\b\b\u0010\u0005R\u001a\u0010\t\u001a\u00020\nX\u0080\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000e¨\u0006\u0013"}, d2 = {"Landroidx/compose/runtime/snapshots/SnapshotStateList$StateListStateRecord;", "T", "Landroidx/compose/runtime/snapshots/StateRecord;", "list", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/PersistentList;", "(Landroidx/compose/runtime/external/kotlinx/collections/immutable/PersistentList;)V", "getList$runtime_release", "()Landroidx/compose/runtime/external/kotlinx/collections/immutable/PersistentList;", "setList$runtime_release", "modification", "", "getModification$runtime_release", "()I", "setModification$runtime_release", "(I)V", "assign", "", "value", "create", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class StateListStateRecord<T> extends StateRecord {
        private PersistentList<? extends T> list;
        private int modification;

        public final PersistentList<T> getList$runtime_release() {
            return (PersistentList<? extends T>) this.list;
        }

        public final void setList$runtime_release(PersistentList<? extends T> persistentList) {
            Intrinsics.checkNotNullParameter(persistentList, "<set-?>");
            this.list = persistentList;
        }

        public StateListStateRecord(PersistentList<? extends T> list) {
            Intrinsics.checkNotNullParameter(list, "list");
            this.list = list;
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
            lock$iv = SnapshotStateListKt.sync;
            synchronized (lock$iv) {
                this.list = ((StateListStateRecord) value).list;
                this.modification = ((StateListStateRecord) value).modification;
                Unit unit = Unit.INSTANCE;
            }
        }

        @Override // androidx.compose.runtime.snapshots.StateRecord
        public StateRecord create() {
            return new StateListStateRecord(this.list);
        }
    }

    public int getSize() {
        return getReadable$runtime_release().getList$runtime_release().size();
    }

    @Override // java.util.List, java.util.Collection
    public boolean contains(Object element) {
        return getReadable$runtime_release().getList$runtime_release().contains(element);
    }

    @Override // java.util.List, java.util.Collection
    public boolean containsAll(Collection<? extends Object> elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        return getReadable$runtime_release().getList$runtime_release().containsAll(elements);
    }

    @Override // java.util.List
    public T get(int index) {
        return (T) getReadable$runtime_release().getList$runtime_release().get(index);
    }

    @Override // java.util.List
    public int indexOf(Object element) {
        return getReadable$runtime_release().getList$runtime_release().indexOf(element);
    }

    @Override // java.util.List, java.util.Collection
    public boolean isEmpty() {
        return getReadable$runtime_release().getList$runtime_release().isEmpty();
    }

    @Override // java.util.List, java.util.Collection, java.lang.Iterable
    public Iterator<T> iterator() {
        return listIterator();
    }

    @Override // java.util.List
    public int lastIndexOf(Object element) {
        return getReadable$runtime_release().getList$runtime_release().lastIndexOf(element);
    }

    @Override // java.util.List
    public ListIterator<T> listIterator() {
        return new StateListIterator(this, 0);
    }

    @Override // java.util.List
    public ListIterator<T> listIterator(int index) {
        return new StateListIterator(this, index);
    }

    @Override // java.util.List
    public List<T> subList(int fromIndex, int toIndex) {
        boolean z = true;
        if (!(fromIndex >= 0 && fromIndex <= toIndex) || toIndex > size()) {
            z = false;
        }
        if (!z) {
            throw new IllegalArgumentException("Failed requirement.".toString());
        }
        return new SubList(this, fromIndex, toIndex);
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x00b6, code lost:
        androidx.compose.runtime.snapshots.SnapshotKt.notifyWrite(r21, r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00c7, code lost:
        if (r24 == false) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00c9, code lost:
        return true;
     */
    @Override // java.util.List, java.util.Collection
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean add(T r26) {
        /*
            Method dump skipped, instructions count: 256
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.SnapshotStateList.add(java.lang.Object):boolean");
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x00c1, code lost:
        androidx.compose.runtime.snapshots.SnapshotKt.notifyWrite(r24, r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x00d3, code lost:
        if (r27 == false) goto L38;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00db, code lost:
        return;
     */
    @Override // java.util.List
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void add(int r29, T r30) {
        /*
            Method dump skipped, instructions count: 275
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.SnapshotStateList.add(int, java.lang.Object):void");
    }

    @Override // java.util.List
    public boolean addAll(final int index, final Collection<? extends T> elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        return mutateBoolean(new Function1<List<T>, Boolean>() { // from class: androidx.compose.runtime.snapshots.SnapshotStateList$addAll$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Boolean invoke(Object p1) {
                return invoke((List) ((List) p1));
            }

            public final Boolean invoke(List<T> it) {
                Intrinsics.checkNotNullParameter(it, "it");
                return Boolean.valueOf(it.addAll(index, elements));
            }
        });
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x00b8, code lost:
        androidx.compose.runtime.snapshots.SnapshotKt.notifyWrite(r21, r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00c9, code lost:
        if (r23 == false) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00cb, code lost:
        return true;
     */
    @Override // java.util.List, java.util.Collection
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean addAll(java.util.Collection<? extends T> r25) {
        /*
            Method dump skipped, instructions count: 248
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.SnapshotStateList.addAll(java.util.Collection):boolean");
    }

    @Override // java.util.List, java.util.Collection
    public void clear() {
        Object lock$iv;
        Snapshot current;
        lock$iv = SnapshotStateListKt.sync;
        synchronized (lock$iv) {
            StateRecord firstStateRecord = getFirstStateRecord();
            Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
            StateRecord $this$writable$iv$iv = (StateListStateRecord) firstStateRecord;
            SnapshotKt.getSnapshotInitializer();
            Object lock$iv$iv$iv$iv = SnapshotKt.getLock();
            synchronized (lock$iv$iv$iv$iv) {
                current = Snapshot.Companion.getCurrent();
                StateListStateRecord $this$clear_u24lambda_u245_u24lambda_u244 = (StateListStateRecord) SnapshotKt.writableRecord($this$writable$iv$iv, this, current);
                $this$clear_u24lambda_u245_u24lambda_u244.setList$runtime_release(ExtensionsKt.persistentListOf());
                $this$clear_u24lambda_u245_u24lambda_u244.setModification$runtime_release($this$clear_u24lambda_u245_u24lambda_u244.getModification$runtime_release() + 1);
            }
            SnapshotKt.notifyWrite(current, this);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x00b6, code lost:
        androidx.compose.runtime.snapshots.SnapshotKt.notifyWrite(r21, r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00c7, code lost:
        if (r24 == false) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00c9, code lost:
        return true;
     */
    @Override // java.util.List, java.util.Collection
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean remove(java.lang.Object r26) {
        /*
            Method dump skipped, instructions count: 256
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.SnapshotStateList.remove(java.lang.Object):boolean");
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x00b8, code lost:
        androidx.compose.runtime.snapshots.SnapshotKt.notifyWrite(r21, r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00c9, code lost:
        if (r23 == false) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00cb, code lost:
        return true;
     */
    @Override // java.util.List, java.util.Collection
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean removeAll(java.util.Collection<? extends java.lang.Object> r25) {
        /*
            Method dump skipped, instructions count: 248
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.SnapshotStateList.removeAll(java.util.Collection):boolean");
    }

    public T removeAt(int index) {
        Object lock$iv$iv$iv;
        Object lock$iv$iv$iv2;
        boolean z;
        T t = get(index);
        Object it = t;
        boolean z2 = false;
        SnapshotStateList snapshotStateList = this;
        boolean z3 = false;
        SnapshotStateList this_$iv$iv = snapshotStateList;
        SnapshotStateList $this$conditionalUpdate_u24lambda_u2423$iv$iv = this_$iv$iv;
        while (true) {
            lock$iv$iv$iv = SnapshotStateListKt.sync;
            synchronized (lock$iv$iv$iv) {
                Object it2 = it;
                try {
                    StateRecord it3 = $this$conditionalUpdate_u24lambda_u2423$iv$iv.getFirstStateRecord();
                    boolean z4 = z2;
                    try {
                        Intrinsics.checkNotNull(it3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                        StateRecord $this$withCurrent$iv$iv$iv$iv = (StateListStateRecord) it3;
                        StateListStateRecord current$iv$iv = (StateListStateRecord) SnapshotKt.current($this$withCurrent$iv$iv$iv$iv);
                        int currentModification$iv$iv = current$iv$iv.getModification$runtime_release();
                        PersistentList<T> list$runtime_release = current$iv$iv.getList$runtime_release();
                        Unit unit = Unit.INSTANCE;
                        Intrinsics.checkNotNull(list$runtime_release);
                        PersistentList it4 = list$runtime_release.removeAt(index);
                        if (Intrinsics.areEqual(it4, list$runtime_release)) {
                            break;
                        }
                        lock$iv$iv$iv2 = SnapshotStateListKt.sync;
                        synchronized (lock$iv$iv$iv2) {
                            SnapshotStateList<T> snapshotStateList2 = snapshotStateList;
                            try {
                                StateRecord firstStateRecord = $this$conditionalUpdate_u24lambda_u2423$iv$iv.getFirstStateRecord();
                                boolean z5 = z3;
                                try {
                                    Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                                    StateRecord $this$writable$iv$iv$iv$iv = (StateListStateRecord) firstStateRecord;
                                    SnapshotKt.getSnapshotInitializer();
                                    Object lock$iv$iv$iv$iv$iv$iv = SnapshotKt.getLock();
                                    synchronized (lock$iv$iv$iv$iv$iv$iv) {
                                        try {
                                            Snapshot current = Snapshot.Companion.getCurrent();
                                            try {
                                                SnapshotStateList this_$iv$iv2 = this_$iv$iv;
                                                try {
                                                    StateListStateRecord $this$conditionalUpdate_u24lambda_u2423_u24lambda_u2422_u24lambda_u2421$iv$iv = (StateListStateRecord) SnapshotKt.writableRecord($this$writable$iv$iv$iv$iv, $this$conditionalUpdate_u24lambda_u2423$iv$iv, current);
                                                    try {
                                                        if ($this$conditionalUpdate_u24lambda_u2423_u24lambda_u2422_u24lambda_u2421$iv$iv.getModification$runtime_release() == currentModification$iv$iv) {
                                                            try {
                                                                $this$conditionalUpdate_u24lambda_u2423_u24lambda_u2422_u24lambda_u2421$iv$iv.setList$runtime_release(it4);
                                                                z = true;
                                                                $this$conditionalUpdate_u24lambda_u2423_u24lambda_u2422_u24lambda_u2421$iv$iv.setModification$runtime_release($this$conditionalUpdate_u24lambda_u2423_u24lambda_u2422_u24lambda_u2421$iv$iv.getModification$runtime_release() + 1);
                                                            } catch (Throwable th) {
                                                                th = th;
                                                                throw th;
                                                            }
                                                        } else {
                                                            z = false;
                                                        }
                                                        try {
                                                            try {
                                                                SnapshotKt.notifyWrite(current, $this$conditionalUpdate_u24lambda_u2423$iv$iv);
                                                                if (z) {
                                                                    break;
                                                                }
                                                                it = it2;
                                                                z2 = z4;
                                                                snapshotStateList = snapshotStateList2;
                                                                z3 = z5;
                                                                this_$iv$iv = this_$iv$iv2;
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
                                        } catch (Throwable th7) {
                                            th = th7;
                                        }
                                    }
                                } catch (Throwable th8) {
                                    th = th8;
                                }
                            } catch (Throwable th9) {
                                th = th9;
                            }
                        }
                    } catch (Throwable th10) {
                        th = th10;
                        throw th;
                    }
                } catch (Throwable th11) {
                    th = th11;
                }
            }
        }
        return t;
    }

    @Override // java.util.List, java.util.Collection
    public boolean retainAll(final Collection<? extends Object> elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        return mutateBoolean(new Function1<List<T>, Boolean>() { // from class: androidx.compose.runtime.snapshots.SnapshotStateList$retainAll$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            public final Boolean invoke(List<T> it) {
                Intrinsics.checkNotNullParameter(it, "it");
                return Boolean.valueOf(it.retainAll(elements));
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Boolean invoke(Object p1) {
                return invoke((List) ((List) p1));
            }
        });
    }

    @Override // java.util.List
    public T set(int index, T t) {
        Object lock$iv$iv$iv;
        StateRecord it;
        boolean z;
        Object lock$iv$iv$iv2;
        boolean z2;
        T t2 = get(index);
        Object it2 = t2;
        boolean z3 = false;
        SnapshotStateList snapshotStateList = this;
        boolean z4 = false;
        SnapshotStateList this_$iv$iv = snapshotStateList;
        SnapshotStateList $this$conditionalUpdate_u24lambda_u2423$iv$iv = this_$iv$iv;
        while (true) {
            lock$iv$iv$iv = SnapshotStateListKt.sync;
            synchronized (lock$iv$iv$iv) {
                Object it3 = it2;
                try {
                    it = $this$conditionalUpdate_u24lambda_u2423$iv$iv.getFirstStateRecord();
                    z = z3;
                } catch (Throwable th) {
                    th = th;
                }
                try {
                    Intrinsics.checkNotNull(it, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                    StateRecord $this$withCurrent$iv$iv$iv$iv = (StateListStateRecord) it;
                    StateListStateRecord current$iv$iv = (StateListStateRecord) SnapshotKt.current($this$withCurrent$iv$iv$iv$iv);
                    int currentModification$iv$iv = current$iv$iv.getModification$runtime_release();
                    PersistentList<T> list$runtime_release = current$iv$iv.getList$runtime_release();
                    Unit unit = Unit.INSTANCE;
                    Intrinsics.checkNotNull(list$runtime_release);
                    PersistentList it4 = list$runtime_release.set(index, (int) t);
                    if (Intrinsics.areEqual(it4, list$runtime_release)) {
                        break;
                    }
                    lock$iv$iv$iv2 = SnapshotStateListKt.sync;
                    synchronized (lock$iv$iv$iv2) {
                        SnapshotStateList<T> snapshotStateList2 = snapshotStateList;
                        try {
                            StateRecord firstStateRecord = $this$conditionalUpdate_u24lambda_u2423$iv$iv.getFirstStateRecord();
                            boolean z5 = z4;
                            try {
                                Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                                StateRecord $this$writable$iv$iv$iv$iv = (StateListStateRecord) firstStateRecord;
                                SnapshotKt.getSnapshotInitializer();
                                Object lock$iv$iv$iv$iv$iv$iv = SnapshotKt.getLock();
                                synchronized (lock$iv$iv$iv$iv$iv$iv) {
                                    try {
                                        Snapshot current = Snapshot.Companion.getCurrent();
                                        try {
                                            SnapshotStateList this_$iv$iv2 = this_$iv$iv;
                                            try {
                                                StateListStateRecord $this$conditionalUpdate_u24lambda_u2423_u24lambda_u2422_u24lambda_u2421$iv$iv = (StateListStateRecord) SnapshotKt.writableRecord($this$writable$iv$iv$iv$iv, $this$conditionalUpdate_u24lambda_u2423$iv$iv, current);
                                                try {
                                                    if ($this$conditionalUpdate_u24lambda_u2423_u24lambda_u2422_u24lambda_u2421$iv$iv.getModification$runtime_release() == currentModification$iv$iv) {
                                                        try {
                                                            $this$conditionalUpdate_u24lambda_u2423_u24lambda_u2422_u24lambda_u2421$iv$iv.setList$runtime_release(it4);
                                                            z2 = true;
                                                            $this$conditionalUpdate_u24lambda_u2423_u24lambda_u2422_u24lambda_u2421$iv$iv.setModification$runtime_release($this$conditionalUpdate_u24lambda_u2423_u24lambda_u2422_u24lambda_u2421$iv$iv.getModification$runtime_release() + 1);
                                                        } catch (Throwable th2) {
                                                            th = th2;
                                                            throw th;
                                                        }
                                                    } else {
                                                        z2 = false;
                                                    }
                                                    try {
                                                        try {
                                                            SnapshotKt.notifyWrite(current, $this$conditionalUpdate_u24lambda_u2423$iv$iv);
                                                            if (z2) {
                                                                break;
                                                            }
                                                            it2 = it3;
                                                            z3 = z;
                                                            snapshotStateList = snapshotStateList2;
                                                            z4 = z5;
                                                            this_$iv$iv = this_$iv$iv2;
                                                        } catch (Throwable th3) {
                                                            th = th3;
                                                            throw th;
                                                        }
                                                    } catch (Throwable th4) {
                                                        th = th4;
                                                        throw th;
                                                    }
                                                } catch (Throwable th5) {
                                                    th = th5;
                                                }
                                            } catch (Throwable th6) {
                                                th = th6;
                                            }
                                        } catch (Throwable th7) {
                                            th = th7;
                                        }
                                    } catch (Throwable th8) {
                                        th = th8;
                                    }
                                }
                            } catch (Throwable th9) {
                                th = th9;
                            }
                        } catch (Throwable th10) {
                            th = th10;
                        }
                    }
                } catch (Throwable th11) {
                    th = th11;
                    throw th;
                }
            }
        }
        return t2;
    }

    /* JADX WARN: Code restructure failed: missing block: B:29:0x00be, code lost:
        androidx.compose.runtime.snapshots.SnapshotKt.notifyWrite(r21, r13);
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x00cf, code lost:
        if (r24 == false) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:?, code lost:
        return;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void removeRange(int r26, int r27) {
        /*
            Method dump skipped, instructions count: 268
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.SnapshotStateList.removeRange(int, int):void");
    }

    public final int retainAllInRange$runtime_release(Collection<? extends T> collection, int start, int end) {
        Object lock$iv$iv;
        int currentModification$iv;
        PersistentList<T> list$runtime_release;
        Object lock$iv$iv2;
        boolean z;
        Collection<? extends T> elements = collection;
        Intrinsics.checkNotNullParameter(elements, "elements");
        int startSize = size();
        SnapshotStateList this_$iv = this;
        while (true) {
            lock$iv$iv = SnapshotStateListKt.sync;
            synchronized (lock$iv$iv) {
                try {
                    StateRecord firstStateRecord = this_$iv.getFirstStateRecord();
                    Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                    StateRecord $this$withCurrent$iv$iv$iv = (StateListStateRecord) firstStateRecord;
                    StateListStateRecord current$iv = (StateListStateRecord) SnapshotKt.current($this$withCurrent$iv$iv$iv);
                    currentModification$iv = current$iv.getModification$runtime_release();
                    list$runtime_release = current$iv.getList$runtime_release();
                    Unit unit = Unit.INSTANCE;
                } catch (Throwable th) {
                    throw th;
                }
            }
            Intrinsics.checkNotNull(list$runtime_release);
            PersistentList.Builder builder$iv = list$runtime_release.builder();
            PersistentList.Builder it = builder$iv;
            it.subList(start, end).retainAll(elements);
            Unit unit2 = Unit.INSTANCE;
            PersistentList newList$iv = builder$iv.build();
            if (Intrinsics.areEqual(newList$iv, list$runtime_release)) {
                break;
            }
            lock$iv$iv2 = SnapshotStateListKt.sync;
            synchronized (lock$iv$iv2) {
                SnapshotStateList this_$iv$iv = this_$iv;
                try {
                    StateRecord firstStateRecord2 = this_$iv$iv.getFirstStateRecord();
                    Intrinsics.checkNotNull(firstStateRecord2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                    StateRecord $this$writable$iv$iv$iv = (StateListStateRecord) firstStateRecord2;
                    SnapshotKt.getSnapshotInitializer();
                    Object lock$iv$iv$iv$iv$iv = SnapshotKt.getLock();
                    synchronized (lock$iv$iv$iv$iv$iv) {
                        try {
                            Snapshot current = Snapshot.Companion.getCurrent();
                            try {
                                SnapshotStateList this_$iv2 = this_$iv;
                                try {
                                    StateListStateRecord $this$mutate_u24lambda_u2418_u24lambda_u2417$iv = (StateListStateRecord) SnapshotKt.writableRecord($this$writable$iv$iv$iv, this_$iv$iv, current);
                                    try {
                                        if ($this$mutate_u24lambda_u2418_u24lambda_u2417$iv.getModification$runtime_release() == currentModification$iv) {
                                            $this$mutate_u24lambda_u2418_u24lambda_u2417$iv.setList$runtime_release(newList$iv);
                                            z = true;
                                            $this$mutate_u24lambda_u2418_u24lambda_u2417$iv.setModification$runtime_release($this$mutate_u24lambda_u2418_u24lambda_u2417$iv.getModification$runtime_release() + 1);
                                        } else {
                                            z = false;
                                        }
                                        try {
                                            SnapshotKt.notifyWrite(current, this_$iv$iv);
                                            if (z) {
                                                break;
                                            }
                                            elements = collection;
                                            this_$iv = this_$iv2;
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
        return startSize - size();
    }

    public final List<T> getDebuggerDisplayValue() {
        StateRecord firstStateRecord = getFirstStateRecord();
        Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
        StateRecord $this$withCurrent$iv$iv = (StateListStateRecord) firstStateRecord;
        StateListStateRecord $this$_get_debuggerDisplayValue__u24lambda_u2414 = (StateListStateRecord) SnapshotKt.current($this$withCurrent$iv$iv);
        return $this$_get_debuggerDisplayValue__u24lambda_u2414.getList$runtime_release();
    }

    private final <R> R writable(Function1<? super StateListStateRecord<T>, ? extends R> function1) {
        Snapshot current;
        R invoke;
        StateRecord firstStateRecord = getFirstStateRecord();
        Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
        StateRecord $this$writable$iv = (StateListStateRecord) firstStateRecord;
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

    private final <R> R withCurrent(Function1<? super StateListStateRecord<T>, ? extends R> function1) {
        StateRecord firstStateRecord = getFirstStateRecord();
        Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
        StateRecord $this$withCurrent$iv = (StateListStateRecord) firstStateRecord;
        return function1.invoke(SnapshotKt.current($this$withCurrent$iv));
    }

    private final boolean mutateBoolean(Function1<? super List<T>, Boolean> function1) {
        Object lock$iv$iv;
        int currentModification$iv;
        PersistentList<T> list$runtime_release;
        Object result$iv;
        Object lock$iv$iv2;
        boolean z;
        SnapshotStateList this_$iv = this;
        boolean z2 = false;
        while (true) {
            lock$iv$iv = SnapshotStateListKt.sync;
            synchronized (lock$iv$iv) {
                try {
                    StateRecord firstStateRecord = this_$iv.getFirstStateRecord();
                    Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                    StateRecord $this$withCurrent$iv$iv$iv = (StateListStateRecord) firstStateRecord;
                    StateListStateRecord current$iv = (StateListStateRecord) SnapshotKt.current($this$withCurrent$iv$iv$iv);
                    currentModification$iv = current$iv.getModification$runtime_release();
                    list$runtime_release = current$iv.getList$runtime_release();
                    Unit unit = Unit.INSTANCE;
                } catch (Throwable th) {
                    throw th;
                }
            }
            Intrinsics.checkNotNull(list$runtime_release);
            PersistentList.Builder builder$iv = list$runtime_release.builder();
            result$iv = function1.invoke(builder$iv);
            PersistentList newList$iv = builder$iv.build();
            if (Intrinsics.areEqual(newList$iv, list$runtime_release)) {
                break;
            }
            lock$iv$iv2 = SnapshotStateListKt.sync;
            synchronized (lock$iv$iv2) {
                SnapshotStateList this_$iv$iv = this_$iv;
                try {
                    StateRecord firstStateRecord2 = this_$iv$iv.getFirstStateRecord();
                    Intrinsics.checkNotNull(firstStateRecord2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                    StateRecord $this$writable$iv$iv$iv = (StateListStateRecord) firstStateRecord2;
                    SnapshotKt.getSnapshotInitializer();
                    Object lock$iv$iv$iv$iv$iv = SnapshotKt.getLock();
                    synchronized (lock$iv$iv$iv$iv$iv) {
                        try {
                            Snapshot current = Snapshot.Companion.getCurrent();
                            try {
                                SnapshotStateList this_$iv2 = this_$iv;
                                try {
                                    StateListStateRecord $this$mutate_u24lambda_u2418_u24lambda_u2417$iv = (StateListStateRecord) SnapshotKt.writableRecord($this$writable$iv$iv$iv, this_$iv$iv, current);
                                    boolean z3 = z2;
                                    try {
                                        int $i$f$mutate = $this$mutate_u24lambda_u2418_u24lambda_u2417$iv.getModification$runtime_release();
                                        if ($i$f$mutate == currentModification$iv) {
                                            $this$mutate_u24lambda_u2418_u24lambda_u2417$iv.setList$runtime_release(newList$iv);
                                            z = true;
                                            $this$mutate_u24lambda_u2418_u24lambda_u2417$iv.setModification$runtime_release($this$mutate_u24lambda_u2418_u24lambda_u2417$iv.getModification$runtime_release() + 1);
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
        return ((Boolean) result$iv).booleanValue();
    }

    private final <R> R mutate(Function1<? super List<T>, ? extends R> function1) {
        Object lock$iv;
        R invoke;
        Object lock$iv2;
        boolean z;
        boolean z2 = false;
        while (true) {
            lock$iv = SnapshotStateListKt.sync;
            synchronized (lock$iv) {
                try {
                    StateRecord firstStateRecord = getFirstStateRecord();
                    Intrinsics.checkNotNull(firstStateRecord, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                    StateRecord $this$withCurrent$iv$iv = (StateListStateRecord) firstStateRecord;
                    StateListStateRecord current = (StateListStateRecord) SnapshotKt.current($this$withCurrent$iv$iv);
                    int currentModification = current.getModification$runtime_release();
                    PersistentList<T> list$runtime_release = current.getList$runtime_release();
                    try {
                        Unit unit = Unit.INSTANCE;
                        InlineMarker.finallyStart(1);
                        InlineMarker.finallyEnd(1);
                        Intrinsics.checkNotNull(list$runtime_release);
                        PersistentList.Builder builder = list$runtime_release.builder();
                        invoke = function1.invoke(builder);
                        PersistentList newList = builder.build();
                        if (Intrinsics.areEqual(newList, list$runtime_release)) {
                            break;
                        }
                        lock$iv2 = SnapshotStateListKt.sync;
                        synchronized (lock$iv2) {
                            try {
                                StateRecord firstStateRecord2 = getFirstStateRecord();
                                Intrinsics.checkNotNull(firstStateRecord2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                                StateRecord $this$writable$iv$iv = (StateListStateRecord) firstStateRecord2;
                                SnapshotKt.getSnapshotInitializer();
                                Object lock$iv$iv$iv$iv = SnapshotKt.getLock();
                                synchronized (lock$iv$iv$iv$iv) {
                                    try {
                                        Snapshot current2 = Snapshot.Companion.getCurrent();
                                        try {
                                            boolean z3 = z2;
                                            try {
                                                StateListStateRecord $this$mutate_u24lambda_u2418_u24lambda_u2417 = (StateListStateRecord) SnapshotKt.writableRecord($this$writable$iv$iv, this, current2);
                                                if ($this$mutate_u24lambda_u2418_u24lambda_u2417.getModification$runtime_release() == currentModification) {
                                                    try {
                                                        $this$mutate_u24lambda_u2418_u24lambda_u2417.setList$runtime_release(newList);
                                                        $this$mutate_u24lambda_u2418_u24lambda_u2417.setModification$runtime_release($this$mutate_u24lambda_u2418_u24lambda_u2417.getModification$runtime_release() + 1);
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

    /* JADX WARN: Code restructure failed: missing block: B:32:0x00c5, code lost:
        kotlin.jvm.internal.InlineMarker.finallyEnd(1);
        androidx.compose.runtime.snapshots.SnapshotKt.notifyWrite(r23, r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00d9, code lost:
        kotlin.jvm.internal.InlineMarker.finallyStart(1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00de, code lost:
        kotlin.jvm.internal.InlineMarker.finallyEnd(1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00e1, code lost:
        if (r2 == false) goto L41;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00e8, code lost:
        return;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final void update(kotlin.jvm.functions.Function1<? super androidx.compose.runtime.external.kotlinx.collections.immutable.PersistentList<? extends T>, ? extends androidx.compose.runtime.external.kotlinx.collections.immutable.PersistentList<? extends T>> r27) {
        /*
            Method dump skipped, instructions count: 303
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.SnapshotStateList.update(kotlin.jvm.functions.Function1):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x00c3, code lost:
        kotlin.jvm.internal.InlineMarker.finallyEnd(1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00c7, code lost:
        r23 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x00cc, code lost:
        androidx.compose.runtime.snapshots.SnapshotKt.notifyWrite(r21, r13);
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00d7, code lost:
        kotlin.jvm.internal.InlineMarker.finallyStart(1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00dc, code lost:
        kotlin.jvm.internal.InlineMarker.finallyEnd(1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x00df, code lost:
        if (r0 == false) goto L40;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00e1, code lost:
        return true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x010c, code lost:
        r0 = th;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final boolean conditionalUpdate(kotlin.jvm.functions.Function1<? super androidx.compose.runtime.external.kotlinx.collections.immutable.PersistentList<? extends T>, ? extends androidx.compose.runtime.external.kotlinx.collections.immutable.PersistentList<? extends T>> r25) {
        /*
            Method dump skipped, instructions count: 300
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.SnapshotStateList.conditionalUpdate(kotlin.jvm.functions.Function1):boolean");
    }
}
