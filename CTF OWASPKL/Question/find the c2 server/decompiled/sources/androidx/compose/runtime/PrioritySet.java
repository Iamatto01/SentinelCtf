package androidx.compose.runtime;

import java.util.ArrayList;
import java.util.List;
import kotlin.KotlinNothingValueException;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: SlotTable.kt */
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010!\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0005\b\u0000\u0018\u00002\u00020\u0001B\u0015\u0012\u000e\b\u0002\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003¢\u0006\u0002\u0010\u0005J\u000e\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u0004J\u0006\u0010\t\u001a\u00020\nJ\u0006\u0010\u000b\u001a\u00020\nJ\u0006\u0010\f\u001a\u00020\u0004J\u0006\u0010\r\u001a\u00020\u0004J\u0006\u0010\u000e\u001a\u00020\u0007R\u0014\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000f"}, d2 = {"Landroidx/compose/runtime/PrioritySet;", "", "list", "", "", "(Ljava/util/List;)V", "add", "", "value", "isEmpty", "", "isNotEmpty", "peek", "takeMax", "validateHeap", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class PrioritySet {
    private final List<Integer> list;

    public PrioritySet() {
        this(null, 1, null);
    }

    public PrioritySet(List<Integer> list) {
        Intrinsics.checkNotNullParameter(list, "list");
        this.list = list;
    }

    public /* synthetic */ PrioritySet(ArrayList arrayList, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? new ArrayList() : arrayList);
    }

    public final void add(int value) {
        List<Integer> list;
        if (!this.list.isEmpty()) {
            if (this.list.get(0).intValue() == value) {
                return;
            }
            if (this.list.get(list.size() - 1).intValue() == value) {
                return;
            }
        }
        int index = this.list.size();
        this.list.add(Integer.valueOf(value));
        while (index > 0) {
            int parent = ((index + 1) >>> 1) - 1;
            int parentValue = this.list.get(parent).intValue();
            if (value <= parentValue) {
                break;
            }
            this.list.set(index, Integer.valueOf(parentValue));
            index = parent;
        }
        this.list.set(index, Integer.valueOf(value));
    }

    public final boolean isEmpty() {
        return this.list.isEmpty();
    }

    public final boolean isNotEmpty() {
        return !this.list.isEmpty();
    }

    public final int peek() {
        return ((Number) CollectionsKt.first((List<? extends Object>) this.list)).intValue();
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final int takeMax() {
        int rightValue;
        boolean value$iv = this.list.size() > 0;
        if (value$iv) {
            int value = this.list.get(0).intValue();
            while ((!this.list.isEmpty()) && this.list.get(0).intValue() == value) {
                List<Integer> list = this.list;
                list.set(0, CollectionsKt.last((List<? extends Object>) list));
                List<Integer> list2 = this.list;
                list2.remove(list2.size() - 1);
                int index = 0;
                int size = this.list.size();
                int max = this.list.size() >>> 1;
                while (index < max) {
                    int indexValue = this.list.get(index).intValue();
                    int left = ((index + 1) * 2) - 1;
                    int leftValue = this.list.get(left).intValue();
                    int right = (index + 1) * 2;
                    if (right < size && (rightValue = this.list.get(right).intValue()) > leftValue) {
                        if (rightValue > indexValue) {
                            this.list.set(index, Integer.valueOf(rightValue));
                            this.list.set(right, Integer.valueOf(indexValue));
                            index = right;
                        }
                    } else if (leftValue > indexValue) {
                        this.list.set(index, Integer.valueOf(leftValue));
                        this.list.set(left, Integer.valueOf(indexValue));
                        index = left;
                    }
                }
            }
            return value;
        }
        ComposerKt.composeRuntimeError("Set is empty".toString());
        throw new KotlinNothingValueException();
    }

    public final void validateHeap() {
        int size = this.list.size();
        int i = size / 2;
        for (int index = 0; index < i; index++) {
            boolean z = true;
            int left = ((index + 1) * 2) - 1;
            int right = (index + 1) * 2;
            if (!(this.list.get(index).intValue() >= this.list.get(left).intValue())) {
                throw new IllegalStateException("Check failed.".toString());
            }
            if (right < size && this.list.get(index).intValue() < this.list.get(right).intValue()) {
                z = false;
            }
            if (!z) {
                throw new IllegalStateException("Check failed.".toString());
            }
        }
    }
}
