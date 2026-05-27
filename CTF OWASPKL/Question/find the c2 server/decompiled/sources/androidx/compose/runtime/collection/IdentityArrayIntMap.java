package androidx.compose.runtime.collection;

import androidx.compose.runtime.ActualJvm_jvmKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.ArraysKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: IdentityArrayIntMap.kt */
@Metadata(d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u0011\n\u0002\b\u0007\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0010\u0015\n\u0002\b\t\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0000\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0016\u0010\u0019\u001a\u00020\f2\u0006\u0010\u001a\u001a\u00020\u00012\u0006\u0010\u001b\u001a\u00020\fJ&\u0010\u001c\u001a\u00020\u001d2\u0018\u0010\u001e\u001a\u0014\u0012\u0004\u0012\u00020\u0001\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020\u001d0\u001fH\u0086\bø\u0001\u0000J\u0012\u0010 \u001a\u00020\f2\b\u0010\u001a\u001a\u0004\u0018\u00010\u0001H\u0002J\"\u0010!\u001a\u00020\f2\u0006\u0010\"\u001a\u00020\f2\b\u0010\u001b\u001a\u0004\u0018\u00010\u00012\u0006\u0010#\u001a\u00020\fH\u0002J&\u0010$\u001a\u00020%2\u0018\u0010&\u001a\u0014\u0012\u0004\u0012\u00020\u0001\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020%0\u001fH\u0086\bø\u0001\u0000J\u0011\u0010'\u001a\u00020\f2\u0006\u0010\u001a\u001a\u00020\u0001H\u0086\u0002J\u000e\u0010(\u001a\u00020\u001d2\u0006\u0010\u001a\u001a\u00020\u0001J&\u0010)\u001a\u00020%2\u0018\u0010\u001e\u001a\u0014\u0012\u0004\u0012\u00020\u0001\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020\u001d0\u001fH\u0086\bø\u0001\u0000R.\u0010\u0003\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00010\u00048\u0000@\u0000X\u0081\u000e¢\u0006\u0016\n\u0002\u0010\n\u0012\u0004\b\u0005\u0010\u0002\u001a\u0004\b\u0006\u0010\u0007\"\u0004\b\b\u0010\tR$\u0010\u000b\u001a\u00020\f8\u0000@\u0000X\u0081\u000e¢\u0006\u0014\n\u0000\u0012\u0004\b\r\u0010\u0002\u001a\u0004\b\u000e\u0010\u000f\"\u0004\b\u0010\u0010\u0011R$\u0010\u0012\u001a\u00020\u00138\u0000@\u0000X\u0081\u000e¢\u0006\u0014\n\u0000\u0012\u0004\b\u0014\u0010\u0002\u001a\u0004\b\u0015\u0010\u0016\"\u0004\b\u0017\u0010\u0018\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006*"}, d2 = {"Landroidx/compose/runtime/collection/IdentityArrayIntMap;", "", "()V", "keys", "", "getKeys$annotations", "getKeys", "()[Ljava/lang/Object;", "setKeys", "([Ljava/lang/Object;)V", "[Ljava/lang/Object;", "size", "", "getSize$annotations", "getSize", "()I", "setSize", "(I)V", "values", "", "getValues$annotations", "getValues", "()[I", "setValues", "([I)V", "add", "key", "value", "any", "", "predicate", "Lkotlin/Function2;", "find", "findExactIndex", "midIndex", "valueHash", "forEach", "", "block", "get", "remove", "removeValueIf", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class IdentityArrayIntMap {
    private int size;
    private Object[] keys = new Object[4];
    private int[] values = new int[4];

    public static /* synthetic */ void getKeys$annotations() {
    }

    public static /* synthetic */ void getSize$annotations() {
    }

    public static /* synthetic */ void getValues$annotations() {
    }

    public final int getSize() {
        return this.size;
    }

    public final void setSize(int i) {
        this.size = i;
    }

    public final Object[] getKeys() {
        return this.keys;
    }

    public final void setKeys(Object[] objArr) {
        Intrinsics.checkNotNullParameter(objArr, "<set-?>");
        this.keys = objArr;
    }

    public final int[] getValues() {
        return this.values;
    }

    public final void setValues(int[] iArr) {
        Intrinsics.checkNotNullParameter(iArr, "<set-?>");
        this.values = iArr;
    }

    public final int get(Object key) {
        Intrinsics.checkNotNullParameter(key, "key");
        int index = find(key);
        if (index >= 0) {
            return this.values[index];
        }
        throw new IllegalStateException("Key not found".toString());
    }

    public final int add(Object key, int value) {
        int index;
        Intrinsics.checkNotNullParameter(key, "key");
        if (this.size > 0) {
            index = find(key);
            if (index >= 0) {
                int[] iArr = this.values;
                int previousValue = iArr[index];
                iArr[index] = value;
                return previousValue;
            }
        } else {
            index = -1;
        }
        int insertIndex = -(index + 1);
        int i = this.size;
        Object[] objArr = this.keys;
        if (i == objArr.length) {
            Object[] newKeys = new Object[objArr.length * 2];
            int[] newValues = new int[objArr.length * 2];
            ArraysKt.copyInto(objArr, newKeys, insertIndex + 1, insertIndex, i);
            ArraysKt.copyInto(this.values, newValues, insertIndex + 1, insertIndex, this.size);
            ArraysKt.copyInto$default(this.keys, newKeys, 0, 0, insertIndex, 6, (Object) null);
            ArraysKt.copyInto$default(this.values, newValues, 0, 0, insertIndex, 6, (Object) null);
            this.keys = newKeys;
            this.values = newValues;
        } else {
            ArraysKt.copyInto(objArr, objArr, insertIndex + 1, insertIndex, i);
            int[] iArr2 = this.values;
            ArraysKt.copyInto(iArr2, iArr2, insertIndex + 1, insertIndex, this.size);
        }
        this.keys[insertIndex] = key;
        this.values[insertIndex] = value;
        this.size++;
        return -1;
    }

    public final boolean remove(Object key) {
        Intrinsics.checkNotNullParameter(key, "key");
        int index = find(key);
        if (index >= 0) {
            int i = this.size;
            if (index < i - 1) {
                Object[] objArr = this.keys;
                ArraysKt.copyInto(objArr, objArr, index, index + 1, i);
                int[] iArr = this.values;
                ArraysKt.copyInto(iArr, iArr, index, index + 1, this.size);
            }
            int i2 = this.size - 1;
            this.size = i2;
            this.keys[i2] = null;
            return true;
        }
        return false;
    }

    public final void removeValueIf(Function2<Object, ? super Integer, Boolean> predicate) {
        Intrinsics.checkNotNullParameter(predicate, "predicate");
        int destinationIndex = 0;
        int size = getSize();
        for (int i = 0; i < size; i++) {
            Object key = getKeys()[i];
            Intrinsics.checkNotNull(key, "null cannot be cast to non-null type kotlin.Any");
            int value = getValues()[i];
            if (!predicate.invoke(key, Integer.valueOf(value)).booleanValue()) {
                if (destinationIndex != i) {
                    getKeys()[destinationIndex] = key;
                    getValues()[destinationIndex] = value;
                }
                destinationIndex++;
            }
        }
        int size2 = getSize();
        for (int i2 = destinationIndex; i2 < size2; i2++) {
            getKeys()[i2] = null;
        }
        setSize(destinationIndex);
    }

    public final boolean any(Function2<Object, ? super Integer, Boolean> predicate) {
        Intrinsics.checkNotNullParameter(predicate, "predicate");
        int size = getSize();
        for (int i = 0; i < size; i++) {
            Object obj = getKeys()[i];
            Intrinsics.checkNotNull(obj, "null cannot be cast to non-null type kotlin.Any");
            if (predicate.invoke(obj, Integer.valueOf(getValues()[i])).booleanValue()) {
                return true;
            }
        }
        return false;
    }

    public final void forEach(Function2<Object, ? super Integer, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        int size = getSize();
        for (int i = 0; i < size; i++) {
            Object obj = getKeys()[i];
            Intrinsics.checkNotNull(obj, "null cannot be cast to non-null type kotlin.Any");
            block.invoke(obj, Integer.valueOf(getValues()[i]));
        }
    }

    private final int find(Object key) {
        int low = 0;
        int high = this.size - 1;
        int valueIdentity = ActualJvm_jvmKt.identityHashCode(key);
        while (low <= high) {
            int mid = (low + high) >>> 1;
            Object midVal = this.keys[mid];
            int midIdentity = ActualJvm_jvmKt.identityHashCode(midVal);
            if (midIdentity < valueIdentity) {
                low = mid + 1;
            } else if (midIdentity <= valueIdentity) {
                return midVal == key ? mid : findExactIndex(mid, key, valueIdentity);
            } else {
                high = mid - 1;
            }
        }
        return -(low + 1);
    }

    private final int findExactIndex(int midIndex, Object value, int valueHash) {
        for (int i = midIndex - 1; -1 < i; i--) {
            Object v = this.keys[i];
            if (v == value) {
                return i;
            }
            if (ActualJvm_jvmKt.identityHashCode(v) != valueHash) {
                break;
            }
        }
        int i2 = this.size;
        for (int i3 = midIndex + 1; i3 < i2; i3++) {
            Object v2 = this.keys[i3];
            if (v2 == value) {
                return i3;
            }
            if (ActualJvm_jvmKt.identityHashCode(v2) != valueHash) {
                return -(i3 + 1);
            }
        }
        int i4 = this.size;
        return -(i4 + 1);
    }
}
