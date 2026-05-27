package androidx.compose.ui.text.caches;

import java.util.Arrays;
import java.util.ConcurrentModificationException;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.ArraysKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: SimpleArrayMap.kt */
@Metadata(d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\b\n\u0002\u0010\u0015\n\u0000\n\u0002\u0010\u0011\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b'\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0000\u0018\u0000*\u0004\b\u0000\u0010\u0001*\u0004\b\u0001\u0010\u00022\u00020\u0003B\u0011\b\u0017\u0012\b\b\u0002\u0010\u0004\u001a\u00020\u0005¢\u0006\u0002\u0010\u0006B\u001d\b\u0016\u0012\u0014\u0010\u0007\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u0000¢\u0006\u0002\u0010\bJ\u0006\u0010\u0015\u001a\u00020\u0016J\u0013\u0010\u0017\u001a\u00020\u00182\u0006\u0010\u0019\u001a\u00028\u0000¢\u0006\u0002\u0010\u001aJ\u0013\u0010\u001b\u001a\u00020\u00182\u0006\u0010\u001c\u001a\u00028\u0001¢\u0006\u0002\u0010\u001aJ\u000e\u0010\u001d\u001a\u00020\u00162\u0006\u0010\u001e\u001a\u00020\u0005J\u0013\u0010\u001f\u001a\u00020\u00182\b\u0010 \u001a\u0004\u0018\u00010\u0003H\u0096\u0002J\u0018\u0010!\u001a\u0004\u0018\u00018\u00012\u0006\u0010\u0019\u001a\u00028\u0000H\u0086\u0002¢\u0006\u0002\u0010\"J\u001b\u0010#\u001a\u00028\u00012\u0006\u0010\u0019\u001a\u00028\u00002\u0006\u0010$\u001a\u00028\u0001¢\u0006\u0002\u0010%J\b\u0010&\u001a\u00020\u0005H\u0016J\u0018\u0010'\u001a\u00020\u00052\u0006\u0010\u0019\u001a\u00020\u00032\u0006\u0010(\u001a\u00020\u0005H\u0004J\u0010\u0010)\u001a\u00020\u00052\b\u0010\u0019\u001a\u0004\u0018\u00010\u0003J\b\u0010*\u001a\u00020\u0005H\u0004J\u0017\u0010+\u001a\u00020\u00052\u0006\u0010\u001c\u001a\u00028\u0001H\u0000¢\u0006\u0004\b,\u0010-J\u0006\u0010.\u001a\u00020\u0018J\u0013\u0010/\u001a\u00028\u00002\u0006\u00100\u001a\u00020\u0005¢\u0006\u0002\u00101J\u001d\u00102\u001a\u0004\u0018\u00018\u00012\u0006\u0010\u0019\u001a\u00028\u00002\u0006\u0010\u001c\u001a\u00028\u0001¢\u0006\u0002\u0010%J\u001e\u00103\u001a\u00020\u00162\u0016\u00104\u001a\u0012\u0012\u0006\b\u0001\u0012\u00028\u0000\u0012\u0006\b\u0001\u0012\u00028\u00010\u0000J\u001d\u00105\u001a\u0004\u0018\u00018\u00012\u0006\u0010\u0019\u001a\u00028\u00002\u0006\u0010\u001c\u001a\u00028\u0001¢\u0006\u0002\u0010%J\u0015\u00106\u001a\u0004\u0018\u00018\u00012\u0006\u0010\u0019\u001a\u00028\u0000¢\u0006\u0002\u0010\"J\u001b\u00106\u001a\u00020\u00182\u0006\u0010\u0019\u001a\u00028\u00002\u0006\u0010\u001c\u001a\u00028\u0001¢\u0006\u0002\u00107J\u0015\u00108\u001a\u0004\u0018\u00018\u00012\u0006\u00100\u001a\u00020\u0005¢\u0006\u0002\u00101J\u001d\u00109\u001a\u0004\u0018\u00018\u00012\u0006\u0010\u0019\u001a\u00028\u00002\u0006\u0010\u001c\u001a\u00028\u0001¢\u0006\u0002\u0010%J#\u00109\u001a\u00020\u00182\u0006\u0010\u0019\u001a\u00028\u00002\u0006\u0010:\u001a\u00028\u00012\u0006\u0010;\u001a\u00028\u0001¢\u0006\u0002\u0010<J\u001b\u0010=\u001a\u00028\u00012\u0006\u00100\u001a\u00020\u00052\u0006\u0010\u001c\u001a\u00028\u0001¢\u0006\u0002\u0010>J\b\u0010?\u001a\u00020@H\u0016J\u0013\u0010A\u001a\u00028\u00012\u0006\u00100\u001a\u00020\u0005¢\u0006\u0002\u00101R\u001a\u0010\t\u001a\u00020\u0005X\u0084\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\n\u0010\u000b\"\u0004\b\f\u0010\u0006R\u000e\u0010\r\u001a\u00020\u000eX\u0082\u000e¢\u0006\u0002\n\u0000R\u0018\u0010\u000f\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00030\u0010X\u0082\u000e¢\u0006\u0004\n\u0002\u0010\u0011R\u0017\u0010\u0012\u001a\u00020\u00058G¢\u0006\f\u0012\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0012\u0010\u000b¨\u0006B"}, d2 = {"Landroidx/compose/ui/text/caches/SimpleArrayMap;", "K", "V", "", "capacity", "", "(I)V", "map", "(Landroidx/compose/ui/text/caches/SimpleArrayMap;)V", "_size", "get_size", "()I", "set_size", "hashes", "", "keyValues", "", "[Ljava/lang/Object;", "size", "size$annotations", "()V", "clear", "", "containsKey", "", "key", "(Ljava/lang/Object;)Z", "containsValue", "value", "ensureCapacity", "minimumCapacity", "equals", "other", "get", "(Ljava/lang/Object;)Ljava/lang/Object;", "getOrDefault", "defaultValue", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", "hashCode", "indexOf", "hash", "indexOfKey", "indexOfNull", "indexOfValue", "indexOfValue$ui_text_release", "(Ljava/lang/Object;)I", "isEmpty", "keyAt", "index", "(I)Ljava/lang/Object;", "put", "putAll", "array", "putIfAbsent", "remove", "(Ljava/lang/Object;Ljava/lang/Object;)Z", "removeAt", "replace", "oldValue", "newValue", "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z", "setValueAt", "(ILjava/lang/Object;)Ljava/lang/Object;", "toString", "", "valueAt", "ui-text_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class SimpleArrayMap<K, V> {
    private int _size;
    private int[] hashes;
    private Object[] keyValues;

    public SimpleArrayMap() {
        this(0, 1, null);
    }

    public static /* synthetic */ void size$annotations() {
    }

    protected final int get_size() {
        return this._size;
    }

    protected final void set_size(int i) {
        this._size = i;
    }

    public final int size() {
        return this._size;
    }

    protected final int indexOf(Object key, int hash) {
        Intrinsics.checkNotNullParameter(key, "key");
        int N = this._size;
        if (N == 0) {
            return -1;
        }
        int index = ContainerHelpersKt.binarySearchInternal(this.hashes, N, hash);
        if (index < 0) {
            return index;
        }
        if (Intrinsics.areEqual(key, this.keyValues[index << 1])) {
            return index;
        }
        int end = index + 1;
        while (end < N && this.hashes[end] == hash) {
            if (Intrinsics.areEqual(key, this.keyValues[end << 1])) {
                return end;
            }
            end++;
        }
        for (int i = index - 1; i >= 0 && this.hashes[i] == hash; i--) {
            if (Intrinsics.areEqual(key, this.keyValues[i << 1])) {
                return i;
            }
        }
        return ~end;
    }

    protected final int indexOfNull() {
        int N = this._size;
        if (N == 0) {
            return -1;
        }
        int index = ContainerHelpersKt.binarySearchInternal(this.hashes, N, 0);
        if (index < 0) {
            return index;
        }
        if (this.keyValues[index << 1] == null) {
            return index;
        }
        int end = index + 1;
        while (end < N && this.hashes[end] == 0) {
            if (this.keyValues[end << 1] == null) {
                return end;
            }
            end++;
        }
        for (int i = index - 1; i >= 0 && this.hashes[i] == 0; i--) {
            if (this.keyValues[i << 1] == null) {
                return i;
            }
        }
        return ~end;
    }

    public SimpleArrayMap(int capacity) {
        if (capacity == 0) {
            this.hashes = ContainerHelpersKt.EMPTY_INTS;
            this.keyValues = ContainerHelpersKt.EMPTY_OBJECTS;
        } else {
            this.hashes = new int[capacity];
            this.keyValues = new Object[capacity << 1];
        }
        this._size = 0;
    }

    public /* synthetic */ SimpleArrayMap(int i, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? 0 : i);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public SimpleArrayMap(SimpleArrayMap<K, V> simpleArrayMap) {
        this(0, 1, null);
        if (simpleArrayMap != 0) {
            putAll(simpleArrayMap);
        }
    }

    public final void clear() {
        if (this._size > 0) {
            this.hashes = ContainerHelpersKt.EMPTY_INTS;
            this.keyValues = ContainerHelpersKt.EMPTY_OBJECTS;
            this._size = 0;
        }
        if (this._size > 0) {
            throw new ConcurrentModificationException();
        }
    }

    public final void ensureCapacity(int minimumCapacity) {
        int osize = this._size;
        int[] iArr = this.hashes;
        if (iArr.length < minimumCapacity) {
            int[] copyOf = Arrays.copyOf(iArr, minimumCapacity);
            Intrinsics.checkNotNullExpressionValue(copyOf, "copyOf(this, newSize)");
            this.hashes = copyOf;
            Object[] copyOf2 = Arrays.copyOf(this.keyValues, minimumCapacity << 1);
            Intrinsics.checkNotNullExpressionValue(copyOf2, "copyOf(this, newSize)");
            this.keyValues = copyOf2;
        }
        if (this._size != osize) {
            throw new ConcurrentModificationException();
        }
    }

    public final boolean containsKey(K k) {
        return indexOfKey(k) >= 0;
    }

    public final int indexOfKey(Object key) {
        return key == null ? indexOfNull() : indexOf(key, key.hashCode());
    }

    public final int indexOfValue$ui_text_release(V v) {
        int N = this._size << 1;
        Object[] array = this.keyValues;
        if (v == null) {
            for (int i = 1; i < N; i += 2) {
                if (array[i] == null) {
                    return i >> 1;
                }
            }
            return -1;
        }
        for (int i2 = 1; i2 < N; i2 += 2) {
            if (Intrinsics.areEqual(v, array[i2])) {
                return i2 >> 1;
            }
        }
        return -1;
    }

    public final boolean containsValue(V v) {
        return indexOfValue$ui_text_release(v) >= 0;
    }

    public final V get(K k) {
        int index = indexOfKey(k);
        if (index >= 0) {
            return (V) this.keyValues[(index << 1) + 1];
        }
        return null;
    }

    public final V getOrDefault(K k, V v) {
        int index = indexOfKey(k);
        return index >= 0 ? (V) this.keyValues[(index << 1) + 1] : v;
    }

    public final K keyAt(int index) {
        return (K) this.keyValues[index << 1];
    }

    public final V valueAt(int index) {
        return (V) this.keyValues[(index << 1) + 1];
    }

    public final V setValueAt(int index, V v) {
        int actualIndex = (index << 1) + 1;
        Object[] objArr = this.keyValues;
        V v2 = (V) objArr[actualIndex];
        objArr[actualIndex] = v;
        return v2;
    }

    public final boolean isEmpty() {
        return this._size <= 0;
    }

    public final V put(K k, V v) {
        int hash;
        int index;
        int osize = this._size;
        if (k == null) {
            hash = 0;
            index = indexOfNull();
        } else {
            hash = k.hashCode();
            index = indexOf(k, hash);
        }
        if (index >= 0) {
            int index2 = (index << 1) + 1;
            Object[] objArr = this.keyValues;
            V v2 = (V) objArr[index2];
            objArr[index2] = v;
            return v2;
        }
        int index3 = ~index;
        int[] iArr = this.hashes;
        if (osize >= iArr.length) {
            int n = 8;
            if (osize >= 8) {
                n = (osize >> 1) + osize;
            } else if (osize < 4) {
                n = 4;
            }
            int[] copyOf = Arrays.copyOf(iArr, n);
            Intrinsics.checkNotNullExpressionValue(copyOf, "copyOf(this, newSize)");
            this.hashes = copyOf;
            Object[] copyOf2 = Arrays.copyOf(this.keyValues, n << 1);
            Intrinsics.checkNotNullExpressionValue(copyOf2, "copyOf(this, newSize)");
            this.keyValues = copyOf2;
            if (osize != this._size) {
                throw new ConcurrentModificationException();
            }
        }
        if (index3 < osize) {
            int[] iArr2 = this.hashes;
            ArraysKt.copyInto(iArr2, iArr2, index3 + 1, index3, osize);
            Object[] objArr2 = this.keyValues;
            ArraysKt.copyInto(objArr2, objArr2, (index3 + 1) << 1, index3 << 1, this._size << 1);
        }
        int i = this._size;
        if (osize == i) {
            int[] iArr3 = this.hashes;
            if (index3 < iArr3.length) {
                iArr3[index3] = hash;
                Object[] objArr3 = this.keyValues;
                objArr3[index3 << 1] = k;
                objArr3[(index3 << 1) + 1] = v;
                this._size = i + 1;
                return null;
            }
        }
        throw new ConcurrentModificationException();
    }

    public final void putAll(SimpleArrayMap<? extends K, ? extends V> array) {
        Intrinsics.checkNotNullParameter(array, "array");
        int N = array._size;
        ensureCapacity(this._size + N);
        if (this._size == 0) {
            if (N > 0) {
                ArraysKt.copyInto(array.hashes, this.hashes, 0, 0, N);
                ArraysKt.copyInto(array.keyValues, this.keyValues, 0, 0, N << 1);
                this._size = N;
                return;
            }
            return;
        }
        for (int i = 0; i < N; i++) {
            put(array.keyAt(i), array.valueAt(i));
        }
    }

    public final V putIfAbsent(K k, V v) {
        V v2 = get(k);
        if (v2 == null) {
            return put(k, v);
        }
        return v2;
    }

    public final V remove(K k) {
        int index = indexOfKey(k);
        if (index >= 0) {
            return removeAt(index);
        }
        return null;
    }

    public final boolean remove(K k, V v) {
        int index = indexOfKey(k);
        if (index >= 0) {
            Object mapValue = valueAt(index);
            if (Intrinsics.areEqual(v, mapValue)) {
                removeAt(index);
                return true;
            }
            return false;
        }
        return false;
    }

    public final V removeAt(int index) {
        V v = (V) this.keyValues[(index << 1) + 1];
        int osize = this._size;
        if (osize <= 1) {
            clear();
        } else {
            int nsize = osize - 1;
            int[] iArr = this.hashes;
            if (iArr.length > 8 && osize < iArr.length / 3) {
                int n = osize > 8 ? osize + (osize >> 1) : 8;
                int[] ohashes = this.hashes;
                Object[] oarray = this.keyValues;
                int[] iArr2 = new int[n];
                this.hashes = iArr2;
                this.keyValues = new Object[n << 1];
                if (osize != this._size) {
                    throw new ConcurrentModificationException();
                }
                if (index > 0) {
                    ArraysKt.copyInto(ohashes, iArr2, 0, 0, index);
                    ArraysKt.copyInto(oarray, this.keyValues, 0, 0, index << 1);
                }
                if (index < nsize) {
                    ArraysKt.copyInto(ohashes, this.hashes, index, index + 1, nsize + 1);
                    ArraysKt.copyInto(oarray, this.keyValues, index << 1, (index + 1) << 1, (nsize + 1) << 1);
                }
            } else {
                if (index < nsize) {
                    ArraysKt.copyInto(iArr, iArr, index, index + 1, nsize + 1);
                    Object[] objArr = this.keyValues;
                    ArraysKt.copyInto(objArr, objArr, index << 1, (index + 1) << 1, (nsize + 1) << 1);
                }
                Object[] objArr2 = this.keyValues;
                objArr2[nsize << 1] = null;
                objArr2[(nsize << 1) + 1] = null;
            }
            if (osize != this._size) {
                throw new ConcurrentModificationException();
            }
            this._size = nsize;
        }
        return v;
    }

    public final V replace(K k, V v) {
        int index = indexOfKey(k);
        if (index >= 0) {
            return setValueAt(index, v);
        }
        return null;
    }

    public final boolean replace(K k, V v, V v2) {
        int index = indexOfKey(k);
        if (index >= 0) {
            Object mapValue = valueAt(index);
            if (mapValue == v) {
                setValueAt(index, v2);
                return true;
            }
            return false;
        }
        return false;
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        try {
            if (other instanceof SimpleArrayMap) {
                SimpleArrayMap map = (SimpleArrayMap) other;
                int i = this._size;
                if (i != map._size) {
                    return false;
                }
                for (int i2 = 0; i2 < i; i2++) {
                    K keyAt = keyAt(i2);
                    Object mine = valueAt(i2);
                    Object theirs = map.get(keyAt);
                    if (mine == null) {
                        if (theirs != null || !map.containsKey(keyAt)) {
                            return false;
                        }
                    } else if (!Intrinsics.areEqual(mine, theirs)) {
                        return false;
                    }
                }
                return true;
            } else if (!(other instanceof Map) || this._size != ((Map) other).size()) {
                return false;
            } else {
                int i3 = this._size;
                for (int i4 = 0; i4 < i3; i4++) {
                    Object key = keyAt(i4);
                    Object mine2 = valueAt(i4);
                    Object theirs2 = ((Map) other).get(key);
                    if (mine2 == null) {
                        if (theirs2 != null || !((Map) other).containsKey(key)) {
                            return false;
                        }
                    } else if (!Intrinsics.areEqual(mine2, theirs2)) {
                        return false;
                    }
                }
                return true;
            }
        } catch (ClassCastException e) {
        } catch (NullPointerException e2) {
        }
        return false;
    }

    public int hashCode() {
        int[] hashes = this.hashes;
        Object[] array = this.keyValues;
        int result = 0;
        int i = 0;
        int v = 1;
        int s = this._size;
        while (i < s) {
            Object value = array[v];
            result += hashes[i] ^ (value != null ? value.hashCode() : 0);
            i++;
            v += 2;
        }
        return result;
    }

    public String toString() {
        if (isEmpty()) {
            return "{}";
        }
        StringBuilder buffer = new StringBuilder(this._size * 28);
        buffer.append('{');
        int i = this._size;
        for (int i2 = 0; i2 < i; i2++) {
            if (i2 > 0) {
                buffer.append(", ");
            }
            Object key = keyAt(i2);
            if (key != this) {
                buffer.append(key);
            } else {
                buffer.append("(this Map)");
            }
            buffer.append('=');
            Object value = valueAt(i2);
            if (value != this) {
                buffer.append(value);
            } else {
                buffer.append("(this Map)");
            }
        }
        buffer.append('}');
        String sb = buffer.toString();
        Intrinsics.checkNotNullExpressionValue(sb, "buffer.toString()");
        return sb;
    }
}
