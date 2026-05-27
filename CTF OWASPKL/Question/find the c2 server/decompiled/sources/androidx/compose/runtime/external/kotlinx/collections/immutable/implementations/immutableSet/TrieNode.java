package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet;

import androidx.compose.runtime.external.kotlinx.collections.immutable.internal.CommonFunctionsKt;
import androidx.compose.runtime.external.kotlinx.collections.immutable.internal.DeltaCounter;
import androidx.compose.runtime.external.kotlinx.collections.immutable.internal.MutabilityOwnership;
import java.util.Arrays;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.ArraysKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: TrieNode.kt */
@Metadata(d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0011\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u001a\n\u0002\u0010\u000b\n\u0002\b\u001f\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0018\b\u0000\u0018\u0000 _*\u0004\b\u0000\u0010\u00012\u00020\u0002:\u0001_B\u001f\b\u0016\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\u000e\u0010\u0005\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0006¢\u0006\u0002\u0010\u0007B'\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\u000e\u0010\u0005\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0006\u0012\b\u0010\b\u001a\u0004\u0018\u00010\t¢\u0006\u0002\u0010\nJ)\u0010\u0018\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u0019\u001a\u00020\u00042\u0006\u0010\u001a\u001a\u00028\u00002\u0006\u0010\u001b\u001a\u00020\u0004¢\u0006\u0002\u0010\u001cJ#\u0010\u001d\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u001e\u001a\u00020\u00042\u0006\u0010\u001a\u001a\u00028\u0000H\u0002¢\u0006\u0002\u0010\u001fJ\b\u0010 \u001a\u00020\u0004H\u0002J\u001b\u0010!\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u001a\u001a\u00028\u0000H\u0002¢\u0006\u0002\u0010\"J\u0015\u0010#\u001a\u00020$2\u0006\u0010\u001a\u001a\u00028\u0000H\u0002¢\u0006\u0002\u0010%J\u001b\u0010&\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u001a\u001a\u00028\u0000H\u0002¢\u0006\u0002\u0010\"J\u0016\u0010'\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010(\u001a\u00020\u0004H\u0002J#\u0010)\u001a\u00020$2\u0006\u0010\u0019\u001a\u00020\u00042\u0006\u0010\u001a\u001a\u00028\u00002\u0006\u0010\u001b\u001a\u00020\u0004¢\u0006\u0002\u0010*J\u001c\u0010+\u001a\u00020$2\f\u0010,\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u001b\u001a\u00020\u0004J\u0015\u0010-\u001a\u00028\u00002\u0006\u0010.\u001a\u00020\u0004H\u0002¢\u0006\u0002\u0010/J\u0016\u00100\u001a\u00020$2\f\u0010,\u001a\b\u0012\u0004\u0012\u00028\u00000\u0000H\u0002J\u0010\u00101\u001a\u00020$2\u0006\u0010\u001e\u001a\u00020\u0004H\u0002J\u0015\u00102\u001a\u00020\u00042\u0006\u0010\u001e\u001a\u00020\u0004H\u0000¢\u0006\u0002\b3JE\u00104\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u00105\u001a\u00020\u00042\u0006\u00106\u001a\u00028\u00002\u0006\u00107\u001a\u00020\u00042\u0006\u00108\u001a\u00028\u00002\u0006\u0010\u001b\u001a\u00020\u00042\b\u00109\u001a\u0004\u0018\u00010\tH\u0002¢\u0006\u0002\u0010:J=\u0010;\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010<\u001a\u00020\u00042\u0006\u0010=\u001a\u00020\u00042\u0006\u0010>\u001a\u00028\u00002\u0006\u0010\u001b\u001a\u00020\u00042\b\u00109\u001a\u0004\u0018\u00010\tH\u0002¢\u0006\u0002\u0010?J3\u0010@\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010<\u001a\u00020\u00042\u0006\u0010=\u001a\u00020\u00042\u0006\u0010>\u001a\u00028\u00002\u0006\u0010\u001b\u001a\u00020\u0004H\u0002¢\u0006\u0002\u0010AJ5\u0010B\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u0019\u001a\u00020\u00042\u0006\u0010\u001a\u001a\u00028\u00002\u0006\u0010\u001b\u001a\u00020\u00042\n\u0010C\u001a\u0006\u0012\u0002\b\u00030D¢\u0006\u0002\u0010EJ6\u0010F\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\f\u0010,\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u001b\u001a\u00020\u00042\u0006\u0010G\u001a\u00020H2\n\u0010C\u001a\u0006\u0012\u0002\b\u00030DJ+\u0010I\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u001e\u001a\u00020\u00042\u0006\u0010\u001a\u001a\u00028\u00002\u0006\u00109\u001a\u00020\tH\u0002¢\u0006\u0002\u0010JJ'\u0010K\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u001a\u001a\u00028\u00002\n\u0010C\u001a\u0006\u0012\u0002\b\u00030DH\u0002¢\u0006\u0002\u0010LJ,\u0010M\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\f\u0010,\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010G\u001a\u00020H2\u0006\u00109\u001a\u00020\tH\u0002J'\u0010N\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u001a\u001a\u00028\u00002\n\u0010C\u001a\u0006\u0012\u0002\b\u00030DH\u0002¢\u0006\u0002\u0010LJ(\u0010O\u001a\u0004\u0018\u00010\u00022\f\u0010,\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010G\u001a\u00020H2\u0006\u00109\u001a\u00020\tH\u0002J\u001e\u0010P\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010(\u001a\u00020\u00042\u0006\u00109\u001a\u00020\tH\u0002J(\u0010Q\u001a\u0004\u0018\u00010\u00022\f\u0010,\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010G\u001a\u00020H2\u0006\u00109\u001a\u00020\tH\u0002J;\u0010R\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010<\u001a\u00020\u00042\u0006\u0010=\u001a\u00020\u00042\u0006\u0010>\u001a\u00028\u00002\u0006\u0010\u001b\u001a\u00020\u00042\u0006\u00109\u001a\u00020\tH\u0002¢\u0006\u0002\u0010?J5\u0010S\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u0019\u001a\u00020\u00042\u0006\u0010\u001a\u001a\u00028\u00002\u0006\u0010\u001b\u001a\u00020\u00042\n\u0010C\u001a\u0006\u0012\u0002\b\u00030D¢\u0006\u0002\u0010EJ2\u0010T\u001a\u0004\u0018\u00010\u00022\f\u0010,\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u001b\u001a\u00020\u00042\u0006\u0010G\u001a\u00020H2\n\u0010C\u001a\u0006\u0012\u0002\b\u00030DJ&\u0010U\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010V\u001a\u00020\u00042\u0006\u0010\u001e\u001a\u00020\u00042\u0006\u00109\u001a\u00020\tH\u0002J2\u0010W\u001a\u0004\u0018\u00010\u00022\f\u0010,\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u001b\u001a\u00020\u00042\u0006\u0010G\u001a\u00020H2\n\u0010C\u001a\u0006\u0012\u0002\b\u00030DJ,\u0010X\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010Y\u001a\u00020\u00042\f\u0010Z\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u00109\u001a\u00020\tH\u0002J\u0016\u0010[\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010.\u001a\u00020\u0004H\u0002J)\u0010\\\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010\u0019\u001a\u00020\u00042\u0006\u0010\u001a\u001a\u00028\u00002\u0006\u0010\u001b\u001a\u00020\u0004¢\u0006\u0002\u0010\u001cJ\u001e\u0010]\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010V\u001a\u00020\u00042\u0006\u0010\u001e\u001a\u00020\u0004H\u0002J$\u0010^\u001a\b\u0012\u0004\u0012\u00028\u00000\u00002\u0006\u0010Y\u001a\u00020\u00042\f\u0010Z\u001a\b\u0012\u0004\u0012\u00028\u00000\u0000H\u0002R\u001a\u0010\u0003\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000eR$\u0010\u0005\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0006X\u0086\u000e¢\u0006\u0010\n\u0002\u0010\u0013\u001a\u0004\b\u000f\u0010\u0010\"\u0004\b\u0011\u0010\u0012R\u001c\u0010\b\u001a\u0004\u0018\u00010\tX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0014\u0010\u0015\"\u0004\b\u0016\u0010\u0017¨\u0006`"}, d2 = {"Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/TrieNode;", "E", "", "bitmap", "", "buffer", "", "(I[Ljava/lang/Object;)V", "ownedBy", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/internal/MutabilityOwnership;", "(I[Ljava/lang/Object;Landroidx/compose/runtime/external/kotlinx/collections/immutable/internal/MutabilityOwnership;)V", "getBitmap", "()I", "setBitmap", "(I)V", "getBuffer", "()[Ljava/lang/Object;", "setBuffer", "([Ljava/lang/Object;)V", "[Ljava/lang/Object;", "getOwnedBy", "()Landroidx/compose/runtime/external/kotlinx/collections/immutable/internal/MutabilityOwnership;", "setOwnedBy", "(Landroidx/compose/runtime/external/kotlinx/collections/immutable/internal/MutabilityOwnership;)V", "add", "elementHash", "element", "shift", "(ILjava/lang/Object;I)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/TrieNode;", "addElementAt", "positionMask", "(ILjava/lang/Object;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/TrieNode;", "calculateSize", "collisionAdd", "(Ljava/lang/Object;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/TrieNode;", "collisionContainsElement", "", "(Ljava/lang/Object;)Z", "collisionRemove", "collisionRemoveElementAtIndex", "i", "contains", "(ILjava/lang/Object;I)Z", "containsAll", "otherNode", "elementAtIndex", "index", "(I)Ljava/lang/Object;", "elementsIdentityEquals", "hasNoCellAt", "indexOfCellAt", "indexOfCellAt$runtime_release", "makeNode", "elementHash1", "element1", "elementHash2", "element2", "owner", "(ILjava/lang/Object;ILjava/lang/Object;ILandroidx/compose/runtime/external/kotlinx/collections/immutable/internal/MutabilityOwnership;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/TrieNode;", "makeNodeAtIndex", "elementIndex", "newElementHash", "newElement", "(IILjava/lang/Object;ILandroidx/compose/runtime/external/kotlinx/collections/immutable/internal/MutabilityOwnership;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/TrieNode;", "moveElementToNode", "(IILjava/lang/Object;I)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/TrieNode;", "mutableAdd", "mutator", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/PersistentHashSetBuilder;", "(ILjava/lang/Object;ILandroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/PersistentHashSetBuilder;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/TrieNode;", "mutableAddAll", "intersectionSizeRef", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/internal/DeltaCounter;", "mutableAddElementAt", "(ILjava/lang/Object;Landroidx/compose/runtime/external/kotlinx/collections/immutable/internal/MutabilityOwnership;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/TrieNode;", "mutableCollisionAdd", "(Ljava/lang/Object;Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/PersistentHashSetBuilder;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/TrieNode;", "mutableCollisionAddAll", "mutableCollisionRemove", "mutableCollisionRemoveAll", "mutableCollisionRemoveElementAtIndex", "mutableCollisionRetainAll", "mutableMoveElementToNode", "mutableRemove", "mutableRemoveAll", "mutableRemoveCellAtIndex", "cellIndex", "mutableRetainAll", "mutableUpdateNodeAtIndex", "nodeIndex", "newNode", "nodeAtIndex", "remove", "removeCellAtIndex", "updateNodeAtIndex", "Companion", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class TrieNode<E> {
    public static final Companion Companion = new Companion(null);
    private static final TrieNode EMPTY = new TrieNode(0, new Object[0]);
    private int bitmap;
    private Object[] buffer;
    private MutabilityOwnership ownedBy;

    public TrieNode(int bitmap, Object[] buffer, MutabilityOwnership ownedBy) {
        Intrinsics.checkNotNullParameter(buffer, "buffer");
        this.bitmap = bitmap;
        this.buffer = buffer;
        this.ownedBy = ownedBy;
    }

    public final int getBitmap() {
        return this.bitmap;
    }

    public final void setBitmap(int i) {
        this.bitmap = i;
    }

    public final Object[] getBuffer() {
        return this.buffer;
    }

    public final void setBuffer(Object[] objArr) {
        Intrinsics.checkNotNullParameter(objArr, "<set-?>");
        this.buffer = objArr;
    }

    public final MutabilityOwnership getOwnedBy() {
        return this.ownedBy;
    }

    public final void setOwnedBy(MutabilityOwnership mutabilityOwnership) {
        this.ownedBy = mutabilityOwnership;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public TrieNode(int bitmap, Object[] buffer) {
        this(bitmap, buffer, null);
        Intrinsics.checkNotNullParameter(buffer, "buffer");
    }

    private final boolean hasNoCellAt(int positionMask) {
        return (this.bitmap & positionMask) == 0;
    }

    public final int indexOfCellAt$runtime_release(int positionMask) {
        return Integer.bitCount(this.bitmap & (positionMask - 1));
    }

    private final E elementAtIndex(int index) {
        return (E) this.buffer[index];
    }

    private final TrieNode<E> nodeAtIndex(int index) {
        Object obj = this.buffer[index];
        Intrinsics.checkNotNull(obj, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode<E of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode>");
        return (TrieNode) obj;
    }

    private final TrieNode<E> addElementAt(int positionMask, E e) {
        Object[] newBuffer;
        int index = indexOfCellAt$runtime_release(positionMask);
        newBuffer = TrieNodeKt.addElementAtIndex(this.buffer, index, e);
        return new TrieNode<>(this.bitmap | positionMask, newBuffer);
    }

    private final TrieNode<E> mutableAddElementAt(int positionMask, E e, MutabilityOwnership owner) {
        Object[] newBuffer;
        Object[] addElementAtIndex;
        int index = indexOfCellAt$runtime_release(positionMask);
        if (this.ownedBy == owner) {
            addElementAtIndex = TrieNodeKt.addElementAtIndex(this.buffer, index, e);
            this.buffer = addElementAtIndex;
            this.bitmap |= positionMask;
            return this;
        }
        newBuffer = TrieNodeKt.addElementAtIndex(this.buffer, index, e);
        return new TrieNode<>(this.bitmap | positionMask, newBuffer, owner);
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final TrieNode<E> updateNodeAtIndex(int nodeIndex, TrieNode<E> trieNode) {
        Object cell;
        Object[] newNodeBuffer = trieNode.buffer;
        if (newNodeBuffer.length == 1 && !(newNodeBuffer[0] instanceof TrieNode)) {
            if (this.buffer.length == 1) {
                trieNode.bitmap = this.bitmap;
                return trieNode;
            }
            Object cell2 = newNodeBuffer[0];
            cell = cell2;
        } else {
            cell = trieNode;
        }
        Object[] objArr = this.buffer;
        Object[] newBuffer = Arrays.copyOf(objArr, objArr.length);
        Intrinsics.checkNotNullExpressionValue(newBuffer, "copyOf(this, size)");
        newBuffer[nodeIndex] = cell;
        return new TrieNode<>(this.bitmap, newBuffer);
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final TrieNode<E> mutableUpdateNodeAtIndex(int nodeIndex, TrieNode<E> trieNode, MutabilityOwnership owner) {
        Object cell;
        Object[] newNodeBuffer = trieNode.buffer;
        if (newNodeBuffer.length == 1 && !(newNodeBuffer[0] instanceof TrieNode)) {
            if (this.buffer.length == 1) {
                trieNode.bitmap = this.bitmap;
                return trieNode;
            }
            Object cell2 = newNodeBuffer[0];
            cell = cell2;
        } else {
            cell = trieNode;
        }
        if (this.ownedBy == owner) {
            this.buffer[nodeIndex] = cell;
            return this;
        }
        Object[] objArr = this.buffer;
        Object[] newBuffer = Arrays.copyOf(objArr, objArr.length);
        Intrinsics.checkNotNullExpressionValue(newBuffer, "copyOf(this, size)");
        newBuffer[nodeIndex] = cell;
        return new TrieNode<>(this.bitmap, newBuffer, owner);
    }

    private final TrieNode<E> makeNodeAtIndex(int elementIndex, int newElementHash, E e, int shift, MutabilityOwnership owner) {
        E elementAtIndex = elementAtIndex(elementIndex);
        return makeNode(elementAtIndex != null ? elementAtIndex.hashCode() : 0, elementAtIndex, newElementHash, e, shift + 5, owner);
    }

    private final TrieNode<E> moveElementToNode(int elementIndex, int newElementHash, E e, int shift) {
        Object[] objArr = this.buffer;
        Object[] newBuffer = Arrays.copyOf(objArr, objArr.length);
        Intrinsics.checkNotNullExpressionValue(newBuffer, "copyOf(this, size)");
        newBuffer[elementIndex] = makeNodeAtIndex(elementIndex, newElementHash, e, shift, null);
        return new TrieNode<>(this.bitmap, newBuffer);
    }

    private final TrieNode<E> mutableMoveElementToNode(int elementIndex, int newElementHash, E e, int shift, MutabilityOwnership owner) {
        if (this.ownedBy == owner) {
            this.buffer[elementIndex] = makeNodeAtIndex(elementIndex, newElementHash, e, shift, owner);
            return this;
        }
        Object[] objArr = this.buffer;
        Object[] newBuffer = Arrays.copyOf(objArr, objArr.length);
        Intrinsics.checkNotNullExpressionValue(newBuffer, "copyOf(this, size)");
        newBuffer[elementIndex] = makeNodeAtIndex(elementIndex, newElementHash, e, shift, owner);
        return new TrieNode<>(this.bitmap, newBuffer, owner);
    }

    private final TrieNode<E> makeNode(int elementHash1, E e, int elementHash2, E e2, int shift, MutabilityOwnership owner) {
        Object[] nodeBuffer;
        if (shift > 30) {
            return new TrieNode<>(0, new Object[]{e, e2}, owner);
        }
        int setBit1 = TrieNodeKt.indexSegment(elementHash1, shift);
        int setBit2 = TrieNodeKt.indexSegment(elementHash2, shift);
        if (setBit1 != setBit2) {
            if (setBit1 < setBit2) {
                nodeBuffer = new Object[]{e, e2};
            } else {
                nodeBuffer = new Object[]{e2, e};
            }
            return new TrieNode<>((1 << setBit1) | (1 << setBit2), nodeBuffer, owner);
        }
        TrieNode node = makeNode(elementHash1, e, elementHash2, e2, shift + 5, owner);
        return new TrieNode<>(1 << setBit1, new Object[]{node}, owner);
    }

    private final TrieNode<E> removeCellAtIndex(int cellIndex, int positionMask) {
        Object[] newBuffer;
        newBuffer = TrieNodeKt.removeCellAtIndex(this.buffer, cellIndex);
        return new TrieNode<>(this.bitmap ^ positionMask, newBuffer);
    }

    private final TrieNode<E> mutableRemoveCellAtIndex(int cellIndex, int positionMask, MutabilityOwnership owner) {
        Object[] newBuffer;
        Object[] removeCellAtIndex;
        if (this.ownedBy == owner) {
            removeCellAtIndex = TrieNodeKt.removeCellAtIndex(this.buffer, cellIndex);
            this.buffer = removeCellAtIndex;
            this.bitmap ^= positionMask;
            return this;
        }
        newBuffer = TrieNodeKt.removeCellAtIndex(this.buffer, cellIndex);
        return new TrieNode<>(this.bitmap ^ positionMask, newBuffer, owner);
    }

    private final TrieNode<E> collisionRemoveElementAtIndex(int i) {
        Object[] newBuffer;
        newBuffer = TrieNodeKt.removeCellAtIndex(this.buffer, i);
        return new TrieNode<>(0, newBuffer);
    }

    private final TrieNode<E> mutableCollisionRemoveElementAtIndex(int i, MutabilityOwnership owner) {
        Object[] newBuffer;
        Object[] removeCellAtIndex;
        if (this.ownedBy == owner) {
            removeCellAtIndex = TrieNodeKt.removeCellAtIndex(this.buffer, i);
            this.buffer = removeCellAtIndex;
            return this;
        }
        newBuffer = TrieNodeKt.removeCellAtIndex(this.buffer, i);
        return new TrieNode<>(0, newBuffer, owner);
    }

    private final boolean collisionContainsElement(E e) {
        return ArraysKt.contains((E[]) this.buffer, e);
    }

    private final TrieNode<E> collisionAdd(E e) {
        Object[] newBuffer;
        if (collisionContainsElement(e)) {
            return this;
        }
        newBuffer = TrieNodeKt.addElementAtIndex(this.buffer, 0, e);
        return new TrieNode<>(0, newBuffer);
    }

    private final TrieNode<E> mutableCollisionAdd(E e, PersistentHashSetBuilder<?> persistentHashSetBuilder) {
        Object[] newBuffer;
        Object[] addElementAtIndex;
        if (collisionContainsElement(e)) {
            return this;
        }
        persistentHashSetBuilder.setSize(persistentHashSetBuilder.size() + 1);
        if (this.ownedBy == persistentHashSetBuilder.getOwnership$runtime_release()) {
            addElementAtIndex = TrieNodeKt.addElementAtIndex(this.buffer, 0, e);
            this.buffer = addElementAtIndex;
            return this;
        }
        newBuffer = TrieNodeKt.addElementAtIndex(this.buffer, 0, e);
        return new TrieNode<>(0, newBuffer, persistentHashSetBuilder.getOwnership$runtime_release());
    }

    private final TrieNode<E> collisionRemove(E e) {
        int index = ArraysKt.indexOf((E[]) this.buffer, e);
        if (index != -1) {
            return collisionRemoveElementAtIndex(index);
        }
        return this;
    }

    private final TrieNode<E> mutableCollisionRemove(E e, PersistentHashSetBuilder<?> persistentHashSetBuilder) {
        int index = ArraysKt.indexOf((E[]) this.buffer, e);
        if (index != -1) {
            persistentHashSetBuilder.setSize(persistentHashSetBuilder.size() - 1);
            return mutableCollisionRemoveElementAtIndex(index, persistentHashSetBuilder.getOwnership$runtime_release());
        }
        return this;
    }

    private final TrieNode<E> mutableCollisionAddAll(TrieNode<E> trieNode, DeltaCounter intersectionSizeRef, MutabilityOwnership owner) {
        Object[] copyOf;
        if (this == trieNode) {
            intersectionSizeRef.plusAssign(this.buffer.length);
            return this;
        }
        Object[] objArr = this.buffer;
        Object[] tempBuffer = Arrays.copyOf(objArr, objArr.length + trieNode.buffer.length);
        Intrinsics.checkNotNullExpressionValue(tempBuffer, "copyOf(this, newSize)");
        Object[] $this$filterTo$iv = trieNode.buffer;
        int newArrayOffset$iv = this.buffer.length;
        int i$iv = 0;
        int j$iv = 0;
        while (true) {
            if (i$iv >= $this$filterTo$iv.length) {
                break;
            }
            CommonFunctionsKt.m2259assert(j$iv <= i$iv);
            if (!collisionContainsElement((E) $this$filterTo$iv[i$iv])) {
                tempBuffer[newArrayOffset$iv + j$iv] = $this$filterTo$iv[i$iv];
                j$iv++;
                CommonFunctionsKt.m2259assert(newArrayOffset$iv + j$iv <= tempBuffer.length);
            }
            i$iv++;
        }
        int totalWritten = j$iv;
        int totalSize = this.buffer.length + totalWritten;
        intersectionSizeRef.plusAssign(tempBuffer.length - totalSize);
        if (totalSize == this.buffer.length) {
            return this;
        }
        if (totalSize == trieNode.buffer.length) {
            return trieNode;
        }
        if (totalSize == tempBuffer.length) {
            copyOf = tempBuffer;
        } else {
            copyOf = Arrays.copyOf(tempBuffer, totalSize);
            Intrinsics.checkNotNullExpressionValue(copyOf, "copyOf(this, newSize)");
        }
        Object[] newBuffer = copyOf;
        if (Intrinsics.areEqual(this.ownedBy, owner)) {
            this.buffer = newBuffer;
            return this;
        }
        return new TrieNode<>(0, newBuffer, owner);
    }

    private final Object mutableCollisionRetainAll(TrieNode<E> trieNode, DeltaCounter intersectionSizeRef, MutabilityOwnership owner) {
        if (this == trieNode) {
            intersectionSizeRef.plusAssign(this.buffer.length);
            return this;
        }
        Object[] tempBuffer = Intrinsics.areEqual(owner, this.ownedBy) ? this.buffer : new Object[Math.min(this.buffer.length, trieNode.buffer.length)];
        Object[] $this$filterTo_u24default$iv = this.buffer;
        int i$iv = 0;
        int j$iv = 0;
        while (true) {
            if (i$iv >= $this$filterTo_u24default$iv.length) {
                break;
            }
            CommonFunctionsKt.m2259assert(j$iv <= i$iv);
            if (trieNode.collisionContainsElement((E) $this$filterTo_u24default$iv[i$iv])) {
                tempBuffer[0 + j$iv] = $this$filterTo_u24default$iv[i$iv];
                j$iv++;
                CommonFunctionsKt.m2259assert(0 + j$iv <= tempBuffer.length);
            }
            i$iv++;
        }
        int totalWritten = j$iv;
        intersectionSizeRef.plusAssign(totalWritten);
        if (totalWritten == 0) {
            return EMPTY;
        }
        if (totalWritten == 1) {
            return tempBuffer[0];
        }
        if (totalWritten == this.buffer.length) {
            return this;
        }
        if (totalWritten == trieNode.buffer.length) {
            return trieNode;
        }
        if (totalWritten == tempBuffer.length) {
            return new TrieNode(0, tempBuffer, owner);
        }
        Object[] copyOf = Arrays.copyOf(tempBuffer, totalWritten);
        Intrinsics.checkNotNullExpressionValue(copyOf, "copyOf(this, newSize)");
        return new TrieNode(0, copyOf, owner);
    }

    private final Object mutableCollisionRemoveAll(TrieNode<E> trieNode, DeltaCounter intersectionSizeRef, MutabilityOwnership owner) {
        if (this == trieNode) {
            intersectionSizeRef.plusAssign(this.buffer.length);
            return EMPTY;
        }
        Object[] tempBuffer = Intrinsics.areEqual(owner, this.ownedBy) ? this.buffer : new Object[this.buffer.length];
        Object[] $this$filterTo_u24default$iv = this.buffer;
        int i$iv = 0;
        int j$iv = 0;
        while (true) {
            if (i$iv >= $this$filterTo_u24default$iv.length) {
                break;
            }
            CommonFunctionsKt.m2259assert(j$iv <= i$iv);
            if (!trieNode.collisionContainsElement((E) $this$filterTo_u24default$iv[i$iv])) {
                tempBuffer[0 + j$iv] = $this$filterTo_u24default$iv[i$iv];
                j$iv++;
                CommonFunctionsKt.m2259assert(0 + j$iv <= tempBuffer.length);
            }
            i$iv++;
        }
        int totalWritten = j$iv;
        intersectionSizeRef.plusAssign(this.buffer.length - totalWritten);
        if (totalWritten == 0) {
            return EMPTY;
        }
        if (totalWritten == 1) {
            return tempBuffer[0];
        }
        if (totalWritten == this.buffer.length) {
            return this;
        }
        if (totalWritten == tempBuffer.length) {
            return new TrieNode(0, tempBuffer, owner);
        }
        Object[] copyOf = Arrays.copyOf(tempBuffer, totalWritten);
        Intrinsics.checkNotNullExpressionValue(copyOf, "copyOf(this, newSize)");
        return new TrieNode(0, copyOf, owner);
    }

    private final int calculateSize() {
        Object[] objArr;
        if (this.bitmap == 0) {
            return this.buffer.length;
        }
        int result = 0;
        for (Object e : this.buffer) {
            result += e instanceof TrieNode ? ((TrieNode) e).calculateSize() : 1;
        }
        return result;
    }

    private final boolean elementsIdentityEquals(TrieNode<E> trieNode) {
        if (this == trieNode) {
            return true;
        }
        if (this.bitmap != trieNode.bitmap) {
            return false;
        }
        int length = this.buffer.length;
        for (int i = 0; i < length; i++) {
            if (this.buffer[i] != trieNode.buffer[i]) {
                return false;
            }
        }
        return true;
    }

    public final boolean contains(int elementHash, E e, int shift) {
        int cellPositionMask = 1 << TrieNodeKt.indexSegment(elementHash, shift);
        if (hasNoCellAt(cellPositionMask)) {
            return false;
        }
        int cellIndex = indexOfCellAt$runtime_release(cellPositionMask);
        Object obj = this.buffer[cellIndex];
        if (obj instanceof TrieNode) {
            TrieNode targetNode = nodeAtIndex(cellIndex);
            if (shift == 30) {
                return targetNode.collisionContainsElement(e);
            }
            return targetNode.contains(elementHash, e, shift + 5);
        }
        return Intrinsics.areEqual(e, obj);
    }

    public final TrieNode<E> mutableAddAll(TrieNode<E> otherNode, int shift, DeltaCounter intersectionSizeRef, PersistentHashSetBuilder<?> mutator) {
        Object[] objArr;
        TrieNode<E> makeNode;
        Intrinsics.checkNotNullParameter(otherNode, "otherNode");
        Intrinsics.checkNotNullParameter(intersectionSizeRef, "intersectionSizeRef");
        Intrinsics.checkNotNullParameter(mutator, "mutator");
        if (this == otherNode) {
            intersectionSizeRef.setCount(intersectionSizeRef.getCount() + calculateSize());
            return this;
        } else if (shift > 30) {
            return mutableCollisionAddAll(otherNode, intersectionSizeRef, mutator.getOwnership$runtime_release());
        } else {
            int i = this.bitmap;
            int newBitMap = i | otherNode.bitmap;
            TrieNode mutableNode = (newBitMap == i && Intrinsics.areEqual(this.ownedBy, mutator.getOwnership$runtime_release())) ? this : new TrieNode(newBitMap, new Object[Integer.bitCount(newBitMap)], mutator.getOwnership$runtime_release());
            int mask$iv = newBitMap;
            int index$iv = 0;
            while (mask$iv != 0) {
                int bit$iv = Integer.lowestOneBit(mask$iv);
                int newNodeIndex = index$iv;
                int thisIndex = indexOfCellAt$runtime_release(bit$iv);
                int otherNodeIndex = otherNode.indexOfCellAt$runtime_release(bit$iv);
                Object[] objArr2 = mutableNode.buffer;
                if (hasNoCellAt(bit$iv)) {
                    makeNode = (TrieNode<E>) otherNode.buffer[otherNodeIndex];
                    objArr = objArr2;
                } else if (otherNode.hasNoCellAt(bit$iv)) {
                    makeNode = (TrieNode<E>) this.buffer[thisIndex];
                    objArr = objArr2;
                } else {
                    E e = (E) this.buffer[thisIndex];
                    E e2 = (E) otherNode.buffer[otherNodeIndex];
                    boolean thisIsNode = e instanceof TrieNode;
                    boolean otherIsNode = e2 instanceof TrieNode;
                    if (!thisIsNode || !otherIsNode) {
                        objArr = objArr2;
                        if (thisIsNode) {
                            Intrinsics.checkNotNull(e, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode<E of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode.mutableAddAll$lambda$6>");
                            TrieNode trieNode = (TrieNode) e;
                            int oldSize = mutator.size();
                            TrieNode<E> mutableAdd = ((TrieNode) e).mutableAdd(e2 != null ? e2.hashCode() : 0, e2, shift + 5, mutator);
                            if (mutator.size() == oldSize) {
                                intersectionSizeRef.setCount(intersectionSizeRef.getCount() + 1);
                            }
                            Unit unit = Unit.INSTANCE;
                            makeNode = mutableAdd;
                        } else if (otherIsNode) {
                            Intrinsics.checkNotNull(e2, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode<E of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode.mutableAddAll$lambda$6>");
                            TrieNode trieNode2 = (TrieNode) e2;
                            int oldSize2 = mutator.size();
                            TrieNode<E> mutableAdd2 = ((TrieNode) e2).mutableAdd(e != null ? e.hashCode() : 0, e, shift + 5, mutator);
                            if (mutator.size() == oldSize2) {
                                intersectionSizeRef.setCount(intersectionSizeRef.getCount() + 1);
                            }
                            Unit unit2 = Unit.INSTANCE;
                            makeNode = mutableAdd2;
                        } else if (Intrinsics.areEqual(e, e2)) {
                            intersectionSizeRef.setCount(intersectionSizeRef.getCount() + 1);
                            Object it = Unit.INSTANCE;
                            makeNode = e;
                        } else {
                            makeNode = makeNode(e != null ? e.hashCode() : 0, e, e2 != null ? e2.hashCode() : 0, e2, shift + 5, mutator.getOwnership$runtime_release());
                        }
                    } else {
                        Intrinsics.checkNotNull(e, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode<E of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode.mutableAddAll$lambda$6>");
                        TrieNode trieNode3 = (TrieNode) e;
                        Intrinsics.checkNotNull(e2, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode<E of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode.mutableAddAll$lambda$6>");
                        TrieNode trieNode4 = (TrieNode) e2;
                        objArr = objArr2;
                        int positionMask = shift + 5;
                        makeNode = ((TrieNode) e).mutableAddAll((TrieNode) e2, positionMask, intersectionSizeRef, mutator);
                    }
                }
                objArr[newNodeIndex] = makeNode;
                index$iv++;
                mask$iv ^= bit$iv;
            }
            return elementsIdentityEquals(mutableNode) ? this : otherNode.elementsIdentityEquals(mutableNode) ? otherNode : mutableNode;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final Object mutableRetainAll(TrieNode<E> trieNode, int shift, DeltaCounter intersectionSizeRef, PersistentHashSetBuilder<?> mutator) {
        int newBitMap;
        Object newValue;
        TrieNode trieNode2 = this;
        TrieNode otherNode = trieNode;
        Intrinsics.checkNotNullParameter(otherNode, "otherNode");
        Intrinsics.checkNotNullParameter(intersectionSizeRef, "intersectionSizeRef");
        Intrinsics.checkNotNullParameter(mutator, "mutator");
        if (trieNode2 == otherNode) {
            intersectionSizeRef.plusAssign(calculateSize());
            return trieNode2;
        } else if (shift > 30) {
            return trieNode2.mutableCollisionRetainAll(otherNode, intersectionSizeRef, mutator.getOwnership$runtime_release());
        } else {
            int newBitMap2 = trieNode2.bitmap & otherNode.bitmap;
            if (newBitMap2 == 0) {
                return EMPTY;
            }
            TrieNode mutableNode = (Intrinsics.areEqual(trieNode2.ownedBy, mutator.getOwnership$runtime_release()) && newBitMap2 == trieNode2.bitmap) ? trieNode2 : new TrieNode(newBitMap2, new Object[Integer.bitCount(newBitMap2)], mutator.getOwnership$runtime_release());
            int realBitMap = 0;
            int $this$forEachOneBit$iv = newBitMap2;
            boolean z = false;
            int mask$iv = $this$forEachOneBit$iv;
            int index$iv = 0;
            while (mask$iv != 0) {
                int bit$iv = Integer.lowestOneBit(mask$iv);
                int newNodeIndex = index$iv;
                int thisIndex = trieNode2.indexOfCellAt$runtime_release(bit$iv);
                int otherNodeIndex = otherNode.indexOfCellAt$runtime_release(bit$iv);
                TrieNode $this$mutableRetainAll_u24lambda_u249_u24lambda_u248 = trieNode2;
                Object thisCell = $this$mutableRetainAll_u24lambda_u249_u24lambda_u248.buffer[thisIndex];
                int $this$forEachOneBit$iv2 = $this$forEachOneBit$iv;
                Object otherNodeCell = otherNode.buffer[otherNodeIndex];
                boolean z2 = z;
                boolean thisIsNode = thisCell instanceof TrieNode;
                boolean otherIsNode = otherNodeCell instanceof TrieNode;
                if (!thisIsNode || !otherIsNode) {
                    newBitMap = newBitMap2;
                    if (thisIsNode) {
                        Intrinsics.checkNotNull(thisCell, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode<E of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode.mutableRetainAll$lambda$9$lambda$8>");
                        TrieNode trieNode3 = (TrieNode) thisCell;
                        if (((TrieNode) thisCell).contains(otherNodeCell != null ? otherNodeCell.hashCode() : 0, otherNodeCell, shift + 5)) {
                            intersectionSizeRef.plusAssign(1);
                            newValue = otherNodeCell;
                        } else {
                            newValue = EMPTY;
                        }
                    } else if (otherIsNode) {
                        Intrinsics.checkNotNull(otherNodeCell, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode<E of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode.mutableRetainAll$lambda$9$lambda$8>");
                        TrieNode trieNode4 = (TrieNode) otherNodeCell;
                        if (((TrieNode) otherNodeCell).contains(thisCell != null ? thisCell.hashCode() : 0, thisCell, shift + 5)) {
                            intersectionSizeRef.plusAssign(1);
                            newValue = thisCell;
                        } else {
                            newValue = EMPTY;
                        }
                    } else if (Intrinsics.areEqual(thisCell, otherNodeCell)) {
                        intersectionSizeRef.plusAssign(1);
                        newValue = thisCell;
                    } else {
                        newValue = EMPTY;
                    }
                } else {
                    Intrinsics.checkNotNull(thisCell, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode<E of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode.mutableRetainAll$lambda$9$lambda$8>");
                    TrieNode trieNode5 = (TrieNode) thisCell;
                    Intrinsics.checkNotNull(otherNodeCell, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode<E of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode.mutableRetainAll$lambda$9$lambda$8>");
                    TrieNode trieNode6 = (TrieNode) otherNodeCell;
                    newBitMap = newBitMap2;
                    newValue = ((TrieNode) thisCell).mutableRetainAll((TrieNode) otherNodeCell, shift + 5, intersectionSizeRef, mutator);
                }
                if (newValue != EMPTY) {
                    realBitMap |= bit$iv;
                }
                mutableNode.buffer[newNodeIndex] = newValue;
                index$iv++;
                mask$iv ^= bit$iv;
                trieNode2 = this;
                otherNode = trieNode;
                $this$forEachOneBit$iv = $this$forEachOneBit$iv2;
                z = z2;
                newBitMap2 = newBitMap;
            }
            int newBitMap3 = newBitMap2;
            int realSize = Integer.bitCount(realBitMap);
            if (realBitMap == 0) {
                return EMPTY;
            }
            int newBitMap4 = newBitMap3;
            if (realBitMap == newBitMap4) {
                if (mutableNode.elementsIdentityEquals(this)) {
                    return this;
                }
                return mutableNode.elementsIdentityEquals(trieNode) ? trieNode : mutableNode;
            } else if (realSize == 1 && shift != 0) {
                Object single = mutableNode.buffer[mutableNode.indexOfCellAt$runtime_release(realBitMap)];
                return single instanceof TrieNode ? new TrieNode(realBitMap, new Object[]{single}, mutator.getOwnership$runtime_release()) : single;
            } else {
                Object[] realBuffer = new Object[realSize];
                Object[] $this$filterTo_u24default$iv = mutableNode.buffer;
                int i$iv = 0;
                int j$iv = 0;
                while (i$iv < $this$filterTo_u24default$iv.length) {
                    CommonFunctionsKt.m2259assert(j$iv <= i$iv);
                    Object e$iv = $this$filterTo_u24default$iv[i$iv];
                    int realSize2 = realSize;
                    int newBitMap5 = newBitMap4;
                    if (e$iv != Companion.getEMPTY$runtime_release()) {
                        realBuffer[0 + j$iv] = $this$filterTo_u24default$iv[i$iv];
                        j$iv++;
                        CommonFunctionsKt.m2259assert(0 + j$iv <= realBuffer.length);
                    }
                    i$iv++;
                    realSize = realSize2;
                    newBitMap4 = newBitMap5;
                }
                return new TrieNode(realBitMap, realBuffer, mutator.getOwnership$runtime_release());
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:34:0x00f6, code lost:
        if ((r0 instanceof androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode) == false) goto L22;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object mutableRemoveAll(androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode<E> r28, int r29, androidx.compose.runtime.external.kotlinx.collections.immutable.internal.DeltaCounter r30, androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.PersistentHashSetBuilder<?> r31) {
        /*
            Method dump skipped, instructions count: 490
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode.mutableRemoveAll(androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode, int, androidx.compose.runtime.external.kotlinx.collections.immutable.internal.DeltaCounter, androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.PersistentHashSetBuilder):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final boolean containsAll(TrieNode<E> trieNode, int shift) {
        int potentialBitMap;
        int $this$forEachOneBit$iv;
        boolean z;
        TrieNode<E> trieNode2 = this;
        TrieNode<E> otherNode = trieNode;
        Intrinsics.checkNotNullParameter(otherNode, "otherNode");
        if (trieNode2 == otherNode) {
            return true;
        }
        if (shift <= 30) {
            int i = trieNode2.bitmap;
            int i2 = otherNode.bitmap;
            int potentialBitMap2 = i & i2;
            if (potentialBitMap2 != i2) {
                return false;
            }
            int $this$forEachOneBit$iv2 = potentialBitMap2;
            int mask$iv = $this$forEachOneBit$iv2;
            int index$iv = 0;
            while (mask$iv != 0) {
                int bit$iv = Integer.lowestOneBit(mask$iv);
                int thisIndex = trieNode2.indexOfCellAt$runtime_release(bit$iv);
                int otherNodeIndex = otherNode.indexOfCellAt$runtime_release(bit$iv);
                Object thisCell = trieNode2.buffer[thisIndex];
                Object otherNodeCell = otherNode.buffer[otherNodeIndex];
                boolean thisIsNode = thisCell instanceof TrieNode;
                boolean otherIsNode = otherNodeCell instanceof TrieNode;
                if (!thisIsNode || !otherIsNode) {
                    potentialBitMap = potentialBitMap2;
                    $this$forEachOneBit$iv = $this$forEachOneBit$iv2;
                    if (thisIsNode) {
                        Intrinsics.checkNotNull(thisCell, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode<E of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode.containsAll$lambda$13>");
                        TrieNode trieNode3 = (TrieNode) thisCell;
                        if (!((TrieNode) thisCell).contains(otherNodeCell != null ? otherNodeCell.hashCode() : 0, otherNodeCell, shift + 5)) {
                            return false;
                        }
                        z = false;
                    } else {
                        z = false;
                        if (otherIsNode || !Intrinsics.areEqual(thisCell, otherNodeCell)) {
                            return false;
                        }
                    }
                } else {
                    Intrinsics.checkNotNull(thisCell, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode<E of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode.containsAll$lambda$13>");
                    TrieNode trieNode4 = (TrieNode) thisCell;
                    Intrinsics.checkNotNull(otherNodeCell, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode<E of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableSet.TrieNode.containsAll$lambda$13>");
                    TrieNode trieNode5 = (TrieNode) otherNodeCell;
                    potentialBitMap = potentialBitMap2;
                    $this$forEachOneBit$iv = $this$forEachOneBit$iv2;
                    if (!((TrieNode) thisCell).containsAll((TrieNode) otherNodeCell, shift + 5)) {
                        return false;
                    }
                    z = false;
                }
                index$iv++;
                mask$iv ^= bit$iv;
                trieNode2 = this;
                potentialBitMap2 = potentialBitMap;
                $this$forEachOneBit$iv2 = $this$forEachOneBit$iv;
                otherNode = trieNode;
            }
            return true;
        }
        Object[] $this$all$iv = otherNode.buffer;
        for (Object element$iv : $this$all$iv) {
            if (!ArraysKt.contains(trieNode2.buffer, element$iv)) {
                return false;
            }
        }
        return true;
    }

    public final TrieNode<E> add(int elementHash, E e, int shift) {
        TrieNode newNode;
        int cellPositionMask = 1 << TrieNodeKt.indexSegment(elementHash, shift);
        if (hasNoCellAt(cellPositionMask)) {
            return addElementAt(cellPositionMask, e);
        }
        int cellIndex = indexOfCellAt$runtime_release(cellPositionMask);
        Object obj = this.buffer[cellIndex];
        if (!(obj instanceof TrieNode)) {
            return Intrinsics.areEqual(e, obj) ? this : moveElementToNode(cellIndex, elementHash, e, shift);
        }
        TrieNode targetNode = nodeAtIndex(cellIndex);
        if (shift == 30) {
            newNode = targetNode.collisionAdd(e);
        } else {
            newNode = targetNode.add(elementHash, e, shift + 5);
        }
        return targetNode == newNode ? this : updateNodeAtIndex(cellIndex, newNode);
    }

    public final TrieNode<E> mutableAdd(int elementHash, E e, int shift, PersistentHashSetBuilder<?> mutator) {
        TrieNode newNode;
        Intrinsics.checkNotNullParameter(mutator, "mutator");
        int cellPosition = 1 << TrieNodeKt.indexSegment(elementHash, shift);
        if (hasNoCellAt(cellPosition)) {
            mutator.setSize(mutator.size() + 1);
            return mutableAddElementAt(cellPosition, e, mutator.getOwnership$runtime_release());
        }
        int cellIndex = indexOfCellAt$runtime_release(cellPosition);
        Object obj = this.buffer[cellIndex];
        if (obj instanceof TrieNode) {
            TrieNode targetNode = nodeAtIndex(cellIndex);
            if (shift == 30) {
                newNode = targetNode.mutableCollisionAdd(e, mutator);
            } else {
                newNode = targetNode.mutableAdd(elementHash, e, shift + 5, mutator);
            }
            return targetNode == newNode ? this : mutableUpdateNodeAtIndex(cellIndex, newNode, mutator.getOwnership$runtime_release());
        } else if (Intrinsics.areEqual(e, obj)) {
            return this;
        } else {
            mutator.setSize(mutator.size() + 1);
            return mutableMoveElementToNode(cellIndex, elementHash, e, shift, mutator.getOwnership$runtime_release());
        }
    }

    public final TrieNode<E> remove(int elementHash, E e, int shift) {
        TrieNode newNode;
        int cellPositionMask = 1 << TrieNodeKt.indexSegment(elementHash, shift);
        if (hasNoCellAt(cellPositionMask)) {
            return this;
        }
        int cellIndex = indexOfCellAt$runtime_release(cellPositionMask);
        Object obj = this.buffer[cellIndex];
        if (obj instanceof TrieNode) {
            TrieNode targetNode = nodeAtIndex(cellIndex);
            if (shift == 30) {
                newNode = targetNode.collisionRemove(e);
            } else {
                newNode = targetNode.remove(elementHash, e, shift + 5);
            }
            return targetNode == newNode ? this : updateNodeAtIndex(cellIndex, newNode);
        } else if (Intrinsics.areEqual(e, obj)) {
            return removeCellAtIndex(cellIndex, cellPositionMask);
        } else {
            return this;
        }
    }

    public final TrieNode<E> mutableRemove(int elementHash, E e, int shift, PersistentHashSetBuilder<?> mutator) {
        TrieNode newNode;
        Intrinsics.checkNotNullParameter(mutator, "mutator");
        int cellPositionMask = 1 << TrieNodeKt.indexSegment(elementHash, shift);
        if (hasNoCellAt(cellPositionMask)) {
            return this;
        }
        int cellIndex = indexOfCellAt$runtime_release(cellPositionMask);
        Object obj = this.buffer[cellIndex];
        if (obj instanceof TrieNode) {
            TrieNode targetNode = nodeAtIndex(cellIndex);
            if (shift == 30) {
                newNode = targetNode.mutableCollisionRemove(e, mutator);
            } else {
                newNode = targetNode.mutableRemove(elementHash, e, shift + 5, mutator);
            }
            if (this.ownedBy == mutator.getOwnership$runtime_release() || targetNode != newNode) {
                return mutableUpdateNodeAtIndex(cellIndex, newNode, mutator.getOwnership$runtime_release());
            }
            return this;
        } else if (Intrinsics.areEqual(e, obj)) {
            mutator.setSize(mutator.size() - 1);
            return mutableRemoveCellAtIndex(cellIndex, cellPositionMask, mutator.getOwnership$runtime_release());
        } else {
            return this;
        }
    }

    /* compiled from: TrieNode.kt */
    @Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0001\n\u0002\b\u0003\b\u0080\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u001a\u0010\u0003\u001a\b\u0012\u0004\u0012\u00020\u00050\u0004X\u0080\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0006\u0010\u0007¨\u0006\b"}, d2 = {"Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/TrieNode$Companion;", "", "()V", "EMPTY", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/TrieNode;", "", "getEMPTY$runtime_release", "()Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableSet/TrieNode;", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        public final TrieNode getEMPTY$runtime_release() {
            return TrieNode.EMPTY;
        }
    }
}
