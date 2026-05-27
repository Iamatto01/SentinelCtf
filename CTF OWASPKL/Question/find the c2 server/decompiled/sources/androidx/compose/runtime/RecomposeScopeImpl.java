package androidx.compose.runtime;

import androidx.compose.runtime.collection.IdentityArrayIntMap;
import androidx.compose.runtime.collection.IdentityArrayMap;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: RecomposeScopeImpl.kt */
@Metadata(d1 = {"\u0000j\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u001a\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\b\u0000\u0018\u00002\u00020\u00012\u00020\u0002B\u000f\u0012\b\u0010\u0003\u001a\u0004\u0018\u00010\u0004¢\u0006\u0002\u0010\u0005J\u000e\u00107\u001a\u00020\u00102\u0006\u0010\u0003\u001a\u00020\u0004J\u000e\u00108\u001a\u00020\u00102\u0006\u00109\u001a\u00020\u000eJ\u001c\u0010:\u001a\u0010\u0012\u0004\u0012\u00020<\u0012\u0004\u0012\u00020\u0010\u0018\u00010;2\u0006\u0010=\u001a\u00020\u000fJ\b\u0010>\u001a\u00020\u0010H\u0016J\u0010\u0010?\u001a\u00020@2\b\u0010\u0019\u001a\u0004\u0018\u00010/J\u0016\u0010A\u001a\u00020\u00122\u000e\u0010B\u001a\n\u0012\u0004\u0012\u00020/\u0018\u00010CJ\u000e\u0010D\u001a\u00020\u00102\u0006\u0010E\u001a\u00020/J\u0006\u0010F\u001a\u00020\u0010J\u0006\u0010G\u001a\u00020\u0010J\u0006\u0010H\u001a\u00020\u0010J\u000e\u0010I\u001a\u00020\u00102\u0006\u0010=\u001a\u00020\u000fJ\"\u0010J\u001a\u00020\u00102\u0018\u0010\f\u001a\u0014\u0012\u0004\u0012\u00020\u000e\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u00100\rH\u0016R\u001c\u0010\u0006\u001a\u0004\u0018\u00010\u0007X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\b\u0010\t\"\u0004\b\n\u0010\u000bR\"\u0010\f\u001a\u0016\u0012\u0004\u0012\u00020\u000e\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u0010\u0018\u00010\rX\u0082\u000e¢\u0006\u0002\n\u0000R\u0011\u0010\u0011\u001a\u00020\u00128F¢\u0006\u0006\u001a\u0004\b\u0013\u0010\u0014R\"\u0010\u0003\u001a\u0004\u0018\u00010\u00042\b\u0010\u0015\u001a\u0004\u0018\u00010\u0004@BX\u0086\u000e¢\u0006\b\n\u0000\u001a\u0004\b\u0016\u0010\u0017R\u000e\u0010\u0018\u001a\u00020\u000fX\u0082\u000e¢\u0006\u0002\n\u0000R$\u0010\u001a\u001a\u00020\u00122\u0006\u0010\u0019\u001a\u00020\u00128F@FX\u0086\u000e¢\u0006\f\u001a\u0004\b\u001b\u0010\u0014\"\u0004\b\u001c\u0010\u001dR$\u0010\u001e\u001a\u00020\u00122\u0006\u0010\u0019\u001a\u00020\u00128F@FX\u0086\u000e¢\u0006\f\u001a\u0004\b\u001f\u0010\u0014\"\u0004\b \u0010\u001dR\u000e\u0010!\u001a\u00020\u000fX\u0082\u000e¢\u0006\u0002\n\u0000R\u0011\u0010\"\u001a\u00020\u00128F¢\u0006\u0006\u001a\u0004\b\"\u0010\u0014R$\u0010#\u001a\u00020\u00122\u0006\u0010\u0019\u001a\u00020\u00128F@FX\u0086\u000e¢\u0006\f\u001a\u0004\b$\u0010\u0014\"\u0004\b%\u0010\u001dR$\u0010&\u001a\u00020\u00122\u0006\u0010\u0019\u001a\u00020\u00128B@BX\u0082\u000e¢\u0006\f\u001a\u0004\b'\u0010\u0014\"\u0004\b(\u0010\u001dR$\u0010)\u001a\u00020\u00122\u0006\u0010\u0019\u001a\u00020\u00128@@BX\u0080\u000e¢\u0006\f\u001a\u0004\b*\u0010\u0014\"\u0004\b+\u0010\u001dR\"\u0010,\u001a\u0016\u0012\b\u0012\u0006\u0012\u0002\b\u00030.\u0012\u0006\u0012\u0004\u0018\u00010/\u0018\u00010-X\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u00100\u001a\u0004\u0018\u000101X\u0082\u000e¢\u0006\u0002\n\u0000R$\u00102\u001a\u00020\u00122\u0006\u0010\u0019\u001a\u00020\u00128F@FX\u0086\u000e¢\u0006\f\u001a\u0004\b3\u0010\u0014\"\u0004\b4\u0010\u001dR\u0011\u00105\u001a\u00020\u00128F¢\u0006\u0006\u001a\u0004\b6\u0010\u0014¨\u0006K"}, d2 = {"Landroidx/compose/runtime/RecomposeScopeImpl;", "Landroidx/compose/runtime/ScopeUpdateScope;", "Landroidx/compose/runtime/RecomposeScope;", "composition", "Landroidx/compose/runtime/CompositionImpl;", "(Landroidx/compose/runtime/CompositionImpl;)V", "anchor", "Landroidx/compose/runtime/Anchor;", "getAnchor", "()Landroidx/compose/runtime/Anchor;", "setAnchor", "(Landroidx/compose/runtime/Anchor;)V", "block", "Lkotlin/Function2;", "Landroidx/compose/runtime/Composer;", "", "", "canRecompose", "", "getCanRecompose", "()Z", "<set-?>", "getComposition", "()Landroidx/compose/runtime/CompositionImpl;", "currentToken", "value", "defaultsInScope", "getDefaultsInScope", "setDefaultsInScope", "(Z)V", "defaultsInvalid", "getDefaultsInvalid", "setDefaultsInvalid", "flags", "isConditional", "requiresRecompose", "getRequiresRecompose", "setRequiresRecompose", "rereading", "getRereading", "setRereading", "skipped", "getSkipped$runtime_release", "setSkipped", "trackedDependencies", "Landroidx/compose/runtime/collection/IdentityArrayMap;", "Landroidx/compose/runtime/DerivedState;", "", "trackedInstances", "Landroidx/compose/runtime/collection/IdentityArrayIntMap;", "used", "getUsed", "setUsed", "valid", "getValid", "adoptedBy", "compose", "composer", "end", "Lkotlin/Function1;", "Landroidx/compose/runtime/Composition;", "token", "invalidate", "invalidateForResult", "Landroidx/compose/runtime/InvalidationResult;", "isInvalidFor", "instances", "Landroidx/compose/runtime/collection/IdentityArraySet;", "recordRead", "instance", "release", "rereadTrackedInstances", "scopeSkipped", "start", "updateScope", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class RecomposeScopeImpl implements ScopeUpdateScope, RecomposeScope {
    private Anchor anchor;
    private Function2<? super Composer, ? super Integer, Unit> block;
    private CompositionImpl composition;
    private int currentToken;
    private int flags;
    private IdentityArrayMap<DerivedState<?>, Object> trackedDependencies;
    private IdentityArrayIntMap trackedInstances;

    public RecomposeScopeImpl(CompositionImpl composition) {
        this.composition = composition;
    }

    public final CompositionImpl getComposition() {
        return this.composition;
    }

    public final Anchor getAnchor() {
        return this.anchor;
    }

    public final void setAnchor(Anchor anchor) {
        this.anchor = anchor;
    }

    public final boolean getValid() {
        if (this.composition != null) {
            Anchor anchor = this.anchor;
            return anchor != null ? anchor.getValid() : false;
        }
        return false;
    }

    public final boolean getCanRecompose() {
        return this.block != null;
    }

    public final boolean getUsed() {
        return (this.flags & 1) != 0;
    }

    public final void setUsed(boolean value) {
        if (value) {
            this.flags |= 1;
        } else {
            this.flags &= -2;
        }
    }

    public final boolean getDefaultsInScope() {
        return (this.flags & 2) != 0;
    }

    public final void setDefaultsInScope(boolean value) {
        if (value) {
            this.flags |= 2;
        } else {
            this.flags &= -3;
        }
    }

    public final boolean getDefaultsInvalid() {
        return (this.flags & 4) != 0;
    }

    public final void setDefaultsInvalid(boolean value) {
        if (value) {
            this.flags |= 4;
        } else {
            this.flags &= -5;
        }
    }

    public final boolean getRequiresRecompose() {
        return (this.flags & 8) != 0;
    }

    public final void setRequiresRecompose(boolean value) {
        if (value) {
            this.flags |= 8;
        } else {
            this.flags &= -9;
        }
    }

    public final void compose(Composer composer) {
        Unit unit;
        Intrinsics.checkNotNullParameter(composer, "composer");
        Function2<? super Composer, ? super Integer, Unit> function2 = this.block;
        if (function2 != null) {
            function2.invoke(composer, 1);
            unit = Unit.INSTANCE;
        } else {
            unit = null;
        }
        if (unit == null) {
            throw new IllegalStateException("Invalid restart scope".toString());
        }
    }

    public final InvalidationResult invalidateForResult(Object value) {
        InvalidationResult invalidate;
        CompositionImpl compositionImpl = this.composition;
        return (compositionImpl == null || (invalidate = compositionImpl.invalidate(this, value)) == null) ? InvalidationResult.IGNORED : invalidate;
    }

    public final void release() {
        this.composition = null;
        this.trackedInstances = null;
        this.trackedDependencies = null;
    }

    public final void adoptedBy(CompositionImpl composition) {
        Intrinsics.checkNotNullParameter(composition, "composition");
        this.composition = composition;
    }

    @Override // androidx.compose.runtime.RecomposeScope
    public void invalidate() {
        CompositionImpl compositionImpl = this.composition;
        if (compositionImpl != null) {
            compositionImpl.invalidate(this, null);
        }
    }

    @Override // androidx.compose.runtime.ScopeUpdateScope
    public void updateScope(Function2<? super Composer, ? super Integer, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        this.block = block;
    }

    private final boolean getRereading() {
        return (this.flags & 32) != 0;
    }

    private final void setRereading(boolean value) {
        if (value) {
            this.flags |= 32;
        } else {
            this.flags &= -33;
        }
    }

    public final boolean getSkipped$runtime_release() {
        return (this.flags & 16) != 0;
    }

    private final void setSkipped(boolean value) {
        if (value) {
            this.flags |= 16;
        } else {
            this.flags &= -17;
        }
    }

    public final void start(int token) {
        this.currentToken = token;
        setSkipped(false);
    }

    public final void scopeSkipped() {
        setSkipped(true);
    }

    public final void recordRead(Object instance) {
        Intrinsics.checkNotNullParameter(instance, "instance");
        if (getRereading()) {
            return;
        }
        IdentityArrayIntMap it = this.trackedInstances;
        if (it == null) {
            it = new IdentityArrayIntMap();
            this.trackedInstances = it;
        }
        it.add(instance, this.currentToken);
        if (instance instanceof DerivedState) {
            IdentityArrayMap it2 = this.trackedDependencies;
            if (it2 == null) {
                it2 = new IdentityArrayMap(0, 1, null);
                this.trackedDependencies = it2;
            }
            it2.set(instance, ((DerivedState) instance).getCurrentValue());
        }
    }

    public final boolean isConditional() {
        return this.trackedDependencies != null;
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x005a A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean isInvalidFor(androidx.compose.runtime.collection.IdentityArraySet<java.lang.Object> r15) {
        /*
            r14 = this;
            r0 = 1
            if (r15 != 0) goto L4
            return r0
        L4:
            androidx.compose.runtime.collection.IdentityArrayMap<androidx.compose.runtime.DerivedState<?>, java.lang.Object> r1 = r14.trackedDependencies
            if (r1 != 0) goto L9
            return r0
        L9:
            boolean r2 = r15.isNotEmpty()
            if (r2 == 0) goto L60
            r2 = r15
            java.lang.Iterable r2 = (java.lang.Iterable) r2
            r3 = 0
            boolean r4 = r2 instanceof java.util.Collection
            r5 = 0
            if (r4 == 0) goto L24
            r4 = r2
            java.util.Collection r4 = (java.util.Collection) r4
            boolean r4 = r4.isEmpty()
            if (r4 == 0) goto L24
            r2 = r0
            goto L5d
        L24:
            java.util.Iterator r4 = r2.iterator()
        L28:
            boolean r6 = r4.hasNext()
            if (r6 == 0) goto L5c
            java.lang.Object r6 = r4.next()
            r7 = r6
            r8 = 0
            boolean r9 = r7 instanceof androidx.compose.runtime.DerivedState
            if (r9 == 0) goto L57
            r9 = r7
            androidx.compose.runtime.DerivedState r9 = (androidx.compose.runtime.DerivedState) r9
            r10 = 0
            androidx.compose.runtime.SnapshotMutationPolicy r11 = r9.getPolicy()
            if (r11 != 0) goto L47
            androidx.compose.runtime.SnapshotMutationPolicy r11 = androidx.compose.runtime.SnapshotStateKt.structuralEqualityPolicy()
        L47:
            java.lang.Object r12 = r9.getCurrentValue()
            java.lang.Object r13 = r1.get(r9)
            boolean r9 = r11.equivalent(r12, r13)
            if (r9 == 0) goto L57
            r9 = r0
            goto L58
        L57:
            r9 = r5
        L58:
            if (r9 != 0) goto L28
            r2 = r5
            goto L5d
        L5c:
            r2 = r0
        L5d:
            if (r2 == 0) goto L60
            return r5
        L60:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.RecomposeScopeImpl.isInvalidFor(androidx.compose.runtime.collection.IdentityArraySet):boolean");
    }

    public final void rereadTrackedInstances() {
        IdentityArrayIntMap trackedInstances;
        CompositionImpl composition = this.composition;
        if (composition != null && (trackedInstances = this.trackedInstances) != null) {
            setRereading(true);
            try {
                int size = trackedInstances.getSize();
                for (int i$iv = 0; i$iv < size; i$iv++) {
                    Object value = trackedInstances.getKeys()[i$iv];
                    Intrinsics.checkNotNull(value, "null cannot be cast to non-null type kotlin.Any");
                    int i = trackedInstances.getValues()[i$iv];
                    composition.recordReadOf(value);
                }
            } finally {
                setRereading(false);
            }
        }
    }

    public final Function1<Composition, Unit> end(final int token) {
        boolean z;
        final IdentityArrayIntMap instances = this.trackedInstances;
        if (instances == null || getSkipped$runtime_release()) {
            return null;
        }
        int i$iv = 0;
        int size = instances.getSize();
        while (true) {
            if (i$iv >= size) {
                break;
            }
            Intrinsics.checkNotNull(instances.getKeys()[i$iv], "null cannot be cast to non-null type kotlin.Any");
            int instanceToken = instances.getValues()[i$iv];
            if (instanceToken != token) {
                z = true;
                break;
            }
            i$iv++;
        }
        if (z) {
            return new Function1<Composition, Unit>() { // from class: androidx.compose.runtime.RecomposeScopeImpl$end$1$2
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Composition composition) {
                    invoke2(composition);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2(Composition composition) {
                    int i;
                    IdentityArrayIntMap identityArrayIntMap;
                    int i2;
                    IdentityArrayMap dependencies;
                    Composition composition2 = composition;
                    Intrinsics.checkNotNullParameter(composition2, "composition");
                    i = RecomposeScopeImpl.this.currentToken;
                    if (i == token) {
                        IdentityArrayIntMap identityArrayIntMap2 = instances;
                        identityArrayIntMap = RecomposeScopeImpl.this.trackedInstances;
                        if (Intrinsics.areEqual(identityArrayIntMap2, identityArrayIntMap) && (composition2 instanceof CompositionImpl)) {
                            IdentityArrayIntMap this_$iv = instances;
                            int i3 = token;
                            RecomposeScopeImpl recomposeScopeImpl = RecomposeScopeImpl.this;
                            int destinationIndex$iv = 0;
                            int i$iv2 = 0;
                            int size2 = this_$iv.getSize();
                            while (i$iv2 < size2) {
                                Object key$iv = this_$iv.getKeys()[i$iv2];
                                Intrinsics.checkNotNull(key$iv, "null cannot be cast to non-null type kotlin.Any");
                                int value$iv = this_$iv.getValues()[i$iv2];
                                boolean z2 = value$iv != i3;
                                boolean remove = z2;
                                if (!remove) {
                                    i2 = i3;
                                } else {
                                    ((CompositionImpl) composition2).removeObservation$runtime_release(key$iv, recomposeScopeImpl);
                                    DerivedState it = key$iv instanceof DerivedState ? (DerivedState) key$iv : null;
                                    if (it == null) {
                                        i2 = i3;
                                    } else {
                                        i2 = i3;
                                        ((CompositionImpl) composition2).removeDerivedStateObservation$runtime_release(it);
                                        dependencies = recomposeScopeImpl.trackedDependencies;
                                        if (dependencies != null) {
                                            dependencies.remove(it);
                                            if (dependencies.getSize$runtime_release() == 0) {
                                                recomposeScopeImpl.trackedDependencies = null;
                                            }
                                        }
                                    }
                                }
                                if (!z2) {
                                    if (destinationIndex$iv != i$iv2) {
                                        this_$iv.getKeys()[destinationIndex$iv] = key$iv;
                                        this_$iv.getValues()[destinationIndex$iv] = value$iv;
                                    }
                                    destinationIndex$iv++;
                                }
                                i$iv2++;
                                composition2 = composition;
                                i3 = i2;
                            }
                            int size3 = this_$iv.getSize();
                            for (int i$iv3 = destinationIndex$iv; i$iv3 < size3; i$iv3++) {
                                this_$iv.getKeys()[i$iv3] = null;
                            }
                            this_$iv.setSize(destinationIndex$iv);
                            if (instances.getSize() == 0) {
                                RecomposeScopeImpl.this.trackedInstances = null;
                            }
                        }
                    }
                }
            };
        }
        return null;
    }
}
