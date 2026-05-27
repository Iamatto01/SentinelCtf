package androidx.compose.runtime.snapshots;

import androidx.autofill.HintConstants;
import androidx.compose.animation.core.MutatorMutex$$ExternalSyntheticBackportWithForwarding0;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.DerivedState;
import androidx.compose.runtime.SnapshotMutationPolicy;
import androidx.compose.runtime.SnapshotStateKt;
import androidx.compose.runtime.State;
import androidx.compose.runtime.collection.IdentityArrayIntMap;
import androidx.compose.runtime.collection.IdentityArrayMap;
import androidx.compose.runtime.collection.IdentityArraySet;
import androidx.compose.runtime.collection.IdentityScopeMap;
import androidx.compose.runtime.collection.MutableVector;
import androidx.compose.runtime.snapshots.Snapshot;
import androidx.compose.runtime.snapshots.SnapshotStateObserver;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Deprecated;
import kotlin.KotlinNothingValueException;
import kotlin.Metadata;
import kotlin.ReplaceWith;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.InlineMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.TypeIntrinsics;
/* compiled from: SnapshotStateObserver.kt */
@Metadata(d1 = {"\u0000X\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0016\n\u0002\u0010\u0001\n\u0002\b\u0006\b\u0007\u0018\u00002\u00020\u0001:\u00014B.\u0012'\u0010\u0002\u001a#\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020\u00050\u0004¢\u0006\f\b\u0006\u0012\b\b\u0007\u0012\u0004\b\b(\b\u0012\u0004\u0012\u00020\u00050\u0003¢\u0006\u0002\u0010\tJ\u0016\u0010\u001b\u001a\u00020\u00052\f\u0010\u001c\u001a\b\u0012\u0004\u0012\u00020\u00010\fH\u0002J\u0006\u0010\u001d\u001a\u00020\u0005J\u000e\u0010\u001d\u001a\u00020\u00052\u0006\u0010\u001e\u001a\u00020\u0001J)\u0010\u001f\u001a\u00020\u00052!\u0010 \u001a\u001d\u0012\u0013\u0012\u00110\u0001¢\u0006\f\b\u0006\u0012\b\b\u0007\u0012\u0004\b\b(\u001e\u0012\u0004\u0012\u00020\u00130\u0003J\b\u0010!\u001a\u00020\u0013H\u0002J&\u0010\"\u001a\u00020\u0011\"\b\b\u0000\u0010#*\u00020\u00012\u0012\u0010$\u001a\u000e\u0012\u0004\u0012\u0002H#\u0012\u0004\u0012\u00020\u00050\u0003H\u0002J\u001d\u0010%\u001a\u00020\u00052\u0012\u0010&\u001a\u000e\u0012\u0004\u0012\u00020\u0011\u0012\u0004\u0012\u00020\u00050\u0003H\u0082\bJ\u001c\u0010'\u001a\u00020\u00052\f\u0010(\u001a\b\u0012\u0004\u0012\u00020\u00010\f2\u0006\u0010)\u001a\u00020\rJ?\u0010*\u001a\u00020\u0005\"\b\b\u0000\u0010#*\u00020\u00012\u0006\u0010\u001e\u001a\u0002H#2\u0012\u0010+\u001a\u000e\u0012\u0004\u0012\u0002H#\u0012\u0004\u0012\u00020\u00050\u00032\f\u0010&\u001a\b\u0012\u0004\u0012\u00020\u00050\u0004¢\u0006\u0002\u0010,J\u0010\u0010-\u001a\n\u0012\u0004\u0012\u00020\u0001\u0018\u00010\fH\u0002J\b\u0010.\u001a\u00020/H\u0002J\b\u00100\u001a\u00020\u0005H\u0002J\u0006\u00101\u001a\u00020\u0005J\u0006\u00102\u001a\u00020\u0005J\u0016\u00103\u001a\u00020\u00052\f\u0010&\u001a\b\u0012\u0004\u0012\u00020\u00050\u0004H\u0007R&\u0010\n\u001a\u001a\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00010\f\u0012\u0004\u0012\u00020\r\u0012\u0004\u0012\u00020\u00050\u000bX\u0082\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u000e\u001a\u0004\u0018\u00010\u000fX\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\u0010\u001a\u0004\u0018\u00010\u0011X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0012\u001a\u00020\u0013X\u0082\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u00110\u0015X\u0082\u0004¢\u0006\u0002\n\u0000R/\u0010\u0002\u001a#\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020\u00050\u0004¢\u0006\f\b\u0006\u0012\b\b\u0007\u0012\u0004\b\b(\b\u0012\u0004\u0012\u00020\u00050\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\"\u0010\u0016\u001a\u0016\u0012\u0006\u0012\u0004\u0018\u00010\u00010\u0017j\n\u0012\u0006\u0012\u0004\u0018\u00010\u0001`\u0018X\u0082\u0004¢\u0006\u0002\n\u0000R\u001a\u0010\u0019\u001a\u000e\u0012\u0004\u0012\u00020\u0001\u0012\u0004\u0012\u00020\u00050\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u001a\u001a\u00020\u0013X\u0082\u000e¢\u0006\u0002\n\u0000¨\u00065"}, d2 = {"Landroidx/compose/runtime/snapshots/SnapshotStateObserver;", "", "onChangedExecutor", "Lkotlin/Function1;", "Lkotlin/Function0;", "", "Lkotlin/ParameterName;", HintConstants.AUTOFILL_HINT_NAME, "callback", "(Lkotlin/jvm/functions/Function1;)V", "applyObserver", "Lkotlin/Function2;", "", "Landroidx/compose/runtime/snapshots/Snapshot;", "applyUnsubscribe", "Landroidx/compose/runtime/snapshots/ObserverHandle;", "currentMap", "Landroidx/compose/runtime/snapshots/SnapshotStateObserver$ObservedScopeMap;", "isPaused", "", "observedScopeMaps", "Landroidx/compose/runtime/collection/MutableVector;", "pendingChanges", "Ljava/util/concurrent/atomic/AtomicReference;", "Landroidx/compose/runtime/AtomicReference;", "readObserver", "sendingNotifications", "addChanges", "set", "clear", "scope", "clearIf", "predicate", "drainChanges", "ensureMap", "T", "onChanged", "forEachScopeMap", "block", "notifyChanges", "changes", "snapshot", "observeReads", "onValueChangedForScope", "(Ljava/lang/Object;Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function0;)V", "removeChanges", "report", "", "sendNotifications", "start", "stop", "withNoObservations", "ObservedScopeMap", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class SnapshotStateObserver {
    public static final int $stable = 8;
    private final Function2<Set<? extends Object>, Snapshot, Unit> applyObserver;
    private ObserverHandle applyUnsubscribe;
    private ObservedScopeMap currentMap;
    private boolean isPaused;
    private final MutableVector<ObservedScopeMap> observedScopeMaps;
    private final Function1<Function0<Unit>, Unit> onChangedExecutor;
    private final AtomicReference<Object> pendingChanges;
    private final Function1<Object, Unit> readObserver;
    private boolean sendingNotifications;

    /* JADX WARN: Multi-variable type inference failed */
    public SnapshotStateObserver(Function1<? super Function0<Unit>, Unit> onChangedExecutor) {
        Intrinsics.checkNotNullParameter(onChangedExecutor, "onChangedExecutor");
        this.onChangedExecutor = onChangedExecutor;
        this.pendingChanges = new AtomicReference<>(null);
        this.applyObserver = new Function2<Set<? extends Object>, Snapshot, Unit>() { // from class: androidx.compose.runtime.snapshots.SnapshotStateObserver$applyObserver$1
            /* JADX INFO: Access modifiers changed from: package-private */
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(Set<? extends Object> set, Snapshot snapshot) {
                invoke2(set, snapshot);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke  reason: avoid collision after fix types in other method */
            public final void invoke2(Set<? extends Object> applied, Snapshot snapshot) {
                boolean drainChanges;
                Intrinsics.checkNotNullParameter(applied, "applied");
                Intrinsics.checkNotNullParameter(snapshot, "<anonymous parameter 1>");
                SnapshotStateObserver.this.addChanges(applied);
                drainChanges = SnapshotStateObserver.this.drainChanges();
                if (drainChanges) {
                    SnapshotStateObserver.this.sendNotifications();
                }
            }
        };
        this.readObserver = new Function1<Object, Unit>() { // from class: androidx.compose.runtime.snapshots.SnapshotStateObserver$readObserver$1
            /* JADX INFO: Access modifiers changed from: package-private */
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
                boolean z;
                MutableVector mutableVector;
                SnapshotStateObserver.ObservedScopeMap observedScopeMap;
                Intrinsics.checkNotNullParameter(state, "state");
                z = SnapshotStateObserver.this.isPaused;
                if (!z) {
                    mutableVector = SnapshotStateObserver.this.observedScopeMaps;
                    SnapshotStateObserver snapshotStateObserver = SnapshotStateObserver.this;
                    synchronized (mutableVector) {
                        observedScopeMap = snapshotStateObserver.currentMap;
                        Intrinsics.checkNotNull(observedScopeMap);
                        observedScopeMap.recordRead(state);
                        Unit unit = Unit.INSTANCE;
                    }
                }
            }
        };
        this.observedScopeMaps = new MutableVector<>(new ObservedScopeMap[16], 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final boolean drainChanges() {
        boolean z;
        boolean z2;
        synchronized (this.observedScopeMaps) {
            z = this.sendingNotifications;
        }
        if (z) {
            return false;
        }
        boolean hasValues = false;
        while (true) {
            Set notifications = removeChanges();
            if (notifications == null) {
                return hasValues;
            }
            synchronized (this.observedScopeMaps) {
                MutableVector this_$iv$iv = this.observedScopeMaps;
                int size$iv$iv = this_$iv$iv.getSize();
                if (size$iv$iv > 0) {
                    int i$iv$iv = 0;
                    Object[] content$iv$iv = this_$iv$iv.getContent();
                    do {
                        ObservedScopeMap scopeMap = (ObservedScopeMap) content$iv$iv[i$iv$iv];
                        if (!scopeMap.recordInvalidation(notifications) && !hasValues) {
                            z2 = false;
                            hasValues = z2;
                            i$iv$iv++;
                        }
                        z2 = true;
                        hasValues = z2;
                        i$iv$iv++;
                    } while (i$iv$iv < size$iv$iv);
                    Unit unit = Unit.INSTANCE;
                } else {
                    Unit unit2 = Unit.INSTANCE;
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void sendNotifications() {
        this.onChangedExecutor.invoke(new Function0<Unit>() { // from class: androidx.compose.runtime.snapshots.SnapshotStateObserver$sendNotifications$1
            /* JADX INFO: Access modifiers changed from: package-private */
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke  reason: avoid collision after fix types in other method */
            public final void invoke2() {
                MutableVector mutableVector;
                boolean z;
                boolean drainChanges;
                MutableVector this_$iv;
                do {
                    mutableVector = SnapshotStateObserver.this.observedScopeMaps;
                    SnapshotStateObserver snapshotStateObserver = SnapshotStateObserver.this;
                    synchronized (mutableVector) {
                        z = snapshotStateObserver.sendingNotifications;
                        if (!z) {
                            snapshotStateObserver.sendingNotifications = true;
                            this_$iv = snapshotStateObserver.observedScopeMaps;
                            int size$iv = this_$iv.getSize();
                            if (size$iv <= 0) {
                                snapshotStateObserver.sendingNotifications = false;
                            } else {
                                int i$iv = 0;
                                Object[] content$iv = this_$iv.getContent();
                                do {
                                    SnapshotStateObserver.ObservedScopeMap scopeMap = (SnapshotStateObserver.ObservedScopeMap) content$iv[i$iv];
                                    scopeMap.notifyInvalidatedScopes();
                                    i$iv++;
                                } while (i$iv < size$iv);
                                snapshotStateObserver.sendingNotifications = false;
                            }
                        }
                        Unit unit = Unit.INSTANCE;
                    }
                    drainChanges = SnapshotStateObserver.this.drainChanges();
                } while (drainChanges);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void addChanges(Set<? extends Object> set) {
        Object old;
        Collection plus;
        do {
            old = this.pendingChanges.get();
            if (old == null) {
                plus = set;
            } else if (old instanceof Set) {
                plus = CollectionsKt.listOf((Object[]) new Set[]{(Set) old, set});
            } else if (!(old instanceof List)) {
                report();
                throw new KotlinNothingValueException();
            } else {
                plus = CollectionsKt.plus((Collection) old, (Iterable) CollectionsKt.listOf(set));
            }
        } while (!MutatorMutex$$ExternalSyntheticBackportWithForwarding0.m(this.pendingChanges, old, plus));
    }

    private final Set<Object> removeChanges() {
        Object old;
        Set result;
        Object obj;
        do {
            old = this.pendingChanges.get();
            Object obj2 = null;
            if (old == null) {
                return null;
            }
            if (old instanceof Set) {
                result = (Set) old;
                obj = null;
            } else if (old instanceof List) {
                result = (Set) ((List) old).get(0);
                if (((List) old).size() == 2) {
                    obj2 = ((List) old).get(1);
                } else if (((List) old).size() > 2) {
                    obj2 = ((List) old).subList(1, ((List) old).size());
                }
                obj = obj2;
            } else {
                report();
                throw new KotlinNothingValueException();
            }
        } while (!MutatorMutex$$ExternalSyntheticBackportWithForwarding0.m(this.pendingChanges, old, obj));
        return result;
    }

    private final Void report() {
        ComposerKt.composeRuntimeError("Unexpected notification");
        throw new KotlinNothingValueException();
    }

    private final void forEachScopeMap(Function1<? super ObservedScopeMap, Unit> function1) {
        synchronized (this.observedScopeMaps) {
            try {
                MutableVector this_$iv = this.observedScopeMaps;
                int size$iv = this_$iv.getSize();
                if (size$iv <= 0) {
                    Unit unit = Unit.INSTANCE;
                    InlineMarker.finallyStart(1);
                } else {
                    int i$iv = 0;
                    Object[] content$iv = this_$iv.getContent();
                    do {
                        function1.invoke(content$iv[i$iv]);
                        i$iv++;
                    } while (i$iv < size$iv);
                    Unit unit2 = Unit.INSTANCE;
                    InlineMarker.finallyStart(1);
                }
            } catch (Throwable th) {
                InlineMarker.finallyStart(1);
                InlineMarker.finallyEnd(1);
                throw th;
            }
        }
        InlineMarker.finallyEnd(1);
    }

    public final <T> void observeReads(T scope, Function1<? super T, Unit> onValueChangedForScope, final Function0<Unit> block) {
        ObservedScopeMap scopeMap;
        Intrinsics.checkNotNullParameter(scope, "scope");
        Intrinsics.checkNotNullParameter(onValueChangedForScope, "onValueChangedForScope");
        Intrinsics.checkNotNullParameter(block, "block");
        synchronized (this.observedScopeMaps) {
            scopeMap = ensureMap(onValueChangedForScope);
        }
        boolean oldPaused = this.isPaused;
        ObservedScopeMap oldMap = this.currentMap;
        try {
            this.isPaused = false;
            this.currentMap = scopeMap;
            Object previousScope$iv = scopeMap.currentScope;
            IdentityArrayIntMap previousReads$iv = scopeMap.currentScopeReads;
            int previousToken$iv = scopeMap.currentToken;
            scopeMap.currentScope = scope;
            scopeMap.currentScopeReads = (IdentityArrayIntMap) scopeMap.scopeToValues.get(scope);
            if (scopeMap.currentToken == -1) {
                scopeMap.currentToken = SnapshotKt.currentSnapshot().getId();
            }
            SnapshotStateKt.observeDerivedStateRecalculations(scopeMap.getDerivedStateEnterObserver(), scopeMap.getDerivedStateExitObserver(), new Function0<Unit>() { // from class: androidx.compose.runtime.snapshots.SnapshotStateObserver$observeReads$1$1
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2() {
                    Function1<Object, Unit> function1;
                    Snapshot.Companion companion = Snapshot.Companion;
                    function1 = SnapshotStateObserver.this.readObserver;
                    companion.observe(function1, null, block);
                }
            });
            Object obj = scopeMap.currentScope;
            Intrinsics.checkNotNull(obj);
            scopeMap.clearObsoleteStateReads(obj);
            scopeMap.currentScope = previousScope$iv;
            scopeMap.currentScopeReads = previousReads$iv;
            scopeMap.currentToken = previousToken$iv;
        } finally {
            this.currentMap = oldMap;
            this.isPaused = oldPaused;
        }
    }

    @Deprecated(message = "Replace with Snapshot.withoutReadObservation()", replaceWith = @ReplaceWith(expression = "Snapshot.withoutReadObservation(block)", imports = {"androidx.compose.runtime.snapshots.Snapshot"}))
    public final void withNoObservations(Function0<Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        boolean oldPaused = this.isPaused;
        this.isPaused = true;
        try {
            block.invoke();
        } finally {
            this.isPaused = oldPaused;
        }
    }

    public final void clear(Object scope) {
        Intrinsics.checkNotNullParameter(scope, "scope");
        synchronized (this.observedScopeMaps) {
            MutableVector this_$iv$iv = this.observedScopeMaps;
            int size$iv$iv = this_$iv$iv.getSize();
            if (size$iv$iv > 0) {
                int i$iv$iv = 0;
                Object[] content$iv$iv = this_$iv$iv.getContent();
                do {
                    ObservedScopeMap it = (ObservedScopeMap) content$iv$iv[i$iv$iv];
                    it.clearScopeObservations(scope);
                    i$iv$iv++;
                } while (i$iv$iv < size$iv$iv);
                Unit unit = Unit.INSTANCE;
            } else {
                Unit unit2 = Unit.INSTANCE;
            }
        }
    }

    public final void clearIf(Function1<Object, Boolean> predicate) {
        Intrinsics.checkNotNullParameter(predicate, "predicate");
        synchronized (this.observedScopeMaps) {
            MutableVector this_$iv$iv = this.observedScopeMaps;
            int size$iv$iv = this_$iv$iv.getSize();
            if (size$iv$iv > 0) {
                int i$iv$iv = 0;
                Object[] content$iv$iv = this_$iv$iv.getContent();
                do {
                    ObservedScopeMap scopeMap = (ObservedScopeMap) content$iv$iv[i$iv$iv];
                    scopeMap.removeScopeIf(predicate);
                    i$iv$iv++;
                } while (i$iv$iv < size$iv$iv);
                Unit unit = Unit.INSTANCE;
            } else {
                Unit unit2 = Unit.INSTANCE;
            }
        }
    }

    public final void start() {
        this.applyUnsubscribe = Snapshot.Companion.registerApplyObserver(this.applyObserver);
    }

    public final void stop() {
        ObserverHandle observerHandle = this.applyUnsubscribe;
        if (observerHandle != null) {
            observerHandle.dispose();
        }
    }

    public final void notifyChanges(Set<? extends Object> changes, Snapshot snapshot) {
        Intrinsics.checkNotNullParameter(changes, "changes");
        Intrinsics.checkNotNullParameter(snapshot, "snapshot");
        this.applyObserver.invoke(changes, snapshot);
    }

    public final void clear() {
        synchronized (this.observedScopeMaps) {
            MutableVector this_$iv$iv = this.observedScopeMaps;
            int size$iv$iv = this_$iv$iv.getSize();
            if (size$iv$iv > 0) {
                int i$iv$iv = 0;
                Object[] content$iv$iv = this_$iv$iv.getContent();
                do {
                    ObservedScopeMap scopeMap = (ObservedScopeMap) content$iv$iv[i$iv$iv];
                    scopeMap.clear();
                    i$iv$iv++;
                } while (i$iv$iv < size$iv$iv);
                Unit unit = Unit.INSTANCE;
            } else {
                Unit unit2 = Unit.INSTANCE;
            }
        }
    }

    private final <T> ObservedScopeMap ensureMap(Function1<? super T, Unit> function1) {
        ObservedScopeMap observedScopeMap;
        MutableVector this_$iv = this.observedScopeMaps;
        int size$iv = this_$iv.getSize();
        if (size$iv > 0) {
            int i$iv = 0;
            ObservedScopeMap[] content = this_$iv.getContent();
            do {
                observedScopeMap = content[i$iv];
                ObservedScopeMap it = observedScopeMap;
                if (it.getOnChanged() == function1) {
                    break;
                }
                i$iv++;
            } while (i$iv < size$iv);
            observedScopeMap = null;
        } else {
            observedScopeMap = null;
        }
        ObservedScopeMap scopeMap = observedScopeMap;
        if (scopeMap == null) {
            Intrinsics.checkNotNull(function1, "null cannot be cast to non-null type kotlin.Function1<kotlin.Any, kotlin.Unit>");
            ObservedScopeMap map = new ObservedScopeMap((Function1) TypeIntrinsics.beforeCheckcastToFunctionOfArity(function1, 1));
            this.observedScopeMaps.add(map);
            return map;
        }
        return scopeMap;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* compiled from: SnapshotStateObserver.kt */
    @Metadata(d1 = {"\u0000l\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\"\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0002\u0018\u00002\u00020\u0001B\u0019\u0012\u0012\u0010\u0002\u001a\u000e\u0012\u0004\u0012\u00020\u0001\u0012\u0004\u0012\u00020\u00040\u0003¢\u0006\u0002\u0010\u0005J\u0006\u0010\u001e\u001a\u00020\u0004J\u0010\u0010\u001f\u001a\u00020\u00042\u0006\u0010 \u001a\u00020\u0001H\u0002J\u000e\u0010!\u001a\u00020\u00042\u0006\u0010 \u001a\u00020\u0001J\u0006\u0010\"\u001a\u00020\u0004J\"\u0010#\u001a\u00020\u00042\u0006\u0010 \u001a\u00020\u00012\f\u0010$\u001a\b\u0012\u0004\u0012\u00020\u00040%H\u0086\bø\u0001\u0000J\u0014\u0010&\u001a\u00020'2\f\u0010(\u001a\b\u0012\u0004\u0012\u00020\u00010)J\u000e\u0010*\u001a\u00020\u00042\u0006\u0010+\u001a\u00020\u0001J\u0018\u0010,\u001a\u00020\u00042\u0006\u0010 \u001a\u00020\u00012\u0006\u0010+\u001a\u00020\u0001H\u0002J)\u0010-\u001a\u00020\u00042!\u0010.\u001a\u001d\u0012\u0013\u0012\u00110\u0001¢\u0006\f\b/\u0012\b\b0\u0012\u0004\b\b( \u0012\u0004\u0012\u00020'0\u0003R\u0010\u0010\u0006\u001a\u0004\u0018\u00010\u0001X\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\u0007\u001a\u0004\u0018\u00010\bX\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\nX\u0082\u000e¢\u0006\u0002\n\u0000R\u0018\u0010\u000b\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\r0\fX\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u000e\u001a\u00020\nX\u0082\u000e¢\u0006\u0002\n\u0000R!\u0010\u000f\u001a\u0012\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u0010\u0012\u0004\u0012\u00020\u00040\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0011\u0010\u0012R!\u0010\u0013\u001a\u0012\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u0010\u0012\u0004\u0012\u00020\u00040\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0014\u0010\u0012R\u0014\u0010\u0015\u001a\b\u0012\u0004\u0012\u00020\u00010\u0016X\u0082\u0004¢\u0006\u0002\n\u0000R\u001d\u0010\u0002\u001a\u000e\u0012\u0004\u0012\u00020\u0001\u0012\u0004\u0012\u00020\u00040\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0017\u0010\u0012R6\u0010\u0018\u001a*\u0012\b\u0012\u0006\u0012\u0002\b\u00030\r\u0012\u0006\u0012\u0004\u0018\u00010\u00010\u0019j\u0014\u0012\b\u0012\u0006\u0012\u0002\b\u00030\r\u0012\u0006\u0012\u0004\u0018\u00010\u0001`\u001aX\u0082\u0004¢\u0006\u0002\n\u0000R\u001a\u0010\u001b\u001a\u000e\u0012\u0004\u0012\u00020\u0001\u0012\u0004\u0012\u00020\b0\u001cX\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010\u001d\u001a\b\u0012\u0004\u0012\u00020\u00010\fX\u0082\u0004¢\u0006\u0002\n\u0000\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u00061"}, d2 = {"Landroidx/compose/runtime/snapshots/SnapshotStateObserver$ObservedScopeMap;", "", "onChanged", "Lkotlin/Function1;", "", "(Lkotlin/jvm/functions/Function1;)V", "currentScope", "currentScopeReads", "Landroidx/compose/runtime/collection/IdentityArrayIntMap;", "currentToken", "", "dependencyToDerivedStates", "Landroidx/compose/runtime/collection/IdentityScopeMap;", "Landroidx/compose/runtime/DerivedState;", "deriveStateScopeCount", "derivedStateEnterObserver", "Landroidx/compose/runtime/State;", "getDerivedStateEnterObserver", "()Lkotlin/jvm/functions/Function1;", "derivedStateExitObserver", "getDerivedStateExitObserver", "invalidated", "Landroidx/compose/runtime/collection/IdentityArraySet;", "getOnChanged", "recordedDerivedStateValues", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "scopeToValues", "Landroidx/compose/runtime/collection/IdentityArrayMap;", "valueToScopes", "clear", "clearObsoleteStateReads", "scope", "clearScopeObservations", "notifyInvalidatedScopes", "observe", "block", "Lkotlin/Function0;", "recordInvalidation", "", "changes", "", "recordRead", "value", "removeObservation", "removeScopeIf", "predicate", "Lkotlin/ParameterName;", HintConstants.AUTOFILL_HINT_NAME, "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class ObservedScopeMap {
        private Object currentScope;
        private IdentityArrayIntMap currentScopeReads;
        private int currentToken;
        private final IdentityScopeMap<DerivedState<?>> dependencyToDerivedStates;
        private int deriveStateScopeCount;
        private final Function1<State<?>, Unit> derivedStateEnterObserver;
        private final Function1<State<?>, Unit> derivedStateExitObserver;
        private final IdentityArraySet<Object> invalidated;
        private final Function1<Object, Unit> onChanged;
        private final HashMap<DerivedState<?>, Object> recordedDerivedStateValues;
        private final IdentityArrayMap<Object, IdentityArrayIntMap> scopeToValues;
        private final IdentityScopeMap<Object> valueToScopes;

        public ObservedScopeMap(Function1<Object, Unit> onChanged) {
            Intrinsics.checkNotNullParameter(onChanged, "onChanged");
            this.onChanged = onChanged;
            this.currentToken = -1;
            this.valueToScopes = new IdentityScopeMap<>();
            this.scopeToValues = new IdentityArrayMap<>(0, 1, null);
            this.invalidated = new IdentityArraySet<>();
            this.derivedStateEnterObserver = new Function1<State<?>, Unit>() { // from class: androidx.compose.runtime.snapshots.SnapshotStateObserver$ObservedScopeMap$derivedStateEnterObserver$1
                /* JADX INFO: Access modifiers changed from: package-private */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(State<?> state) {
                    invoke2(state);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2(State<?> it) {
                    int i;
                    Intrinsics.checkNotNullParameter(it, "it");
                    SnapshotStateObserver.ObservedScopeMap observedScopeMap = SnapshotStateObserver.ObservedScopeMap.this;
                    i = observedScopeMap.deriveStateScopeCount;
                    observedScopeMap.deriveStateScopeCount = i + 1;
                }
            };
            this.derivedStateExitObserver = new Function1<State<?>, Unit>() { // from class: androidx.compose.runtime.snapshots.SnapshotStateObserver$ObservedScopeMap$derivedStateExitObserver$1
                /* JADX INFO: Access modifiers changed from: package-private */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(State<?> state) {
                    invoke2(state);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2(State<?> it) {
                    int i;
                    Intrinsics.checkNotNullParameter(it, "it");
                    SnapshotStateObserver.ObservedScopeMap observedScopeMap = SnapshotStateObserver.ObservedScopeMap.this;
                    i = observedScopeMap.deriveStateScopeCount;
                    observedScopeMap.deriveStateScopeCount = i - 1;
                }
            };
            this.dependencyToDerivedStates = new IdentityScopeMap<>();
            this.recordedDerivedStateValues = new HashMap<>();
        }

        public final Function1<Object, Unit> getOnChanged() {
            return this.onChanged;
        }

        public final Function1<State<?>, Unit> getDerivedStateEnterObserver() {
            return this.derivedStateEnterObserver;
        }

        public final Function1<State<?>, Unit> getDerivedStateExitObserver() {
            return this.derivedStateExitObserver;
        }

        public final void recordRead(Object value) {
            Intrinsics.checkNotNullParameter(value, "value");
            if (this.deriveStateScopeCount > 0) {
                return;
            }
            Object scope = this.currentScope;
            Intrinsics.checkNotNull(scope);
            IdentityArrayIntMap it = this.currentScopeReads;
            if (it == null) {
                it = new IdentityArrayIntMap();
                this.currentScopeReads = it;
                this.scopeToValues.set(scope, it);
            }
            int previousValue = it.add(value, this.currentToken);
            if ((value instanceof DerivedState) && previousValue != this.currentToken) {
                Object[] dependencies = ((DerivedState) value).getDependencies();
                for (Object dependency : dependencies) {
                    if (dependency == null) {
                        break;
                    }
                    this.dependencyToDerivedStates.add(dependency, value);
                }
                this.recordedDerivedStateValues.put(value, ((DerivedState) value).getCurrentValue());
            }
            if (previousValue == -1) {
                this.valueToScopes.add(value, scope);
            }
        }

        public final void observe(Object scope, Function0<Unit> block) {
            Intrinsics.checkNotNullParameter(scope, "scope");
            Intrinsics.checkNotNullParameter(block, "block");
            Object previousScope = this.currentScope;
            IdentityArrayIntMap previousReads = this.currentScopeReads;
            int previousToken = this.currentToken;
            this.currentScope = scope;
            this.currentScopeReads = (IdentityArrayIntMap) this.scopeToValues.get(scope);
            if (this.currentToken == -1) {
                this.currentToken = SnapshotKt.currentSnapshot().getId();
            }
            block.invoke();
            Object obj = this.currentScope;
            Intrinsics.checkNotNull(obj);
            clearObsoleteStateReads(obj);
            this.currentScope = previousScope;
            this.currentScopeReads = previousReads;
            this.currentToken = previousToken;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final void clearObsoleteStateReads(Object scope) {
            IdentityArrayIntMap this_$iv = this.currentScopeReads;
            if (this_$iv == null) {
                return;
            }
            int destinationIndex$iv = 0;
            int size = this_$iv.getSize();
            for (int i$iv = 0; i$iv < size; i$iv++) {
                Object key$iv = this_$iv.getKeys()[i$iv];
                Intrinsics.checkNotNull(key$iv, "null cannot be cast to non-null type kotlin.Any");
                int value$iv = this_$iv.getValues()[i$iv];
                boolean z = value$iv != this.currentToken;
                boolean willRemove = z;
                if (willRemove) {
                    removeObservation(scope, key$iv);
                }
                if (!z) {
                    if (destinationIndex$iv != i$iv) {
                        this_$iv.getKeys()[destinationIndex$iv] = key$iv;
                        this_$iv.getValues()[destinationIndex$iv] = value$iv;
                    }
                    destinationIndex$iv++;
                }
            }
            int size2 = this_$iv.getSize();
            for (int i$iv2 = destinationIndex$iv; i$iv2 < size2; i$iv2++) {
                this_$iv.getKeys()[i$iv2] = null;
            }
            this_$iv.setSize(destinationIndex$iv);
        }

        public final void clearScopeObservations(Object scope) {
            Intrinsics.checkNotNullParameter(scope, "scope");
            IdentityArrayIntMap recordedValues = this.scopeToValues.remove(scope);
            if (recordedValues == null) {
                return;
            }
            int size = recordedValues.getSize();
            for (int i$iv = 0; i$iv < size; i$iv++) {
                Object value = recordedValues.getKeys()[i$iv];
                Intrinsics.checkNotNull(value, "null cannot be cast to non-null type kotlin.Any");
                int i = recordedValues.getValues()[i$iv];
                removeObservation(scope, value);
            }
        }

        public final void removeScopeIf(Function1<Object, Boolean> function1) {
            boolean z;
            int i;
            Function1<Object, Boolean> predicate = function1;
            Intrinsics.checkNotNullParameter(predicate, "predicate");
            IdentityArrayMap this_$iv = this.scopeToValues;
            boolean z2 = false;
            int current$iv = 0;
            int index$iv = 0;
            int size$runtime_release = this_$iv.getSize$runtime_release();
            while (index$iv < size$runtime_release) {
                Object key$iv = this_$iv.getKeys$runtime_release()[index$iv];
                Intrinsics.checkNotNull(key$iv, "null cannot be cast to non-null type Key of androidx.compose.runtime.collection.IdentityArrayMap");
                Object value$iv = this_$iv.getValues$runtime_release()[index$iv];
                IdentityArrayIntMap valueSet = (IdentityArrayIntMap) value$iv;
                Boolean invoke = predicate.invoke(key$iv);
                boolean willRemove = invoke.booleanValue();
                if (!willRemove) {
                    z = z2;
                    i = size$runtime_release;
                } else {
                    int size = valueSet.getSize();
                    z = z2;
                    int $i$f$removeIf = 0;
                    while ($i$f$removeIf < size) {
                        int i2 = size;
                        Object value = valueSet.getKeys()[$i$f$removeIf];
                        int i3 = size$runtime_release;
                        Intrinsics.checkNotNull(value, "null cannot be cast to non-null type kotlin.Any");
                        int i4 = valueSet.getValues()[$i$f$removeIf];
                        removeObservation(key$iv, value);
                        $i$f$removeIf++;
                        size$runtime_release = i3;
                        size = i2;
                    }
                    i = size$runtime_release;
                }
                if (!invoke.booleanValue()) {
                    if (current$iv != index$iv) {
                        this_$iv.getKeys$runtime_release()[current$iv] = key$iv;
                        this_$iv.getValues$runtime_release()[current$iv] = this_$iv.getValues$runtime_release()[index$iv];
                    }
                    current$iv++;
                }
                index$iv++;
                predicate = function1;
                size$runtime_release = i;
                z2 = z;
            }
            if (this_$iv.getSize$runtime_release() <= current$iv) {
                return;
            }
            int size$runtime_release2 = this_$iv.getSize$runtime_release();
            for (int index$iv2 = current$iv; index$iv2 < size$runtime_release2; index$iv2++) {
                this_$iv.getKeys$runtime_release()[index$iv2] = null;
                this_$iv.getValues$runtime_release()[index$iv2] = null;
            }
            this_$iv.setSize$runtime_release(current$iv);
        }

        private final void removeObservation(Object scope, Object value) {
            this.valueToScopes.remove(value, scope);
            if ((value instanceof DerivedState) && !this.valueToScopes.contains(value)) {
                this.dependencyToDerivedStates.removeScope(value);
                this.recordedDerivedStateValues.remove(value);
            }
        }

        public final void clear() {
            this.valueToScopes.clear();
            this.scopeToValues.clear();
            this.dependencyToDerivedStates.clear();
            this.recordedDerivedStateValues.clear();
        }

        public final boolean recordInvalidation(Set<? extends Object> changes) {
            Iterator<? extends Object> it;
            Iterator<? extends Object> it2;
            Intrinsics.checkNotNullParameter(changes, "changes");
            boolean hasValues = false;
            Iterator<? extends Object> it3 = changes.iterator();
            while (it3.hasNext()) {
                Object value = it3.next();
                if (!this.dependencyToDerivedStates.contains(value)) {
                    it = it3;
                } else {
                    IdentityScopeMap this_$iv = this.dependencyToDerivedStates;
                    int index$iv = IdentityScopeMap.access$find(this_$iv, value);
                    if (index$iv < 0) {
                        it = it3;
                    } else {
                        IdentityArraySet this_$iv$iv = IdentityScopeMap.access$scopeSetAt(this_$iv, index$iv);
                        int i$iv$iv = 0;
                        int size = this_$iv$iv.size();
                        while (i$iv$iv < size) {
                            DerivedState derivedState = (DerivedState) this_$iv$iv.get(i$iv$iv);
                            Intrinsics.checkNotNull(derivedState, "null cannot be cast to non-null type androidx.compose.runtime.DerivedState<kotlin.Any?>");
                            Object previousValue = this.recordedDerivedStateValues.get(derivedState);
                            SnapshotMutationPolicy policy = derivedState.getPolicy();
                            if (policy == null) {
                                policy = SnapshotStateKt.structuralEqualityPolicy();
                            }
                            boolean hasValues2 = hasValues;
                            if (policy.equivalent(derivedState.getCurrentValue(), previousValue)) {
                                it2 = it3;
                            } else {
                                IdentityScopeMap this_$iv2 = this.valueToScopes;
                                int index$iv2 = IdentityScopeMap.access$find(this_$iv2, derivedState);
                                if (index$iv2 >= 0) {
                                    it2 = it3;
                                    IdentityArraySet this_$iv$iv2 = IdentityScopeMap.access$scopeSetAt(this_$iv2, index$iv2);
                                    int size2 = this_$iv$iv2.size();
                                    int index$iv3 = 0;
                                    while (index$iv3 < size2) {
                                        int i = size2;
                                        Object scope = this_$iv$iv2.get(index$iv3);
                                        this.invalidated.add(scope);
                                        hasValues2 = true;
                                        index$iv3++;
                                        size2 = i;
                                        this_$iv$iv2 = this_$iv$iv2;
                                    }
                                } else {
                                    it2 = it3;
                                }
                            }
                            hasValues = hasValues2;
                            i$iv$iv++;
                            it3 = it2;
                        }
                        it = it3;
                    }
                }
                IdentityScopeMap this_$iv3 = this.valueToScopes;
                int index$iv4 = IdentityScopeMap.access$find(this_$iv3, value);
                if (index$iv4 >= 0) {
                    IdentityArraySet this_$iv$iv3 = IdentityScopeMap.access$scopeSetAt(this_$iv3, index$iv4);
                    int size3 = this_$iv$iv3.size();
                    for (int i$iv$iv2 = 0; i$iv$iv2 < size3; i$iv$iv2++) {
                        Object scope2 = this_$iv$iv3.get(i$iv$iv2);
                        this.invalidated.add(scope2);
                        hasValues = true;
                    }
                }
                it3 = it;
            }
            return hasValues;
        }

        public final void notifyInvalidatedScopes() {
            IdentityArraySet this_$iv = this.invalidated;
            Function1 block$iv = this.onChanged;
            int size = this_$iv.size();
            for (int i$iv = 0; i$iv < size; i$iv++) {
                block$iv.invoke(this_$iv.get(i$iv));
            }
            this.invalidated.clear();
        }
    }
}
