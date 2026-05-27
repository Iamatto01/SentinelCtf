package androidx.compose.runtime;

import androidx.compose.runtime.Recomposer;
import androidx.compose.runtime.snapshots.ObserverHandle;
import androidx.compose.runtime.snapshots.Snapshot;
import java.util.List;
import java.util.Set;
import kotlin.Metadata;
import kotlin.Result;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.CancellableContinuation;
import kotlinx.coroutines.CoroutineScope;
import kotlinx.coroutines.CoroutineScopeKt;
import kotlinx.coroutines.Job;
import kotlinx.coroutines.JobKt;
import kotlinx.coroutines.flow.MutableStateFlow;
/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: Recomposer.kt */
@Metadata(d1 = {"\u0000\n\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u008a@"}, d2 = {"<anonymous>", "", "Lkotlinx/coroutines/CoroutineScope;"}, k = 3, mv = {1, 8, 0}, xi = 48)
@DebugMetadata(c = "androidx.compose.runtime.Recomposer$recompositionRunner$2", f = "Recomposer.kt", i = {0, 0}, l = {898}, m = "invokeSuspend", n = {"callingJob", "unregisterApplyObserver"}, s = {"L$0", "L$1"})
/* loaded from: classes.dex */
public final class Recomposer$recompositionRunner$2 extends SuspendLambda implements Function2<CoroutineScope, Continuation<? super Unit>, Object> {
    final /* synthetic */ Function3<CoroutineScope, MonotonicFrameClock, Continuation<? super Unit>, Object> $block;
    final /* synthetic */ MonotonicFrameClock $parentFrameClock;
    private /* synthetic */ Object L$0;
    Object L$1;
    int label;
    final /* synthetic */ Recomposer this$0;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public Recomposer$recompositionRunner$2(Recomposer recomposer, Function3<? super CoroutineScope, ? super MonotonicFrameClock, ? super Continuation<? super Unit>, ? extends Object> function3, MonotonicFrameClock monotonicFrameClock, Continuation<? super Recomposer$recompositionRunner$2> continuation) {
        super(2, continuation);
        this.this$0 = recomposer;
        this.$block = function3;
        this.$parentFrameClock = monotonicFrameClock;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
        Recomposer$recompositionRunner$2 recomposer$recompositionRunner$2 = new Recomposer$recompositionRunner$2(this.this$0, this.$block, this.$parentFrameClock, continuation);
        recomposer$recompositionRunner$2.L$0 = obj;
        return recomposer$recompositionRunner$2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(CoroutineScope coroutineScope, Continuation<? super Unit> continuation) {
        return ((Recomposer$recompositionRunner$2) create(coroutineScope, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    /* JADX WARN: Not initialized variable reg: 4, insn: 0x00d3: INVOKE  
      (r4 I:androidx.compose.runtime.snapshots.ObserverHandle A[D('unregisterApplyObserver' androidx.compose.runtime.snapshots.ObserverHandle)])
     type: INTERFACE call: androidx.compose.runtime.snapshots.ObserverHandle.dispose():void, block:B:38:0x00d3 */
    /* JADX WARN: Not initialized variable reg: 5, insn: 0x00e5: IF  (r9v0 ?? I:??[int, boolean, OBJECT, ARRAY, byte, short, char]) != (r5 I:??[int, boolean, OBJECT, ARRAY, byte, short, char] A[D('callingJob' kotlinx.coroutines.Job)])  -> B:44:0x00ea, block:B:42:0x00e5 */
    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Object invokeSuspend(Object $result) {
        ObserverHandle unregisterApplyObserver;
        Job job;
        Job callingJob;
        Recomposer.RecomposerInfoImpl recomposerInfoImpl;
        Recomposer$recompositionRunner$2 recomposer$recompositionRunner$2;
        Job callingJob2;
        ObserverHandle unregisterApplyObserver2;
        Recomposer.RecomposerInfoImpl recomposerInfoImpl2;
        Job job2;
        Recomposer.RecomposerInfoImpl recomposerInfoImpl3;
        Object coroutine_suspended = IntrinsicsKt.getCOROUTINE_SUSPENDED();
        try {
            switch (this.label) {
                case 0:
                    ResultKt.throwOnFailure($result);
                    recomposer$recompositionRunner$2 = this;
                    CoroutineScope $this$withContext = (CoroutineScope) recomposer$recompositionRunner$2.L$0;
                    callingJob2 = JobKt.getJob($this$withContext.getCoroutineContext());
                    recomposer$recompositionRunner$2.this$0.registerRunnerJob(callingJob2);
                    Snapshot.Companion companion = Snapshot.Companion;
                    final Recomposer recomposer = recomposer$recompositionRunner$2.this$0;
                    unregisterApplyObserver2 = companion.registerApplyObserver(new Function2<Set<? extends Object>, Snapshot, Unit>() { // from class: androidx.compose.runtime.Recomposer$recompositionRunner$2$unregisterApplyObserver$1
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
                        public final void invoke2(Set<? extends Object> changed, Snapshot snapshot) {
                            MutableStateFlow mutableStateFlow;
                            CancellableContinuation cancellableContinuation;
                            Intrinsics.checkNotNullParameter(changed, "changed");
                            Intrinsics.checkNotNullParameter(snapshot, "<anonymous parameter 1>");
                            Object lock$iv = Recomposer.this.stateLock;
                            Recomposer recomposer2 = Recomposer.this;
                            synchronized (lock$iv) {
                                mutableStateFlow = recomposer2._state;
                                if (((Recomposer.State) mutableStateFlow.getValue()).compareTo(Recomposer.State.Idle) >= 0) {
                                    recomposer2.snapshotInvalidations.addAll(changed);
                                    cancellableContinuation = recomposer2.deriveStateLocked();
                                } else {
                                    cancellableContinuation = null;
                                }
                            }
                            if (cancellableContinuation != null) {
                                Result.Companion companion2 = Result.Companion;
                                cancellableContinuation.resumeWith(Result.m5433constructorimpl(Unit.INSTANCE));
                            }
                        }
                    });
                    Recomposer.Companion companion2 = Recomposer.Companion;
                    recomposerInfoImpl2 = recomposer$recompositionRunner$2.this$0.recomposerInfo;
                    companion2.addRunning(recomposerInfoImpl2);
                    Object lock$iv = recomposer$recompositionRunner$2.this$0.stateLock;
                    Recomposer recomposer2 = recomposer$recompositionRunner$2.this$0;
                    synchronized (lock$iv) {
                        List $this$fastForEach$iv = recomposer2.knownCompositions;
                        int size = $this$fastForEach$iv.size();
                        for (int index$iv = 0; index$iv < size; index$iv++) {
                            Object item$iv = $this$fastForEach$iv.get(index$iv);
                            ControlledComposition it = (ControlledComposition) item$iv;
                            it.invalidateAll();
                        }
                        Unit unit = Unit.INSTANCE;
                    }
                    recomposer$recompositionRunner$2.L$0 = callingJob2;
                    recomposer$recompositionRunner$2.L$1 = unregisterApplyObserver2;
                    recomposer$recompositionRunner$2.label = 1;
                    if (CoroutineScopeKt.coroutineScope(new AnonymousClass2(recomposer$recompositionRunner$2.$block, recomposer$recompositionRunner$2.$parentFrameClock, null), recomposer$recompositionRunner$2) == coroutine_suspended) {
                        return coroutine_suspended;
                    }
                    break;
                case 1:
                    recomposer$recompositionRunner$2 = this;
                    unregisterApplyObserver2 = (ObserverHandle) recomposer$recompositionRunner$2.L$1;
                    callingJob2 = (Job) recomposer$recompositionRunner$2.L$0;
                    ResultKt.throwOnFailure($result);
                    break;
                default:
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            unregisterApplyObserver2.dispose();
            Object lock$iv2 = recomposer$recompositionRunner$2.this$0.stateLock;
            Recomposer recomposer3 = recomposer$recompositionRunner$2.this$0;
            synchronized (lock$iv2) {
                job2 = recomposer3.runnerJob;
                if (job2 == callingJob2) {
                    recomposer3.runnerJob = null;
                }
                recomposer3.deriveStateLocked();
            }
            Recomposer.Companion companion3 = Recomposer.Companion;
            recomposerInfoImpl3 = recomposer$recompositionRunner$2.this$0.recomposerInfo;
            companion3.removeRunning(recomposerInfoImpl3);
            return Unit.INSTANCE;
        } catch (Throwable th) {
            unregisterApplyObserver.dispose();
            Object lock$iv3 = this.this$0.stateLock;
            Recomposer recomposer4 = this.this$0;
            synchronized (lock$iv3) {
                job = recomposer4.runnerJob;
                if (job == callingJob) {
                    recomposer4.runnerJob = null;
                }
                recomposer4.deriveStateLocked();
                Recomposer.Companion companion4 = Recomposer.Companion;
                recomposerInfoImpl = this.this$0.recomposerInfo;
                companion4.removeRunning(recomposerInfoImpl);
                throw th;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* compiled from: Recomposer.kt */
    @Metadata(d1 = {"\u0000\n\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u008a@"}, d2 = {"<anonymous>", "", "Lkotlinx/coroutines/CoroutineScope;"}, k = 3, mv = {1, 8, 0}, xi = 48)
    @DebugMetadata(c = "androidx.compose.runtime.Recomposer$recompositionRunner$2$2", f = "Recomposer.kt", i = {}, l = {899}, m = "invokeSuspend", n = {}, s = {})
    /* renamed from: androidx.compose.runtime.Recomposer$recompositionRunner$2$2  reason: invalid class name */
    /* loaded from: classes.dex */
    public static final class AnonymousClass2 extends SuspendLambda implements Function2<CoroutineScope, Continuation<? super Unit>, Object> {
        final /* synthetic */ Function3<CoroutineScope, MonotonicFrameClock, Continuation<? super Unit>, Object> $block;
        final /* synthetic */ MonotonicFrameClock $parentFrameClock;
        private /* synthetic */ Object L$0;
        int label;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        AnonymousClass2(Function3<? super CoroutineScope, ? super MonotonicFrameClock, ? super Continuation<? super Unit>, ? extends Object> function3, MonotonicFrameClock monotonicFrameClock, Continuation<? super AnonymousClass2> continuation) {
            super(2, continuation);
            this.$block = function3;
            this.$parentFrameClock = monotonicFrameClock;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
            AnonymousClass2 anonymousClass2 = new AnonymousClass2(this.$block, this.$parentFrameClock, continuation);
            anonymousClass2.L$0 = obj;
            return anonymousClass2;
        }

        @Override // kotlin.jvm.functions.Function2
        public final Object invoke(CoroutineScope coroutineScope, Continuation<? super Unit> continuation) {
            return ((AnonymousClass2) create(coroutineScope, continuation)).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        public final Object invokeSuspend(Object $result) {
            Object coroutine_suspended = IntrinsicsKt.getCOROUTINE_SUSPENDED();
            switch (this.label) {
                case 0:
                    ResultKt.throwOnFailure($result);
                    CoroutineScope $this$coroutineScope = (CoroutineScope) this.L$0;
                    Function3<CoroutineScope, MonotonicFrameClock, Continuation<? super Unit>, Object> function3 = this.$block;
                    MonotonicFrameClock monotonicFrameClock = this.$parentFrameClock;
                    this.label = 1;
                    if (function3.invoke($this$coroutineScope, monotonicFrameClock, this) != coroutine_suspended) {
                        break;
                    } else {
                        return coroutine_suspended;
                    }
                case 1:
                    ResultKt.throwOnFailure($result);
                    break;
                default:
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            return Unit.INSTANCE;
        }
    }
}
