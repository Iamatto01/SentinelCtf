package androidx.compose.foundation.gestures;

import androidx.compose.ui.unit.Velocity;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: Scrollable.kt */
@Metadata(d1 = {"\u0000\b\n\u0000\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u008a@"}, d2 = {"<anonymous>", "Landroidx/compose/ui/unit/Velocity;", "velocity"}, k = 3, mv = {1, 8, 0}, xi = 48)
@DebugMetadata(c = "androidx.compose.foundation.gestures.ScrollingLogic$onDragStopped$performFling$1", f = "Scrollable.kt", i = {0, 1, 1, 2, 2}, l = {406, 408, 410}, m = "invokeSuspend", n = {"velocity", "velocity", "available", "velocity", "velocityLeft"}, s = {"J$0", "J$0", "J$1", "J$0", "J$1"})
/* loaded from: classes.dex */
public final class ScrollingLogic$onDragStopped$performFling$1 extends SuspendLambda implements Function2<Velocity, Continuation<? super Velocity>, Object> {
    /* synthetic */ long J$0;
    long J$1;
    int label;
    final /* synthetic */ ScrollingLogic this$0;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ScrollingLogic$onDragStopped$performFling$1(ScrollingLogic scrollingLogic, Continuation<? super ScrollingLogic$onDragStopped$performFling$1> continuation) {
        super(2, continuation);
        this.this$0 = scrollingLogic;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
        ScrollingLogic$onDragStopped$performFling$1 scrollingLogic$onDragStopped$performFling$1 = new ScrollingLogic$onDragStopped$performFling$1(this.this$0, continuation);
        scrollingLogic$onDragStopped$performFling$1.J$0 = ((Velocity) obj).m5356unboximpl();
        return scrollingLogic$onDragStopped$performFling$1;
    }

    @Override // kotlin.jvm.functions.Function2
    public /* bridge */ /* synthetic */ Object invoke(Velocity velocity, Continuation<? super Velocity> continuation) {
        return m323invokesFctU(velocity.m5356unboximpl(), continuation);
    }

    /* renamed from: invoke-sF-c-tU  reason: not valid java name */
    public final Object m323invokesFctU(long j, Continuation<? super Velocity> continuation) {
        return ((ScrollingLogic$onDragStopped$performFling$1) create(Velocity.m5338boximpl(j), continuation)).invokeSuspend(Unit.INSTANCE);
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0087 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0088  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x00b5 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:20:0x00b6  */
    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r19) {
        /*
            r18 = this;
            java.lang.Object r0 = kotlin.coroutines.intrinsics.IntrinsicsKt.getCOROUTINE_SUSPENDED()
            r1 = r18
            int r2 = r1.label
            switch(r2) {
                case 0: goto L40;
                case 1: goto L34;
                case 2: goto L22;
                case 3: goto L13;
                default: goto Lb;
            }
        Lb:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L13:
            r0 = r18
            r1 = r19
            long r2 = r0.J$1
            long r4 = r0.J$0
            kotlin.ResultKt.throwOnFailure(r1)
            r14 = r2
            r2 = r1
            goto Lb8
        L22:
            r1 = r18
            r2 = r19
            long r3 = r1.J$1
            long r5 = r1.J$0
            kotlin.ResultKt.throwOnFailure(r2)
            r16 = r3
            r3 = r2
            r4 = r5
            r6 = r16
            goto L8d
        L34:
            r1 = r18
            r2 = r19
            long r3 = r1.J$0
            kotlin.ResultKt.throwOnFailure(r2)
            r4 = r3
            r3 = r2
            goto L6a
        L40:
            kotlin.ResultKt.throwOnFailure(r19)
            r1 = r18
            r2 = r19
            long r3 = r1.J$0
            androidx.compose.foundation.gestures.ScrollingLogic r5 = r1.this$0
            androidx.compose.runtime.State r5 = r5.getNestedScrollDispatcher()
            java.lang.Object r5 = r5.getValue()
            androidx.compose.ui.input.nestedscroll.NestedScrollDispatcher r5 = (androidx.compose.ui.input.nestedscroll.NestedScrollDispatcher) r5
            r6 = r1
            kotlin.coroutines.Continuation r6 = (kotlin.coroutines.Continuation) r6
            r1.J$0 = r3
            r7 = 1
            r1.label = r7
            java.lang.Object r5 = r5.m3896dispatchPreFlingQWom1Mo(r3, r6)
            if (r5 != r0) goto L64
            return r0
        L64:
            r16 = r3
            r3 = r2
            r2 = r5
            r4 = r16
        L6a:
            androidx.compose.ui.unit.Velocity r2 = (androidx.compose.ui.unit.Velocity) r2
            long r6 = r2.m5356unboximpl()
            long r6 = androidx.compose.ui.unit.Velocity.m5350minusAH228Gc(r4, r6)
            androidx.compose.foundation.gestures.ScrollingLogic r2 = r1.this$0
            r8 = r1
            kotlin.coroutines.Continuation r8 = (kotlin.coroutines.Continuation) r8
            r1.J$0 = r4
            r1.J$1 = r6
            r9 = 2
            r1.label = r9
            java.lang.Object r2 = r2.m311doFlingAnimationQWom1Mo(r6, r8)
            if (r2 != r0) goto L88
            return r0
        L88:
            r16 = r3
            r3 = r2
            r2 = r16
        L8d:
            androidx.compose.ui.unit.Velocity r3 = (androidx.compose.ui.unit.Velocity) r3
            long r14 = r3.m5356unboximpl()
            androidx.compose.foundation.gestures.ScrollingLogic r3 = r1.this$0
            androidx.compose.runtime.State r3 = r3.getNestedScrollDispatcher()
            java.lang.Object r3 = r3.getValue()
            r8 = r3
            androidx.compose.ui.input.nestedscroll.NestedScrollDispatcher r8 = (androidx.compose.ui.input.nestedscroll.NestedScrollDispatcher) r8
            long r9 = androidx.compose.ui.unit.Velocity.m5350minusAH228Gc(r6, r14)
            r13 = r1
            kotlin.coroutines.Continuation r13 = (kotlin.coroutines.Continuation) r13
            r1.J$0 = r4
            r1.J$1 = r14
            r3 = 3
            r1.label = r3
            r11 = r14
            java.lang.Object r3 = r8.m3894dispatchPostFlingRZ2iAVY(r9, r11, r13)
            if (r3 != r0) goto Lb6
            return r0
        Lb6:
            r0 = r1
            r1 = r3
        Lb8:
            androidx.compose.ui.unit.Velocity r1 = (androidx.compose.ui.unit.Velocity) r1
            long r6 = r1.m5356unboximpl()
            long r8 = androidx.compose.ui.unit.Velocity.m5350minusAH228Gc(r14, r6)
            long r10 = androidx.compose.ui.unit.Velocity.m5350minusAH228Gc(r4, r8)
            androidx.compose.ui.unit.Velocity r1 = androidx.compose.ui.unit.Velocity.m5338boximpl(r10)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.ScrollingLogic$onDragStopped$performFling$1.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
