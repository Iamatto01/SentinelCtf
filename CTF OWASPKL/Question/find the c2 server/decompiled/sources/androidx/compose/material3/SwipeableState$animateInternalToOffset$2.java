package androidx.compose.material3;

import androidx.compose.animation.core.Animatable;
import androidx.compose.animation.core.AnimatableKt;
import androidx.compose.animation.core.AnimationSpec;
import androidx.compose.animation.core.AnimationVector1D;
import androidx.compose.foundation.gestures.DragScope;
import androidx.compose.runtime.MutableState;
import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt;
import kotlin.coroutines.jvm.internal.Boxing;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Ref;
/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: Swipeable.kt */
@Metadata(d1 = {"\u0000\f\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\u0010\u0000\u001a\u00020\u0001\"\u0004\b\u0000\u0010\u0002*\u00020\u0003H\u008a@"}, d2 = {"<anonymous>", "", "T", "Landroidx/compose/foundation/gestures/DragScope;"}, k = 3, mv = {1, 7, 1}, xi = 48)
@DebugMetadata(c = "androidx.compose.material3.SwipeableState$animateInternalToOffset$2", f = "Swipeable.kt", i = {}, l = {223}, m = "invokeSuspend", n = {}, s = {})
/* loaded from: classes.dex */
public final class SwipeableState$animateInternalToOffset$2 extends SuspendLambda implements Function2<DragScope, Continuation<? super Unit>, Object> {
    final /* synthetic */ AnimationSpec<Float> $spec;
    final /* synthetic */ float $target;
    private /* synthetic */ Object L$0;
    int label;
    final /* synthetic */ SwipeableState<T> this$0;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SwipeableState$animateInternalToOffset$2(SwipeableState<T> swipeableState, float f, AnimationSpec<Float> animationSpec, Continuation<? super SwipeableState$animateInternalToOffset$2> continuation) {
        super(2, continuation);
        this.this$0 = swipeableState;
        this.$target = f;
        this.$spec = animationSpec;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
        SwipeableState$animateInternalToOffset$2 swipeableState$animateInternalToOffset$2 = new SwipeableState$animateInternalToOffset$2(this.this$0, this.$target, this.$spec, continuation);
        swipeableState$animateInternalToOffset$2.L$0 = obj;
        return swipeableState$animateInternalToOffset$2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(DragScope dragScope, Continuation<? super Unit> continuation) {
        return ((SwipeableState$animateInternalToOffset$2) create(dragScope, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Object invokeSuspend(Object $result) {
        MutableState mutableState;
        MutableState mutableState2;
        MutableState mutableState3;
        Object animateTo;
        MutableState mutableState4;
        Object coroutine_suspended = IntrinsicsKt.getCOROUTINE_SUSPENDED();
        SwipeableState$animateInternalToOffset$2 swipeableState$animateInternalToOffset$2 = this;
        try {
            switch (swipeableState$animateInternalToOffset$2.label) {
                case 0:
                    ResultKt.throwOnFailure($result);
                    swipeableState$animateInternalToOffset$2 = this;
                    final DragScope $this$drag = (DragScope) swipeableState$animateInternalToOffset$2.L$0;
                    final Ref.FloatRef prevValue = new Ref.FloatRef();
                    mutableState2 = ((SwipeableState) swipeableState$animateInternalToOffset$2.this$0).absoluteOffset;
                    prevValue.element = ((Number) mutableState2.getValue()).floatValue();
                    mutableState3 = ((SwipeableState) swipeableState$animateInternalToOffset$2.this$0).animationTarget;
                    mutableState3.setValue(Boxing.boxFloat(swipeableState$animateInternalToOffset$2.$target));
                    swipeableState$animateInternalToOffset$2.this$0.setAnimationRunning(true);
                    swipeableState$animateInternalToOffset$2.label = 1;
                    animateTo = r11.animateTo(Boxing.boxFloat(swipeableState$animateInternalToOffset$2.$target), (r12 & 2) != 0 ? r11.defaultSpringSpec : swipeableState$animateInternalToOffset$2.$spec, (r12 & 4) != 0 ? AnimatableKt.Animatable$default(prevValue.element, 0.0f, 2, null).getVelocity() : null, (r12 & 8) != 0 ? null : new Function1<Animatable<Float, AnimationVector1D>, Unit>() { // from class: androidx.compose.material3.SwipeableState$animateInternalToOffset$2.1
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(Animatable<Float, AnimationVector1D> animatable) {
                            invoke2(animatable);
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke  reason: avoid collision after fix types in other method */
                        public final void invoke2(Animatable<Float, AnimationVector1D> animateTo2) {
                            Intrinsics.checkNotNullParameter(animateTo2, "$this$animateTo");
                            DragScope.this.dragBy(animateTo2.getValue().floatValue() - prevValue.element);
                            prevValue.element = animateTo2.getValue().floatValue();
                        }
                    }, swipeableState$animateInternalToOffset$2);
                    if (animateTo == coroutine_suspended) {
                        return coroutine_suspended;
                    }
                    break;
                case 1:
                    swipeableState$animateInternalToOffset$2 = this;
                    ResultKt.throwOnFailure($result);
                    break;
                default:
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            mutableState4 = ((SwipeableState) swipeableState$animateInternalToOffset$2.this$0).animationTarget;
            mutableState4.setValue(null);
            swipeableState$animateInternalToOffset$2.this$0.setAnimationRunning(false);
            return Unit.INSTANCE;
        } catch (Throwable th) {
            mutableState = ((SwipeableState) swipeableState$animateInternalToOffset$2.this$0).animationTarget;
            mutableState.setValue(null);
            swipeableState$animateInternalToOffset$2.this$0.setAnimationRunning(false);
            throw th;
        }
    }
}
