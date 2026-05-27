package androidx.compose.foundation;

import androidx.compose.foundation.interaction.FocusInteraction;
import androidx.compose.foundation.interaction.MutableInteractionSource;
import androidx.compose.foundation.relocation.BringIntoViewRequester;
import androidx.compose.foundation.relocation.BringIntoViewRequesterKt;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.CompositionScopedCoroutineScopeCanceller;
import androidx.compose.runtime.DisposableEffectResult;
import androidx.compose.runtime.DisposableEffectScope;
import androidx.compose.runtime.EffectsKt;
import androidx.compose.runtime.MutableState;
import androidx.compose.runtime.SnapshotStateKt__SnapshotStateKt;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.focus.FocusChangedModifierKt;
import androidx.compose.ui.focus.FocusModifierKt;
import androidx.compose.ui.focus.FocusRequester;
import androidx.compose.ui.focus.FocusRequesterModifierKt;
import androidx.compose.ui.focus.FocusState;
import androidx.compose.ui.layout.PinnableContainer;
import androidx.compose.ui.layout.PinnableContainerKt;
import androidx.compose.ui.semantics.SemanticsModifierKt;
import androidx.compose.ui.semantics.SemanticsPropertiesKt;
import androidx.compose.ui.semantics.SemanticsPropertyReceiver;
import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlinx.coroutines.BuildersKt__Builders_commonKt;
import kotlinx.coroutines.CoroutineScope;
/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: Focusable.kt */
@Metadata(d1 = {"\u0000\n\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u0001*\u00020\u0001H\u000b¢\u0006\u0004\b\u0002\u0010\u0003"}, d2 = {"<anonymous>", "Landroidx/compose/ui/Modifier;", "invoke", "(Landroidx/compose/ui/Modifier;Landroidx/compose/runtime/Composer;I)Landroidx/compose/ui/Modifier;"}, k = 3, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class FocusableKt$focusable$2 extends Lambda implements Function3<Modifier, Composer, Integer, Modifier> {
    final /* synthetic */ boolean $enabled;
    final /* synthetic */ MutableInteractionSource $interactionSource;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public FocusableKt$focusable$2(MutableInteractionSource mutableInteractionSource, boolean z) {
        super(3);
        this.$interactionSource = mutableInteractionSource;
        this.$enabled = z;
    }

    @Override // kotlin.jvm.functions.Function3
    public /* bridge */ /* synthetic */ Modifier invoke(Modifier modifier, Composer composer, Integer num) {
        return invoke(modifier, composer, num.intValue());
    }

    public final Modifier invoke(Modifier composed, Composer $composer, int $changed) {
        Object value$iv$iv$iv;
        Object value$iv$iv;
        Object value$iv$iv2;
        Object obj;
        Object value$iv$iv3;
        Object value$iv$iv4;
        Modifier.Companion companion;
        Modifier.Companion focusedChildModifier;
        Object value$iv$iv5;
        boolean invalid$iv$iv;
        Object obj2;
        Intrinsics.checkNotNullParameter(composed, "$this$composed");
        $composer.startReplaceableGroup(1871352361);
        ComposerKt.sourceInformation($composer, "C68@2856L24,69@2910L58,70@2990L34,71@3050L29,83@3823L37,84@3901L280,84@3865L316,93@4186L390,116@5029L7,117@5062L66,118@5173L215,118@5137L251,129@5430L185:Focusable.kt#71ulvw");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(1871352361, $changed, -1, "androidx.compose.foundation.focusable.<anonymous> (Focusable.kt:67)");
        }
        $composer.startReplaceableGroup(773894976);
        ComposerKt.sourceInformation($composer, "CC(rememberCoroutineScope)476@19869L144:Effects.kt#9igjgp");
        $composer.startReplaceableGroup(-492369756);
        ComposerKt.sourceInformation($composer, "CC(remember):Composables.kt#9igjgp");
        Object it$iv$iv$iv = $composer.rememberedValue();
        if (it$iv$iv$iv == Composer.Companion.getEmpty()) {
            value$iv$iv$iv = new CompositionScopedCoroutineScopeCanceller(EffectsKt.createCompositionCoroutineScope(EmptyCoroutineContext.INSTANCE, $composer));
            $composer.updateRememberedValue(value$iv$iv$iv);
        } else {
            value$iv$iv$iv = it$iv$iv$iv;
        }
        $composer.endReplaceableGroup();
        CompositionScopedCoroutineScopeCanceller wrapper$iv = (CompositionScopedCoroutineScopeCanceller) value$iv$iv$iv;
        final CoroutineScope scope = wrapper$iv.getCoroutineScope();
        $composer.endReplaceableGroup();
        $composer.startReplaceableGroup(-492369756);
        ComposerKt.sourceInformation($composer, "CC(remember):Composables.kt#9igjgp");
        Object it$iv$iv = $composer.rememberedValue();
        if (it$iv$iv == Composer.Companion.getEmpty()) {
            value$iv$iv = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(null, null, 2, null);
            $composer.updateRememberedValue(value$iv$iv);
        } else {
            value$iv$iv = it$iv$iv;
        }
        $composer.endReplaceableGroup();
        final MutableState focusedInteraction = (MutableState) value$iv$iv;
        $composer.startReplaceableGroup(-492369756);
        ComposerKt.sourceInformation($composer, "CC(remember):Composables.kt#9igjgp");
        Object it$iv$iv2 = $composer.rememberedValue();
        if (it$iv$iv2 == Composer.Companion.getEmpty()) {
            value$iv$iv2 = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(false, null, 2, null);
            $composer.updateRememberedValue(value$iv$iv2);
        } else {
            value$iv$iv2 = it$iv$iv2;
        }
        $composer.endReplaceableGroup();
        final MutableState isFocused$delegate = (MutableState) value$iv$iv2;
        $composer.startReplaceableGroup(-492369756);
        ComposerKt.sourceInformation($composer, "CC(remember):Composables.kt#9igjgp");
        Object it$iv$iv3 = $composer.rememberedValue();
        if (it$iv$iv3 == Composer.Companion.getEmpty()) {
            Object value$iv$iv6 = new FocusRequester();
            $composer.updateRememberedValue(value$iv$iv6);
            obj = value$iv$iv6;
        } else {
            obj = it$iv$iv3;
        }
        $composer.endReplaceableGroup();
        final FocusRequester focusRequester = (FocusRequester) obj;
        $composer.startReplaceableGroup(-492369756);
        ComposerKt.sourceInformation($composer, "CC(remember):Composables.kt#9igjgp");
        Object it$iv$iv4 = $composer.rememberedValue();
        if (it$iv$iv4 == Composer.Companion.getEmpty()) {
            value$iv$iv3 = BringIntoViewRequesterKt.BringIntoViewRequester();
            $composer.updateRememberedValue(value$iv$iv3);
        } else {
            value$iv$iv3 = it$iv$iv4;
        }
        $composer.endReplaceableGroup();
        final BringIntoViewRequester bringIntoViewRequester = (BringIntoViewRequester) value$iv$iv3;
        final MutableInteractionSource mutableInteractionSource = this.$interactionSource;
        Object key2$iv = this.$interactionSource;
        $composer.startReplaceableGroup(511388516);
        ComposerKt.sourceInformation($composer, "CC(remember)P(1,2):Composables.kt#9igjgp");
        boolean invalid$iv$iv2 = $composer.changed(focusedInteraction) | $composer.changed(key2$iv);
        Object it$iv$iv5 = $composer.rememberedValue();
        if (invalid$iv$iv2 || it$iv$iv5 == Composer.Companion.getEmpty()) {
            Object value$iv$iv7 = (Function1) new Function1<DisposableEffectScope, DisposableEffectResult>() { // from class: androidx.compose.foundation.FocusableKt$focusable$2$1$1
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public final DisposableEffectResult invoke(DisposableEffectScope DisposableEffect) {
                    Intrinsics.checkNotNullParameter(DisposableEffect, "$this$DisposableEffect");
                    final MutableState<FocusInteraction.Focus> mutableState = focusedInteraction;
                    final MutableInteractionSource mutableInteractionSource2 = mutableInteractionSource;
                    return new DisposableEffectResult() { // from class: androidx.compose.foundation.FocusableKt$focusable$2$1$1$invoke$$inlined$onDispose$1
                        @Override // androidx.compose.runtime.DisposableEffectResult
                        public void dispose() {
                            FocusInteraction.Focus oldValue = (FocusInteraction.Focus) MutableState.this.getValue();
                            if (oldValue == null) {
                                return;
                            }
                            FocusInteraction.Unfocus interaction = new FocusInteraction.Unfocus(oldValue);
                            MutableInteractionSource mutableInteractionSource3 = mutableInteractionSource2;
                            if (mutableInteractionSource3 != null) {
                                mutableInteractionSource3.tryEmit(interaction);
                            }
                            MutableState.this.setValue(null);
                        }
                    };
                }
            };
            $composer.updateRememberedValue(value$iv$iv7);
            value$iv$iv4 = value$iv$iv7;
        } else {
            value$iv$iv4 = it$iv$iv5;
        }
        $composer.endReplaceableGroup();
        EffectsKt.DisposableEffect(mutableInteractionSource, (Function1) value$iv$iv4, $composer, 0);
        Boolean valueOf = Boolean.valueOf(this.$enabled);
        final boolean z = this.$enabled;
        final MutableInteractionSource mutableInteractionSource2 = this.$interactionSource;
        EffectsKt.DisposableEffect(valueOf, new Function1<DisposableEffectScope, DisposableEffectResult>() { // from class: androidx.compose.foundation.FocusableKt$focusable$2.2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public final DisposableEffectResult invoke(DisposableEffectScope DisposableEffect) {
                Intrinsics.checkNotNullParameter(DisposableEffect, "$this$DisposableEffect");
                if (!z) {
                    BuildersKt__Builders_commonKt.launch$default(scope, null, null, new AnonymousClass1(focusedInteraction, mutableInteractionSource2, null), 3, null);
                }
                return new DisposableEffectResult() { // from class: androidx.compose.foundation.FocusableKt$focusable$2$2$invoke$$inlined$onDispose$1
                    @Override // androidx.compose.runtime.DisposableEffectResult
                    public void dispose() {
                    }
                };
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            /* compiled from: Focusable.kt */
            @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
            @DebugMetadata(c = "androidx.compose.foundation.FocusableKt$focusable$2$2$1", f = "Focusable.kt", i = {}, l = {99}, m = "invokeSuspend", n = {}, s = {})
            /* renamed from: androidx.compose.foundation.FocusableKt$focusable$2$2$1  reason: invalid class name */
            /* loaded from: classes.dex */
            public static final class AnonymousClass1 extends SuspendLambda implements Function2<CoroutineScope, Continuation<? super Unit>, Object> {
                final /* synthetic */ MutableState<FocusInteraction.Focus> $focusedInteraction;
                final /* synthetic */ MutableInteractionSource $interactionSource;
                Object L$0;
                int label;

                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                AnonymousClass1(MutableState<FocusInteraction.Focus> mutableState, MutableInteractionSource mutableInteractionSource, Continuation<? super AnonymousClass1> continuation) {
                    super(2, continuation);
                    this.$focusedInteraction = mutableState;
                    this.$interactionSource = mutableInteractionSource;
                }

                @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
                    return new AnonymousClass1(this.$focusedInteraction, this.$interactionSource, continuation);
                }

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(CoroutineScope coroutineScope, Continuation<? super Unit> continuation) {
                    return ((AnonymousClass1) create(coroutineScope, continuation)).invokeSuspend(Unit.INSTANCE);
                }

                @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                public final Object invokeSuspend(Object $result) {
                    MutableState<FocusInteraction.Focus> mutableState;
                    AnonymousClass1 anonymousClass1;
                    MutableState<FocusInteraction.Focus> mutableState2;
                    boolean z;
                    Object coroutine_suspended = IntrinsicsKt.getCOROUTINE_SUSPENDED();
                    switch (this.label) {
                        case 0:
                            ResultKt.throwOnFailure($result);
                            FocusInteraction.Focus oldValue = this.$focusedInteraction.getValue();
                            if (oldValue != null) {
                                MutableInteractionSource mutableInteractionSource = this.$interactionSource;
                                mutableState = this.$focusedInteraction;
                                FocusInteraction.Unfocus interaction = new FocusInteraction.Unfocus(oldValue);
                                if (mutableInteractionSource != null) {
                                    this.L$0 = mutableState;
                                    this.label = 1;
                                    if (mutableInteractionSource.emit(interaction, this) != coroutine_suspended) {
                                        anonymousClass1 = this;
                                        mutableState2 = mutableState;
                                        z = false;
                                        mutableState = mutableState2;
                                    } else {
                                        return coroutine_suspended;
                                    }
                                }
                                mutableState.setValue(null);
                                break;
                            }
                            break;
                        case 1:
                            anonymousClass1 = this;
                            z = false;
                            mutableState2 = (MutableState) anonymousClass1.L$0;
                            ResultKt.throwOnFailure($result);
                            mutableState = mutableState2;
                            mutableState.setValue(null);
                            break;
                        default:
                            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    return Unit.INSTANCE;
                }
            }
        }, $composer, 0);
        if (this.$enabled) {
            $composer.startReplaceableGroup(1407540673);
            ComposerKt.sourceInformation($composer, "108@4661L36");
            if (!invoke$lambda$2(isFocused$delegate)) {
                focusedChildModifier = Modifier.Companion;
            } else {
                $composer.startReplaceableGroup(-492369756);
                ComposerKt.sourceInformation($composer, "CC(remember):Composables.kt#9igjgp");
                Object it$iv$iv6 = $composer.rememberedValue();
                if (it$iv$iv6 == Composer.Companion.getEmpty()) {
                    Object value$iv$iv8 = new FocusedBoundsModifier();
                    $composer.updateRememberedValue(value$iv$iv8);
                    obj2 = value$iv$iv8;
                } else {
                    obj2 = it$iv$iv6;
                }
                $composer.endReplaceableGroup();
                focusedChildModifier = (Modifier) obj2;
            }
            $composer.endReplaceableGroup();
            ComposerKt.sourceInformationMarkerStart($composer, 2023513938, "CC:CompositionLocal.kt#9igjgp");
            Object consume = $composer.consume(PinnableContainerKt.getLocalPinnableContainer());
            ComposerKt.sourceInformationMarkerEnd($composer);
            final PinnableContainer pinnableContainer = (PinnableContainer) consume;
            $composer.startReplaceableGroup(-492369756);
            ComposerKt.sourceInformation($composer, "CC(remember):Composables.kt#9igjgp");
            Object it$iv$iv7 = $composer.rememberedValue();
            if (it$iv$iv7 == Composer.Companion.getEmpty()) {
                value$iv$iv5 = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(null, null, 2, null);
                $composer.updateRememberedValue(value$iv$iv5);
            } else {
                value$iv$iv5 = it$iv$iv7;
            }
            $composer.endReplaceableGroup();
            final MutableState pinHandle$delegate = (MutableState) value$iv$iv5;
            $composer.startReplaceableGroup(1618982084);
            ComposerKt.sourceInformation($composer, "CC(remember)P(1,2,3):Composables.kt#9igjgp");
            boolean invalid$iv$iv3 = $composer.changed(isFocused$delegate) | $composer.changed(pinHandle$delegate) | $composer.changed(pinnableContainer);
            Object value$iv$iv9 = $composer.rememberedValue();
            if (!invalid$iv$iv3 && value$iv$iv9 != Composer.Companion.getEmpty()) {
                $composer.endReplaceableGroup();
                EffectsKt.DisposableEffect(pinnableContainer, (Function1) value$iv$iv9, $composer, 0);
                Modifier.Companion companion2 = Modifier.Companion;
                $composer.startReplaceableGroup(511388516);
                ComposerKt.sourceInformation($composer, "CC(remember)P(1,2):Composables.kt#9igjgp");
                invalid$iv$iv = $composer.changed(isFocused$delegate) | $composer.changed(focusRequester);
                Object value$iv$iv10 = $composer.rememberedValue();
                if (!invalid$iv$iv && value$iv$iv10 != Composer.Companion.getEmpty()) {
                    $composer.endReplaceableGroup();
                    Modifier then = FocusRequesterModifierKt.focusRequester(BringIntoViewRequesterKt.bringIntoViewRequester(SemanticsModifierKt.semantics$default(companion2, false, (Function1) value$iv$iv10, 1, null), bringIntoViewRequester), focusRequester).then(focusedChildModifier);
                    final MutableInteractionSource mutableInteractionSource3 = this.$interactionSource;
                    companion = FocusModifierKt.focusTarget(FocusChangedModifierKt.onFocusChanged(then, new Function1<FocusState, Unit>() { // from class: androidx.compose.foundation.FocusableKt$focusable$2.5
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(FocusState focusState) {
                            invoke2(focusState);
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke  reason: avoid collision after fix types in other method */
                        public final void invoke2(FocusState it) {
                            Intrinsics.checkNotNullParameter(it, "it");
                            FocusableKt$focusable$2.invoke$lambda$3(isFocused$delegate, it.isFocused());
                            if (!FocusableKt$focusable$2.invoke$lambda$2(isFocused$delegate)) {
                                PinnableContainer.PinnedHandle invoke$lambda$9 = FocusableKt$focusable$2.invoke$lambda$9(pinHandle$delegate);
                                if (invoke$lambda$9 != null) {
                                    invoke$lambda$9.release();
                                }
                                FocusableKt$focusable$2.invoke$lambda$10(pinHandle$delegate, null);
                                BuildersKt__Builders_commonKt.launch$default(scope, null, null, new AnonymousClass2(focusedInteraction, mutableInteractionSource3, null), 3, null);
                                return;
                            }
                            MutableState<PinnableContainer.PinnedHandle> mutableState = pinHandle$delegate;
                            PinnableContainer pinnableContainer2 = PinnableContainer.this;
                            FocusableKt$focusable$2.invoke$lambda$10(mutableState, pinnableContainer2 != null ? pinnableContainer2.pin() : null);
                            BuildersKt__Builders_commonKt.launch$default(scope, null, null, new AnonymousClass1(focusedInteraction, mutableInteractionSource3, bringIntoViewRequester, null), 3, null);
                        }

                        /* JADX INFO: Access modifiers changed from: package-private */
                        /* compiled from: Focusable.kt */
                        @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
                        @DebugMetadata(c = "androidx.compose.foundation.FocusableKt$focusable$2$5$1", f = "Focusable.kt", i = {1}, l = {147, 151, 154}, m = "invokeSuspend", n = {"interaction"}, s = {"L$0"})
                        /* renamed from: androidx.compose.foundation.FocusableKt$focusable$2$5$1  reason: invalid class name */
                        /* loaded from: classes.dex */
                        public static final class AnonymousClass1 extends SuspendLambda implements Function2<CoroutineScope, Continuation<? super Unit>, Object> {
                            final /* synthetic */ BringIntoViewRequester $bringIntoViewRequester;
                            final /* synthetic */ MutableState<FocusInteraction.Focus> $focusedInteraction;
                            final /* synthetic */ MutableInteractionSource $interactionSource;
                            Object L$0;
                            int label;

                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            AnonymousClass1(MutableState<FocusInteraction.Focus> mutableState, MutableInteractionSource mutableInteractionSource, BringIntoViewRequester bringIntoViewRequester, Continuation<? super AnonymousClass1> continuation) {
                                super(2, continuation);
                                this.$focusedInteraction = mutableState;
                                this.$interactionSource = mutableInteractionSource;
                                this.$bringIntoViewRequester = bringIntoViewRequester;
                            }

                            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                            public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
                                return new AnonymousClass1(this.$focusedInteraction, this.$interactionSource, this.$bringIntoViewRequester, continuation);
                            }

                            @Override // kotlin.jvm.functions.Function2
                            public final Object invoke(CoroutineScope coroutineScope, Continuation<? super Unit> continuation) {
                                return ((AnonymousClass1) create(coroutineScope, continuation)).invokeSuspend(Unit.INSTANCE);
                            }

                            /* JADX WARN: Removed duplicated region for block: B:21:0x0068  */
                            /* JADX WARN: Removed duplicated region for block: B:26:0x0090 A[RETURN] */
                            /* JADX WARN: Removed duplicated region for block: B:27:0x0091  */
                            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                            /*
                                Code decompiled incorrectly, please refer to instructions dump.
                                To view partially-correct add '--show-bad-code' argument
                            */
                            public final java.lang.Object invokeSuspend(java.lang.Object r10) {
                                /*
                                    r9 = this;
                                    java.lang.Object r0 = kotlin.coroutines.intrinsics.IntrinsicsKt.getCOROUTINE_SUSPENDED()
                                    int r1 = r9.label
                                    r2 = 1
                                    r3 = 0
                                    switch(r1) {
                                        case 0: goto L2c;
                                        case 1: goto L22;
                                        case 2: goto L19;
                                        case 3: goto L13;
                                        default: goto Lb;
                                    }
                                Lb:
                                    java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
                                    java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
                                    r10.<init>(r0)
                                    throw r10
                                L13:
                                    r0 = r9
                                    kotlin.ResultKt.throwOnFailure(r10)
                                    goto L92
                                L19:
                                    r1 = r9
                                    java.lang.Object r4 = r1.L$0
                                    androidx.compose.foundation.interaction.FocusInteraction$Focus r4 = (androidx.compose.foundation.interaction.FocusInteraction.Focus) r4
                                    kotlin.ResultKt.throwOnFailure(r10)
                                    goto L7a
                                L22:
                                    r1 = r9
                                    r4 = 0
                                    java.lang.Object r5 = r1.L$0
                                    androidx.compose.runtime.MutableState r5 = (androidx.compose.runtime.MutableState) r5
                                    kotlin.ResultKt.throwOnFailure(r10)
                                    goto L57
                                L2c:
                                    kotlin.ResultKt.throwOnFailure(r10)
                                    r1 = r9
                                    androidx.compose.runtime.MutableState<androidx.compose.foundation.interaction.FocusInteraction$Focus> r4 = r1.$focusedInteraction
                                    java.lang.Object r4 = r4.getValue()
                                    androidx.compose.foundation.interaction.FocusInteraction$Focus r4 = (androidx.compose.foundation.interaction.FocusInteraction.Focus) r4
                                    if (r4 == 0) goto L5f
                                    androidx.compose.foundation.interaction.MutableInteractionSource r5 = r1.$interactionSource
                                    androidx.compose.runtime.MutableState<androidx.compose.foundation.interaction.FocusInteraction$Focus> r6 = r1.$focusedInteraction
                                    r7 = 0
                                    androidx.compose.foundation.interaction.FocusInteraction$Unfocus r8 = new androidx.compose.foundation.interaction.FocusInteraction$Unfocus
                                    r8.<init>(r4)
                                    r4 = r8
                                    if (r5 == 0) goto L5a
                                    r8 = r4
                                    androidx.compose.foundation.interaction.Interaction r8 = (androidx.compose.foundation.interaction.Interaction) r8
                                    r1.L$0 = r6
                                    r1.label = r2
                                    java.lang.Object r4 = r5.emit(r8, r1)
                                    if (r4 != r0) goto L55
                                    return r0
                                L55:
                                    r5 = r6
                                    r4 = r7
                                L57:
                                    r7 = r4
                                    r6 = r5
                                L5a:
                                    r6.setValue(r3)
                                L5f:
                                    androidx.compose.foundation.interaction.FocusInteraction$Focus r4 = new androidx.compose.foundation.interaction.FocusInteraction$Focus
                                    r4.<init>()
                                    androidx.compose.foundation.interaction.MutableInteractionSource r5 = r1.$interactionSource
                                    if (r5 == 0) goto L7a
                                    r6 = r4
                                    androidx.compose.foundation.interaction.Interaction r6 = (androidx.compose.foundation.interaction.Interaction) r6
                                    r7 = r1
                                    kotlin.coroutines.Continuation r7 = (kotlin.coroutines.Continuation) r7
                                    r1.L$0 = r4
                                    r8 = 2
                                    r1.label = r8
                                    java.lang.Object r5 = r5.emit(r6, r7)
                                    if (r5 != r0) goto L7a
                                    return r0
                                L7a:
                                    androidx.compose.runtime.MutableState<androidx.compose.foundation.interaction.FocusInteraction$Focus> r5 = r1.$focusedInteraction
                                    r5.setValue(r4)
                                    androidx.compose.foundation.relocation.BringIntoViewRequester r4 = r1.$bringIntoViewRequester
                                    r5 = r1
                                    kotlin.coroutines.Continuation r5 = (kotlin.coroutines.Continuation) r5
                                    r1.L$0 = r3
                                    r6 = 3
                                    r1.label = r6
                                    java.lang.Object r2 = androidx.compose.foundation.relocation.BringIntoViewRequester.bringIntoView$default(r4, r3, r5, r2, r3)
                                    if (r2 != r0) goto L91
                                    return r0
                                L91:
                                    r0 = r1
                                L92:
                                    kotlin.Unit r1 = kotlin.Unit.INSTANCE
                                    return r1
                                */
                                throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.FocusableKt$focusable$2.AnonymousClass5.AnonymousClass1.invokeSuspend(java.lang.Object):java.lang.Object");
                            }
                        }

                        /* JADX INFO: Access modifiers changed from: package-private */
                        /* compiled from: Focusable.kt */
                        @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
                        @DebugMetadata(c = "androidx.compose.foundation.FocusableKt$focusable$2$5$2", f = "Focusable.kt", i = {}, l = {162}, m = "invokeSuspend", n = {}, s = {})
                        /* renamed from: androidx.compose.foundation.FocusableKt$focusable$2$5$2  reason: invalid class name */
                        /* loaded from: classes.dex */
                        public static final class AnonymousClass2 extends SuspendLambda implements Function2<CoroutineScope, Continuation<? super Unit>, Object> {
                            final /* synthetic */ MutableState<FocusInteraction.Focus> $focusedInteraction;
                            final /* synthetic */ MutableInteractionSource $interactionSource;
                            Object L$0;
                            int label;

                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            AnonymousClass2(MutableState<FocusInteraction.Focus> mutableState, MutableInteractionSource mutableInteractionSource, Continuation<? super AnonymousClass2> continuation) {
                                super(2, continuation);
                                this.$focusedInteraction = mutableState;
                                this.$interactionSource = mutableInteractionSource;
                            }

                            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                            public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
                                return new AnonymousClass2(this.$focusedInteraction, this.$interactionSource, continuation);
                            }

                            @Override // kotlin.jvm.functions.Function2
                            public final Object invoke(CoroutineScope coroutineScope, Continuation<? super Unit> continuation) {
                                return ((AnonymousClass2) create(coroutineScope, continuation)).invokeSuspend(Unit.INSTANCE);
                            }

                            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                            public final Object invokeSuspend(Object $result) {
                                MutableState<FocusInteraction.Focus> mutableState;
                                AnonymousClass2 anonymousClass2;
                                MutableState<FocusInteraction.Focus> mutableState2;
                                boolean z;
                                Object coroutine_suspended = IntrinsicsKt.getCOROUTINE_SUSPENDED();
                                switch (this.label) {
                                    case 0:
                                        ResultKt.throwOnFailure($result);
                                        FocusInteraction.Focus oldValue = this.$focusedInteraction.getValue();
                                        if (oldValue != null) {
                                            MutableInteractionSource mutableInteractionSource = this.$interactionSource;
                                            mutableState = this.$focusedInteraction;
                                            FocusInteraction.Unfocus interaction = new FocusInteraction.Unfocus(oldValue);
                                            if (mutableInteractionSource != null) {
                                                this.L$0 = mutableState;
                                                this.label = 1;
                                                if (mutableInteractionSource.emit(interaction, this) != coroutine_suspended) {
                                                    anonymousClass2 = this;
                                                    mutableState2 = mutableState;
                                                    z = false;
                                                    mutableState = mutableState2;
                                                } else {
                                                    return coroutine_suspended;
                                                }
                                            }
                                            mutableState.setValue(null);
                                            break;
                                        }
                                        break;
                                    case 1:
                                        anonymousClass2 = this;
                                        z = false;
                                        mutableState2 = (MutableState) anonymousClass2.L$0;
                                        ResultKt.throwOnFailure($result);
                                        mutableState = mutableState2;
                                        mutableState.setValue(null);
                                        break;
                                    default:
                                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                                }
                                return Unit.INSTANCE;
                            }
                        }
                    }));
                }
                value$iv$iv10 = (Function1) new Function1<SemanticsPropertyReceiver, Unit>() { // from class: androidx.compose.foundation.FocusableKt$focusable$2$4$1
                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(SemanticsPropertyReceiver semanticsPropertyReceiver) {
                        invoke2(semanticsPropertyReceiver);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke  reason: avoid collision after fix types in other method */
                    public final void invoke2(SemanticsPropertyReceiver semantics) {
                        Intrinsics.checkNotNullParameter(semantics, "$this$semantics");
                        SemanticsPropertiesKt.setFocused(semantics, FocusableKt$focusable$2.invoke$lambda$2(isFocused$delegate));
                        final FocusRequester focusRequester2 = focusRequester;
                        final MutableState<Boolean> mutableState = isFocused$delegate;
                        SemanticsPropertiesKt.requestFocus$default(semantics, null, new Function0<Boolean>() { // from class: androidx.compose.foundation.FocusableKt$focusable$2$4$1.1
                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            {
                                super(0);
                            }

                            /* JADX WARN: Can't rename method to resolve collision */
                            @Override // kotlin.jvm.functions.Function0
                            public final Boolean invoke() {
                                FocusRequester.this.requestFocus();
                                return Boolean.valueOf(FocusableKt$focusable$2.invoke$lambda$2(mutableState));
                            }
                        }, 1, null);
                    }
                };
                $composer.updateRememberedValue(value$iv$iv10);
                $composer.endReplaceableGroup();
                Modifier then2 = FocusRequesterModifierKt.focusRequester(BringIntoViewRequesterKt.bringIntoViewRequester(SemanticsModifierKt.semantics$default(companion2, false, (Function1) value$iv$iv10, 1, null), bringIntoViewRequester), focusRequester).then(focusedChildModifier);
                final MutableInteractionSource mutableInteractionSource32 = this.$interactionSource;
                companion = FocusModifierKt.focusTarget(FocusChangedModifierKt.onFocusChanged(then2, new Function1<FocusState, Unit>() { // from class: androidx.compose.foundation.FocusableKt$focusable$2.5
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(FocusState focusState) {
                        invoke2(focusState);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke  reason: avoid collision after fix types in other method */
                    public final void invoke2(FocusState it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        FocusableKt$focusable$2.invoke$lambda$3(isFocused$delegate, it.isFocused());
                        if (!FocusableKt$focusable$2.invoke$lambda$2(isFocused$delegate)) {
                            PinnableContainer.PinnedHandle invoke$lambda$9 = FocusableKt$focusable$2.invoke$lambda$9(pinHandle$delegate);
                            if (invoke$lambda$9 != null) {
                                invoke$lambda$9.release();
                            }
                            FocusableKt$focusable$2.invoke$lambda$10(pinHandle$delegate, null);
                            BuildersKt__Builders_commonKt.launch$default(scope, null, null, new AnonymousClass2(focusedInteraction, mutableInteractionSource32, null), 3, null);
                            return;
                        }
                        MutableState<PinnableContainer.PinnedHandle> mutableState = pinHandle$delegate;
                        PinnableContainer pinnableContainer2 = PinnableContainer.this;
                        FocusableKt$focusable$2.invoke$lambda$10(mutableState, pinnableContainer2 != null ? pinnableContainer2.pin() : null);
                        BuildersKt__Builders_commonKt.launch$default(scope, null, null, new AnonymousClass1(focusedInteraction, mutableInteractionSource32, bringIntoViewRequester, null), 3, null);
                    }

                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* compiled from: Focusable.kt */
                    @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
                    @DebugMetadata(c = "androidx.compose.foundation.FocusableKt$focusable$2$5$1", f = "Focusable.kt", i = {1}, l = {147, 151, 154}, m = "invokeSuspend", n = {"interaction"}, s = {"L$0"})
                    /* renamed from: androidx.compose.foundation.FocusableKt$focusable$2$5$1  reason: invalid class name */
                    /* loaded from: classes.dex */
                    public static final class AnonymousClass1 extends SuspendLambda implements Function2<CoroutineScope, Continuation<? super Unit>, Object> {
                        final /* synthetic */ BringIntoViewRequester $bringIntoViewRequester;
                        final /* synthetic */ MutableState<FocusInteraction.Focus> $focusedInteraction;
                        final /* synthetic */ MutableInteractionSource $interactionSource;
                        Object L$0;
                        int label;

                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        AnonymousClass1(MutableState<FocusInteraction.Focus> mutableState, MutableInteractionSource mutableInteractionSource, BringIntoViewRequester bringIntoViewRequester, Continuation<? super AnonymousClass1> continuation) {
                            super(2, continuation);
                            this.$focusedInteraction = mutableState;
                            this.$interactionSource = mutableInteractionSource;
                            this.$bringIntoViewRequester = bringIntoViewRequester;
                        }

                        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                        public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
                            return new AnonymousClass1(this.$focusedInteraction, this.$interactionSource, this.$bringIntoViewRequester, continuation);
                        }

                        @Override // kotlin.jvm.functions.Function2
                        public final Object invoke(CoroutineScope coroutineScope, Continuation<? super Unit> continuation) {
                            return ((AnonymousClass1) create(coroutineScope, continuation)).invokeSuspend(Unit.INSTANCE);
                        }

                        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                        /*
                            Code decompiled incorrectly, please refer to instructions dump.
                            To view partially-correct add '--show-bad-code' argument
                        */
                        public final java.lang.Object invokeSuspend(java.lang.Object r10) {
                            /*
                                r9 = this;
                                java.lang.Object r0 = kotlin.coroutines.intrinsics.IntrinsicsKt.getCOROUTINE_SUSPENDED()
                                int r1 = r9.label
                                r2 = 1
                                r3 = 0
                                switch(r1) {
                                    case 0: goto L2c;
                                    case 1: goto L22;
                                    case 2: goto L19;
                                    case 3: goto L13;
                                    default: goto Lb;
                                }
                            Lb:
                                java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
                                java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
                                r10.<init>(r0)
                                throw r10
                            L13:
                                r0 = r9
                                kotlin.ResultKt.throwOnFailure(r10)
                                goto L92
                            L19:
                                r1 = r9
                                java.lang.Object r4 = r1.L$0
                                androidx.compose.foundation.interaction.FocusInteraction$Focus r4 = (androidx.compose.foundation.interaction.FocusInteraction.Focus) r4
                                kotlin.ResultKt.throwOnFailure(r10)
                                goto L7a
                            L22:
                                r1 = r9
                                r4 = 0
                                java.lang.Object r5 = r1.L$0
                                androidx.compose.runtime.MutableState r5 = (androidx.compose.runtime.MutableState) r5
                                kotlin.ResultKt.throwOnFailure(r10)
                                goto L57
                            L2c:
                                kotlin.ResultKt.throwOnFailure(r10)
                                r1 = r9
                                androidx.compose.runtime.MutableState<androidx.compose.foundation.interaction.FocusInteraction$Focus> r4 = r1.$focusedInteraction
                                java.lang.Object r4 = r4.getValue()
                                androidx.compose.foundation.interaction.FocusInteraction$Focus r4 = (androidx.compose.foundation.interaction.FocusInteraction.Focus) r4
                                if (r4 == 0) goto L5f
                                androidx.compose.foundation.interaction.MutableInteractionSource r5 = r1.$interactionSource
                                androidx.compose.runtime.MutableState<androidx.compose.foundation.interaction.FocusInteraction$Focus> r6 = r1.$focusedInteraction
                                r7 = 0
                                androidx.compose.foundation.interaction.FocusInteraction$Unfocus r8 = new androidx.compose.foundation.interaction.FocusInteraction$Unfocus
                                r8.<init>(r4)
                                r4 = r8
                                if (r5 == 0) goto L5a
                                r8 = r4
                                androidx.compose.foundation.interaction.Interaction r8 = (androidx.compose.foundation.interaction.Interaction) r8
                                r1.L$0 = r6
                                r1.label = r2
                                java.lang.Object r4 = r5.emit(r8, r1)
                                if (r4 != r0) goto L55
                                return r0
                            L55:
                                r5 = r6
                                r4 = r7
                            L57:
                                r7 = r4
                                r6 = r5
                            L5a:
                                r6.setValue(r3)
                            L5f:
                                androidx.compose.foundation.interaction.FocusInteraction$Focus r4 = new androidx.compose.foundation.interaction.FocusInteraction$Focus
                                r4.<init>()
                                androidx.compose.foundation.interaction.MutableInteractionSource r5 = r1.$interactionSource
                                if (r5 == 0) goto L7a
                                r6 = r4
                                androidx.compose.foundation.interaction.Interaction r6 = (androidx.compose.foundation.interaction.Interaction) r6
                                r7 = r1
                                kotlin.coroutines.Continuation r7 = (kotlin.coroutines.Continuation) r7
                                r1.L$0 = r4
                                r8 = 2
                                r1.label = r8
                                java.lang.Object r5 = r5.emit(r6, r7)
                                if (r5 != r0) goto L7a
                                return r0
                            L7a:
                                androidx.compose.runtime.MutableState<androidx.compose.foundation.interaction.FocusInteraction$Focus> r5 = r1.$focusedInteraction
                                r5.setValue(r4)
                                androidx.compose.foundation.relocation.BringIntoViewRequester r4 = r1.$bringIntoViewRequester
                                r5 = r1
                                kotlin.coroutines.Continuation r5 = (kotlin.coroutines.Continuation) r5
                                r1.L$0 = r3
                                r6 = 3
                                r1.label = r6
                                java.lang.Object r2 = androidx.compose.foundation.relocation.BringIntoViewRequester.bringIntoView$default(r4, r3, r5, r2, r3)
                                if (r2 != r0) goto L91
                                return r0
                            L91:
                                r0 = r1
                            L92:
                                kotlin.Unit r1 = kotlin.Unit.INSTANCE
                                return r1
                            */
                            throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.FocusableKt$focusable$2.AnonymousClass5.AnonymousClass1.invokeSuspend(java.lang.Object):java.lang.Object");
                        }
                    }

                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* compiled from: Focusable.kt */
                    @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
                    @DebugMetadata(c = "androidx.compose.foundation.FocusableKt$focusable$2$5$2", f = "Focusable.kt", i = {}, l = {162}, m = "invokeSuspend", n = {}, s = {})
                    /* renamed from: androidx.compose.foundation.FocusableKt$focusable$2$5$2  reason: invalid class name */
                    /* loaded from: classes.dex */
                    public static final class AnonymousClass2 extends SuspendLambda implements Function2<CoroutineScope, Continuation<? super Unit>, Object> {
                        final /* synthetic */ MutableState<FocusInteraction.Focus> $focusedInteraction;
                        final /* synthetic */ MutableInteractionSource $interactionSource;
                        Object L$0;
                        int label;

                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        AnonymousClass2(MutableState<FocusInteraction.Focus> mutableState, MutableInteractionSource mutableInteractionSource, Continuation<? super AnonymousClass2> continuation) {
                            super(2, continuation);
                            this.$focusedInteraction = mutableState;
                            this.$interactionSource = mutableInteractionSource;
                        }

                        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                        public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
                            return new AnonymousClass2(this.$focusedInteraction, this.$interactionSource, continuation);
                        }

                        @Override // kotlin.jvm.functions.Function2
                        public final Object invoke(CoroutineScope coroutineScope, Continuation<? super Unit> continuation) {
                            return ((AnonymousClass2) create(coroutineScope, continuation)).invokeSuspend(Unit.INSTANCE);
                        }

                        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                        public final Object invokeSuspend(Object $result) {
                            MutableState<FocusInteraction.Focus> mutableState;
                            AnonymousClass2 anonymousClass2;
                            MutableState<FocusInteraction.Focus> mutableState2;
                            boolean z;
                            Object coroutine_suspended = IntrinsicsKt.getCOROUTINE_SUSPENDED();
                            switch (this.label) {
                                case 0:
                                    ResultKt.throwOnFailure($result);
                                    FocusInteraction.Focus oldValue = this.$focusedInteraction.getValue();
                                    if (oldValue != null) {
                                        MutableInteractionSource mutableInteractionSource = this.$interactionSource;
                                        mutableState = this.$focusedInteraction;
                                        FocusInteraction.Unfocus interaction = new FocusInteraction.Unfocus(oldValue);
                                        if (mutableInteractionSource != null) {
                                            this.L$0 = mutableState;
                                            this.label = 1;
                                            if (mutableInteractionSource.emit(interaction, this) != coroutine_suspended) {
                                                anonymousClass2 = this;
                                                mutableState2 = mutableState;
                                                z = false;
                                                mutableState = mutableState2;
                                            } else {
                                                return coroutine_suspended;
                                            }
                                        }
                                        mutableState.setValue(null);
                                        break;
                                    }
                                    break;
                                case 1:
                                    anonymousClass2 = this;
                                    z = false;
                                    mutableState2 = (MutableState) anonymousClass2.L$0;
                                    ResultKt.throwOnFailure($result);
                                    mutableState = mutableState2;
                                    mutableState.setValue(null);
                                    break;
                                default:
                                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                            }
                            return Unit.INSTANCE;
                        }
                    }
                }));
            }
            value$iv$iv9 = (Function1) new Function1<DisposableEffectScope, DisposableEffectResult>() { // from class: androidx.compose.foundation.FocusableKt$focusable$2$3$1
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public final DisposableEffectResult invoke(DisposableEffectScope DisposableEffect) {
                    Intrinsics.checkNotNullParameter(DisposableEffect, "$this$DisposableEffect");
                    if (FocusableKt$focusable$2.invoke$lambda$2(isFocused$delegate)) {
                        MutableState<PinnableContainer.PinnedHandle> mutableState = pinHandle$delegate;
                        PinnableContainer pinnableContainer2 = PinnableContainer.this;
                        FocusableKt$focusable$2.invoke$lambda$10(mutableState, pinnableContainer2 != null ? pinnableContainer2.pin() : null);
                    }
                    final MutableState<PinnableContainer.PinnedHandle> mutableState2 = pinHandle$delegate;
                    return new DisposableEffectResult() { // from class: androidx.compose.foundation.FocusableKt$focusable$2$3$1$invoke$$inlined$onDispose$1
                        @Override // androidx.compose.runtime.DisposableEffectResult
                        public void dispose() {
                            PinnableContainer.PinnedHandle invoke$lambda$9 = FocusableKt$focusable$2.invoke$lambda$9(MutableState.this);
                            if (invoke$lambda$9 != null) {
                                invoke$lambda$9.release();
                            }
                            FocusableKt$focusable$2.invoke$lambda$10(MutableState.this, null);
                        }
                    };
                }
            };
            $composer.updateRememberedValue(value$iv$iv9);
            $composer.endReplaceableGroup();
            EffectsKt.DisposableEffect(pinnableContainer, (Function1) value$iv$iv9, $composer, 0);
            Modifier.Companion companion22 = Modifier.Companion;
            $composer.startReplaceableGroup(511388516);
            ComposerKt.sourceInformation($composer, "CC(remember)P(1,2):Composables.kt#9igjgp");
            invalid$iv$iv = $composer.changed(isFocused$delegate) | $composer.changed(focusRequester);
            Object value$iv$iv102 = $composer.rememberedValue();
            if (!invalid$iv$iv) {
                $composer.endReplaceableGroup();
                Modifier then22 = FocusRequesterModifierKt.focusRequester(BringIntoViewRequesterKt.bringIntoViewRequester(SemanticsModifierKt.semantics$default(companion22, false, (Function1) value$iv$iv102, 1, null), bringIntoViewRequester), focusRequester).then(focusedChildModifier);
                final MutableInteractionSource mutableInteractionSource322 = this.$interactionSource;
                companion = FocusModifierKt.focusTarget(FocusChangedModifierKt.onFocusChanged(then22, new Function1<FocusState, Unit>() { // from class: androidx.compose.foundation.FocusableKt$focusable$2.5
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(FocusState focusState) {
                        invoke2(focusState);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke  reason: avoid collision after fix types in other method */
                    public final void invoke2(FocusState it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        FocusableKt$focusable$2.invoke$lambda$3(isFocused$delegate, it.isFocused());
                        if (!FocusableKt$focusable$2.invoke$lambda$2(isFocused$delegate)) {
                            PinnableContainer.PinnedHandle invoke$lambda$9 = FocusableKt$focusable$2.invoke$lambda$9(pinHandle$delegate);
                            if (invoke$lambda$9 != null) {
                                invoke$lambda$9.release();
                            }
                            FocusableKt$focusable$2.invoke$lambda$10(pinHandle$delegate, null);
                            BuildersKt__Builders_commonKt.launch$default(scope, null, null, new AnonymousClass2(focusedInteraction, mutableInteractionSource322, null), 3, null);
                            return;
                        }
                        MutableState<PinnableContainer.PinnedHandle> mutableState = pinHandle$delegate;
                        PinnableContainer pinnableContainer2 = PinnableContainer.this;
                        FocusableKt$focusable$2.invoke$lambda$10(mutableState, pinnableContainer2 != null ? pinnableContainer2.pin() : null);
                        BuildersKt__Builders_commonKt.launch$default(scope, null, null, new AnonymousClass1(focusedInteraction, mutableInteractionSource322, bringIntoViewRequester, null), 3, null);
                    }

                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* compiled from: Focusable.kt */
                    @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
                    @DebugMetadata(c = "androidx.compose.foundation.FocusableKt$focusable$2$5$1", f = "Focusable.kt", i = {1}, l = {147, 151, 154}, m = "invokeSuspend", n = {"interaction"}, s = {"L$0"})
                    /* renamed from: androidx.compose.foundation.FocusableKt$focusable$2$5$1  reason: invalid class name */
                    /* loaded from: classes.dex */
                    public static final class AnonymousClass1 extends SuspendLambda implements Function2<CoroutineScope, Continuation<? super Unit>, Object> {
                        final /* synthetic */ BringIntoViewRequester $bringIntoViewRequester;
                        final /* synthetic */ MutableState<FocusInteraction.Focus> $focusedInteraction;
                        final /* synthetic */ MutableInteractionSource $interactionSource;
                        Object L$0;
                        int label;

                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        AnonymousClass1(MutableState<FocusInteraction.Focus> mutableState, MutableInteractionSource mutableInteractionSource, BringIntoViewRequester bringIntoViewRequester, Continuation<? super AnonymousClass1> continuation) {
                            super(2, continuation);
                            this.$focusedInteraction = mutableState;
                            this.$interactionSource = mutableInteractionSource;
                            this.$bringIntoViewRequester = bringIntoViewRequester;
                        }

                        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                        public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
                            return new AnonymousClass1(this.$focusedInteraction, this.$interactionSource, this.$bringIntoViewRequester, continuation);
                        }

                        @Override // kotlin.jvm.functions.Function2
                        public final Object invoke(CoroutineScope coroutineScope, Continuation<? super Unit> continuation) {
                            return ((AnonymousClass1) create(coroutineScope, continuation)).invokeSuspend(Unit.INSTANCE);
                        }

                        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                        /*
                            Code decompiled incorrectly, please refer to instructions dump.
                            To view partially-correct add '--show-bad-code' argument
                        */
                        public final java.lang.Object invokeSuspend(java.lang.Object r10) {
                            /*
                                r9 = this;
                                java.lang.Object r0 = kotlin.coroutines.intrinsics.IntrinsicsKt.getCOROUTINE_SUSPENDED()
                                int r1 = r9.label
                                r2 = 1
                                r3 = 0
                                switch(r1) {
                                    case 0: goto L2c;
                                    case 1: goto L22;
                                    case 2: goto L19;
                                    case 3: goto L13;
                                    default: goto Lb;
                                }
                            Lb:
                                java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
                                java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
                                r10.<init>(r0)
                                throw r10
                            L13:
                                r0 = r9
                                kotlin.ResultKt.throwOnFailure(r10)
                                goto L92
                            L19:
                                r1 = r9
                                java.lang.Object r4 = r1.L$0
                                androidx.compose.foundation.interaction.FocusInteraction$Focus r4 = (androidx.compose.foundation.interaction.FocusInteraction.Focus) r4
                                kotlin.ResultKt.throwOnFailure(r10)
                                goto L7a
                            L22:
                                r1 = r9
                                r4 = 0
                                java.lang.Object r5 = r1.L$0
                                androidx.compose.runtime.MutableState r5 = (androidx.compose.runtime.MutableState) r5
                                kotlin.ResultKt.throwOnFailure(r10)
                                goto L57
                            L2c:
                                kotlin.ResultKt.throwOnFailure(r10)
                                r1 = r9
                                androidx.compose.runtime.MutableState<androidx.compose.foundation.interaction.FocusInteraction$Focus> r4 = r1.$focusedInteraction
                                java.lang.Object r4 = r4.getValue()
                                androidx.compose.foundation.interaction.FocusInteraction$Focus r4 = (androidx.compose.foundation.interaction.FocusInteraction.Focus) r4
                                if (r4 == 0) goto L5f
                                androidx.compose.foundation.interaction.MutableInteractionSource r5 = r1.$interactionSource
                                androidx.compose.runtime.MutableState<androidx.compose.foundation.interaction.FocusInteraction$Focus> r6 = r1.$focusedInteraction
                                r7 = 0
                                androidx.compose.foundation.interaction.FocusInteraction$Unfocus r8 = new androidx.compose.foundation.interaction.FocusInteraction$Unfocus
                                r8.<init>(r4)
                                r4 = r8
                                if (r5 == 0) goto L5a
                                r8 = r4
                                androidx.compose.foundation.interaction.Interaction r8 = (androidx.compose.foundation.interaction.Interaction) r8
                                r1.L$0 = r6
                                r1.label = r2
                                java.lang.Object r4 = r5.emit(r8, r1)
                                if (r4 != r0) goto L55
                                return r0
                            L55:
                                r5 = r6
                                r4 = r7
                            L57:
                                r7 = r4
                                r6 = r5
                            L5a:
                                r6.setValue(r3)
                            L5f:
                                androidx.compose.foundation.interaction.FocusInteraction$Focus r4 = new androidx.compose.foundation.interaction.FocusInteraction$Focus
                                r4.<init>()
                                androidx.compose.foundation.interaction.MutableInteractionSource r5 = r1.$interactionSource
                                if (r5 == 0) goto L7a
                                r6 = r4
                                androidx.compose.foundation.interaction.Interaction r6 = (androidx.compose.foundation.interaction.Interaction) r6
                                r7 = r1
                                kotlin.coroutines.Continuation r7 = (kotlin.coroutines.Continuation) r7
                                r1.L$0 = r4
                                r8 = 2
                                r1.label = r8
                                java.lang.Object r5 = r5.emit(r6, r7)
                                if (r5 != r0) goto L7a
                                return r0
                            L7a:
                                androidx.compose.runtime.MutableState<androidx.compose.foundation.interaction.FocusInteraction$Focus> r5 = r1.$focusedInteraction
                                r5.setValue(r4)
                                androidx.compose.foundation.relocation.BringIntoViewRequester r4 = r1.$bringIntoViewRequester
                                r5 = r1
                                kotlin.coroutines.Continuation r5 = (kotlin.coroutines.Continuation) r5
                                r1.L$0 = r3
                                r6 = 3
                                r1.label = r6
                                java.lang.Object r2 = androidx.compose.foundation.relocation.BringIntoViewRequester.bringIntoView$default(r4, r3, r5, r2, r3)
                                if (r2 != r0) goto L91
                                return r0
                            L91:
                                r0 = r1
                            L92:
                                kotlin.Unit r1 = kotlin.Unit.INSTANCE
                                return r1
                            */
                            throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.FocusableKt$focusable$2.AnonymousClass5.AnonymousClass1.invokeSuspend(java.lang.Object):java.lang.Object");
                        }
                    }

                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* compiled from: Focusable.kt */
                    @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
                    @DebugMetadata(c = "androidx.compose.foundation.FocusableKt$focusable$2$5$2", f = "Focusable.kt", i = {}, l = {162}, m = "invokeSuspend", n = {}, s = {})
                    /* renamed from: androidx.compose.foundation.FocusableKt$focusable$2$5$2  reason: invalid class name */
                    /* loaded from: classes.dex */
                    public static final class AnonymousClass2 extends SuspendLambda implements Function2<CoroutineScope, Continuation<? super Unit>, Object> {
                        final /* synthetic */ MutableState<FocusInteraction.Focus> $focusedInteraction;
                        final /* synthetic */ MutableInteractionSource $interactionSource;
                        Object L$0;
                        int label;

                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        AnonymousClass2(MutableState<FocusInteraction.Focus> mutableState, MutableInteractionSource mutableInteractionSource, Continuation<? super AnonymousClass2> continuation) {
                            super(2, continuation);
                            this.$focusedInteraction = mutableState;
                            this.$interactionSource = mutableInteractionSource;
                        }

                        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                        public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
                            return new AnonymousClass2(this.$focusedInteraction, this.$interactionSource, continuation);
                        }

                        @Override // kotlin.jvm.functions.Function2
                        public final Object invoke(CoroutineScope coroutineScope, Continuation<? super Unit> continuation) {
                            return ((AnonymousClass2) create(coroutineScope, continuation)).invokeSuspend(Unit.INSTANCE);
                        }

                        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                        public final Object invokeSuspend(Object $result) {
                            MutableState<FocusInteraction.Focus> mutableState;
                            AnonymousClass2 anonymousClass2;
                            MutableState<FocusInteraction.Focus> mutableState2;
                            boolean z;
                            Object coroutine_suspended = IntrinsicsKt.getCOROUTINE_SUSPENDED();
                            switch (this.label) {
                                case 0:
                                    ResultKt.throwOnFailure($result);
                                    FocusInteraction.Focus oldValue = this.$focusedInteraction.getValue();
                                    if (oldValue != null) {
                                        MutableInteractionSource mutableInteractionSource = this.$interactionSource;
                                        mutableState = this.$focusedInteraction;
                                        FocusInteraction.Unfocus interaction = new FocusInteraction.Unfocus(oldValue);
                                        if (mutableInteractionSource != null) {
                                            this.L$0 = mutableState;
                                            this.label = 1;
                                            if (mutableInteractionSource.emit(interaction, this) != coroutine_suspended) {
                                                anonymousClass2 = this;
                                                mutableState2 = mutableState;
                                                z = false;
                                                mutableState = mutableState2;
                                            } else {
                                                return coroutine_suspended;
                                            }
                                        }
                                        mutableState.setValue(null);
                                        break;
                                    }
                                    break;
                                case 1:
                                    anonymousClass2 = this;
                                    z = false;
                                    mutableState2 = (MutableState) anonymousClass2.L$0;
                                    ResultKt.throwOnFailure($result);
                                    mutableState = mutableState2;
                                    mutableState.setValue(null);
                                    break;
                                default:
                                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                            }
                            return Unit.INSTANCE;
                        }
                    }
                }));
            }
            value$iv$iv102 = (Function1) new Function1<SemanticsPropertyReceiver, Unit>() { // from class: androidx.compose.foundation.FocusableKt$focusable$2$4$1
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(SemanticsPropertyReceiver semanticsPropertyReceiver) {
                    invoke2(semanticsPropertyReceiver);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2(SemanticsPropertyReceiver semantics) {
                    Intrinsics.checkNotNullParameter(semantics, "$this$semantics");
                    SemanticsPropertiesKt.setFocused(semantics, FocusableKt$focusable$2.invoke$lambda$2(isFocused$delegate));
                    final FocusRequester focusRequester2 = focusRequester;
                    final MutableState<Boolean> mutableState = isFocused$delegate;
                    SemanticsPropertiesKt.requestFocus$default(semantics, null, new Function0<Boolean>() { // from class: androidx.compose.foundation.FocusableKt$focusable$2$4$1.1
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(0);
                        }

                        /* JADX WARN: Can't rename method to resolve collision */
                        @Override // kotlin.jvm.functions.Function0
                        public final Boolean invoke() {
                            FocusRequester.this.requestFocus();
                            return Boolean.valueOf(FocusableKt$focusable$2.invoke$lambda$2(mutableState));
                        }
                    }, 1, null);
                }
            };
            $composer.updateRememberedValue(value$iv$iv102);
            $composer.endReplaceableGroup();
            Modifier then222 = FocusRequesterModifierKt.focusRequester(BringIntoViewRequesterKt.bringIntoViewRequester(SemanticsModifierKt.semantics$default(companion22, false, (Function1) value$iv$iv102, 1, null), bringIntoViewRequester), focusRequester).then(focusedChildModifier);
            final MutableInteractionSource mutableInteractionSource3222 = this.$interactionSource;
            companion = FocusModifierKt.focusTarget(FocusChangedModifierKt.onFocusChanged(then222, new Function1<FocusState, Unit>() { // from class: androidx.compose.foundation.FocusableKt$focusable$2.5
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(FocusState focusState) {
                    invoke2(focusState);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2(FocusState it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                    FocusableKt$focusable$2.invoke$lambda$3(isFocused$delegate, it.isFocused());
                    if (!FocusableKt$focusable$2.invoke$lambda$2(isFocused$delegate)) {
                        PinnableContainer.PinnedHandle invoke$lambda$9 = FocusableKt$focusable$2.invoke$lambda$9(pinHandle$delegate);
                        if (invoke$lambda$9 != null) {
                            invoke$lambda$9.release();
                        }
                        FocusableKt$focusable$2.invoke$lambda$10(pinHandle$delegate, null);
                        BuildersKt__Builders_commonKt.launch$default(scope, null, null, new AnonymousClass2(focusedInteraction, mutableInteractionSource3222, null), 3, null);
                        return;
                    }
                    MutableState<PinnableContainer.PinnedHandle> mutableState = pinHandle$delegate;
                    PinnableContainer pinnableContainer2 = PinnableContainer.this;
                    FocusableKt$focusable$2.invoke$lambda$10(mutableState, pinnableContainer2 != null ? pinnableContainer2.pin() : null);
                    BuildersKt__Builders_commonKt.launch$default(scope, null, null, new AnonymousClass1(focusedInteraction, mutableInteractionSource3222, bringIntoViewRequester, null), 3, null);
                }

                /* JADX INFO: Access modifiers changed from: package-private */
                /* compiled from: Focusable.kt */
                @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
                @DebugMetadata(c = "androidx.compose.foundation.FocusableKt$focusable$2$5$1", f = "Focusable.kt", i = {1}, l = {147, 151, 154}, m = "invokeSuspend", n = {"interaction"}, s = {"L$0"})
                /* renamed from: androidx.compose.foundation.FocusableKt$focusable$2$5$1  reason: invalid class name */
                /* loaded from: classes.dex */
                public static final class AnonymousClass1 extends SuspendLambda implements Function2<CoroutineScope, Continuation<? super Unit>, Object> {
                    final /* synthetic */ BringIntoViewRequester $bringIntoViewRequester;
                    final /* synthetic */ MutableState<FocusInteraction.Focus> $focusedInteraction;
                    final /* synthetic */ MutableInteractionSource $interactionSource;
                    Object L$0;
                    int label;

                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    AnonymousClass1(MutableState<FocusInteraction.Focus> mutableState, MutableInteractionSource mutableInteractionSource, BringIntoViewRequester bringIntoViewRequester, Continuation<? super AnonymousClass1> continuation) {
                        super(2, continuation);
                        this.$focusedInteraction = mutableState;
                        this.$interactionSource = mutableInteractionSource;
                        this.$bringIntoViewRequester = bringIntoViewRequester;
                    }

                    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                    public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
                        return new AnonymousClass1(this.$focusedInteraction, this.$interactionSource, this.$bringIntoViewRequester, continuation);
                    }

                    @Override // kotlin.jvm.functions.Function2
                    public final Object invoke(CoroutineScope coroutineScope, Continuation<? super Unit> continuation) {
                        return ((AnonymousClass1) create(coroutineScope, continuation)).invokeSuspend(Unit.INSTANCE);
                    }

                    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                    /*
                        Code decompiled incorrectly, please refer to instructions dump.
                        To view partially-correct add '--show-bad-code' argument
                    */
                    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
                        /*
                            r9 = this;
                            java.lang.Object r0 = kotlin.coroutines.intrinsics.IntrinsicsKt.getCOROUTINE_SUSPENDED()
                            int r1 = r9.label
                            r2 = 1
                            r3 = 0
                            switch(r1) {
                                case 0: goto L2c;
                                case 1: goto L22;
                                case 2: goto L19;
                                case 3: goto L13;
                                default: goto Lb;
                            }
                        Lb:
                            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
                            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
                            r10.<init>(r0)
                            throw r10
                        L13:
                            r0 = r9
                            kotlin.ResultKt.throwOnFailure(r10)
                            goto L92
                        L19:
                            r1 = r9
                            java.lang.Object r4 = r1.L$0
                            androidx.compose.foundation.interaction.FocusInteraction$Focus r4 = (androidx.compose.foundation.interaction.FocusInteraction.Focus) r4
                            kotlin.ResultKt.throwOnFailure(r10)
                            goto L7a
                        L22:
                            r1 = r9
                            r4 = 0
                            java.lang.Object r5 = r1.L$0
                            androidx.compose.runtime.MutableState r5 = (androidx.compose.runtime.MutableState) r5
                            kotlin.ResultKt.throwOnFailure(r10)
                            goto L57
                        L2c:
                            kotlin.ResultKt.throwOnFailure(r10)
                            r1 = r9
                            androidx.compose.runtime.MutableState<androidx.compose.foundation.interaction.FocusInteraction$Focus> r4 = r1.$focusedInteraction
                            java.lang.Object r4 = r4.getValue()
                            androidx.compose.foundation.interaction.FocusInteraction$Focus r4 = (androidx.compose.foundation.interaction.FocusInteraction.Focus) r4
                            if (r4 == 0) goto L5f
                            androidx.compose.foundation.interaction.MutableInteractionSource r5 = r1.$interactionSource
                            androidx.compose.runtime.MutableState<androidx.compose.foundation.interaction.FocusInteraction$Focus> r6 = r1.$focusedInteraction
                            r7 = 0
                            androidx.compose.foundation.interaction.FocusInteraction$Unfocus r8 = new androidx.compose.foundation.interaction.FocusInteraction$Unfocus
                            r8.<init>(r4)
                            r4 = r8
                            if (r5 == 0) goto L5a
                            r8 = r4
                            androidx.compose.foundation.interaction.Interaction r8 = (androidx.compose.foundation.interaction.Interaction) r8
                            r1.L$0 = r6
                            r1.label = r2
                            java.lang.Object r4 = r5.emit(r8, r1)
                            if (r4 != r0) goto L55
                            return r0
                        L55:
                            r5 = r6
                            r4 = r7
                        L57:
                            r7 = r4
                            r6 = r5
                        L5a:
                            r6.setValue(r3)
                        L5f:
                            androidx.compose.foundation.interaction.FocusInteraction$Focus r4 = new androidx.compose.foundation.interaction.FocusInteraction$Focus
                            r4.<init>()
                            androidx.compose.foundation.interaction.MutableInteractionSource r5 = r1.$interactionSource
                            if (r5 == 0) goto L7a
                            r6 = r4
                            androidx.compose.foundation.interaction.Interaction r6 = (androidx.compose.foundation.interaction.Interaction) r6
                            r7 = r1
                            kotlin.coroutines.Continuation r7 = (kotlin.coroutines.Continuation) r7
                            r1.L$0 = r4
                            r8 = 2
                            r1.label = r8
                            java.lang.Object r5 = r5.emit(r6, r7)
                            if (r5 != r0) goto L7a
                            return r0
                        L7a:
                            androidx.compose.runtime.MutableState<androidx.compose.foundation.interaction.FocusInteraction$Focus> r5 = r1.$focusedInteraction
                            r5.setValue(r4)
                            androidx.compose.foundation.relocation.BringIntoViewRequester r4 = r1.$bringIntoViewRequester
                            r5 = r1
                            kotlin.coroutines.Continuation r5 = (kotlin.coroutines.Continuation) r5
                            r1.L$0 = r3
                            r6 = 3
                            r1.label = r6
                            java.lang.Object r2 = androidx.compose.foundation.relocation.BringIntoViewRequester.bringIntoView$default(r4, r3, r5, r2, r3)
                            if (r2 != r0) goto L91
                            return r0
                        L91:
                            r0 = r1
                        L92:
                            kotlin.Unit r1 = kotlin.Unit.INSTANCE
                            return r1
                        */
                        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.FocusableKt$focusable$2.AnonymousClass5.AnonymousClass1.invokeSuspend(java.lang.Object):java.lang.Object");
                    }
                }

                /* JADX INFO: Access modifiers changed from: package-private */
                /* compiled from: Focusable.kt */
                @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
                @DebugMetadata(c = "androidx.compose.foundation.FocusableKt$focusable$2$5$2", f = "Focusable.kt", i = {}, l = {162}, m = "invokeSuspend", n = {}, s = {})
                /* renamed from: androidx.compose.foundation.FocusableKt$focusable$2$5$2  reason: invalid class name */
                /* loaded from: classes.dex */
                public static final class AnonymousClass2 extends SuspendLambda implements Function2<CoroutineScope, Continuation<? super Unit>, Object> {
                    final /* synthetic */ MutableState<FocusInteraction.Focus> $focusedInteraction;
                    final /* synthetic */ MutableInteractionSource $interactionSource;
                    Object L$0;
                    int label;

                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    AnonymousClass2(MutableState<FocusInteraction.Focus> mutableState, MutableInteractionSource mutableInteractionSource, Continuation<? super AnonymousClass2> continuation) {
                        super(2, continuation);
                        this.$focusedInteraction = mutableState;
                        this.$interactionSource = mutableInteractionSource;
                    }

                    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                    public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
                        return new AnonymousClass2(this.$focusedInteraction, this.$interactionSource, continuation);
                    }

                    @Override // kotlin.jvm.functions.Function2
                    public final Object invoke(CoroutineScope coroutineScope, Continuation<? super Unit> continuation) {
                        return ((AnonymousClass2) create(coroutineScope, continuation)).invokeSuspend(Unit.INSTANCE);
                    }

                    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                    public final Object invokeSuspend(Object $result) {
                        MutableState<FocusInteraction.Focus> mutableState;
                        AnonymousClass2 anonymousClass2;
                        MutableState<FocusInteraction.Focus> mutableState2;
                        boolean z;
                        Object coroutine_suspended = IntrinsicsKt.getCOROUTINE_SUSPENDED();
                        switch (this.label) {
                            case 0:
                                ResultKt.throwOnFailure($result);
                                FocusInteraction.Focus oldValue = this.$focusedInteraction.getValue();
                                if (oldValue != null) {
                                    MutableInteractionSource mutableInteractionSource = this.$interactionSource;
                                    mutableState = this.$focusedInteraction;
                                    FocusInteraction.Unfocus interaction = new FocusInteraction.Unfocus(oldValue);
                                    if (mutableInteractionSource != null) {
                                        this.L$0 = mutableState;
                                        this.label = 1;
                                        if (mutableInteractionSource.emit(interaction, this) != coroutine_suspended) {
                                            anonymousClass2 = this;
                                            mutableState2 = mutableState;
                                            z = false;
                                            mutableState = mutableState2;
                                        } else {
                                            return coroutine_suspended;
                                        }
                                    }
                                    mutableState.setValue(null);
                                    break;
                                }
                                break;
                            case 1:
                                anonymousClass2 = this;
                                z = false;
                                mutableState2 = (MutableState) anonymousClass2.L$0;
                                ResultKt.throwOnFailure($result);
                                mutableState = mutableState2;
                                mutableState.setValue(null);
                                break;
                            default:
                                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                        }
                        return Unit.INSTANCE;
                    }
                }
            }));
        } else {
            companion = Modifier.Companion;
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return companion;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean invoke$lambda$2(MutableState<Boolean> mutableState) {
        MutableState<Boolean> $this$getValue$iv = mutableState;
        return $this$getValue$iv.getValue().booleanValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void invoke$lambda$3(MutableState<Boolean> mutableState, boolean value) {
        mutableState.setValue(Boolean.valueOf(value));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void invoke$lambda$10(MutableState<PinnableContainer.PinnedHandle> mutableState, PinnableContainer.PinnedHandle value) {
        mutableState.setValue(value);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final PinnableContainer.PinnedHandle invoke$lambda$9(MutableState<PinnableContainer.PinnedHandle> mutableState) {
        MutableState<PinnableContainer.PinnedHandle> $this$getValue$iv = mutableState;
        return $this$getValue$iv.getValue();
    }
}
