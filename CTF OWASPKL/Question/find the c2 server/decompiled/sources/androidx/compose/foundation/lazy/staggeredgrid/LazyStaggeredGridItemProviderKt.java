package androidx.compose.foundation.lazy.staggeredgrid;

import androidx.compose.foundation.lazy.layout.IntervalList;
import androidx.compose.foundation.lazy.layout.LazyLayoutItemProvider;
import androidx.compose.foundation.lazy.layout.LazyLayoutItemProviderKt;
import androidx.compose.foundation.lazy.layout.LazyLayoutPinnableItemKt;
import androidx.compose.foundation.lazy.layout.LazyNearestItemsRangeKt;
import androidx.compose.foundation.lazy.staggeredgrid.LazyStaggeredGridItemProviderKt$rememberStaggeredGridItemProvider$1$itemProviderState$1;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.SnapshotStateKt;
import androidx.compose.runtime.State;
import androidx.compose.runtime.internal.ComposableLambdaKt;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
/* compiled from: LazyStaggeredGridItemProvider.kt */
@Metadata(d1 = {"\u0000\"\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a.\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0017\u0010\u0004\u001a\u0013\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u00070\u0005¢\u0006\u0002\b\bH\u0001¢\u0006\u0002\u0010\t¨\u0006\n"}, d2 = {"rememberStaggeredGridItemProvider", "Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridItemProvider;", "state", "Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridState;", "content", "Lkotlin/Function1;", "Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridScope;", "", "Lkotlin/ExtensionFunctionType;", "(Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridState;Lkotlin/jvm/functions/Function1;Landroidx/compose/runtime/Composer;I)Landroidx/compose/foundation/lazy/staggeredgrid/LazyStaggeredGridItemProvider;", "foundation_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LazyStaggeredGridItemProviderKt {
    public static final LazyStaggeredGridItemProvider rememberStaggeredGridItemProvider(final LazyStaggeredGridState state, Function1<? super LazyStaggeredGridScope, Unit> content, Composer $composer, int $changed) {
        Object value$iv$iv;
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(content, "content");
        $composer.startReplaceableGroup(2039920307);
        ComposerKt.sourceInformation($composer, "C(rememberStaggeredGridItemProvider)P(1)39@1622L29,40@1685L175,45@1872L1186:LazyStaggeredGridItemProvider.kt#fzvcnm");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(2039920307, $changed, -1, "androidx.compose.foundation.lazy.staggeredgrid.rememberStaggeredGridItemProvider (LazyStaggeredGridItemProvider.kt:35)");
        }
        final State latestContent = SnapshotStateKt.rememberUpdatedState(content, $composer, ($changed >> 3) & 14);
        final State nearestItemsRangeState = LazyNearestItemsRangeKt.rememberLazyNearestItemsRangeState(new Function0<Integer>() { // from class: androidx.compose.foundation.lazy.staggeredgrid.LazyStaggeredGridItemProviderKt$rememberStaggeredGridItemProvider$nearestItemsRangeState$1
            /* JADX INFO: Access modifiers changed from: package-private */
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final Integer invoke() {
                return Integer.valueOf(LazyStaggeredGridState.this.getFirstVisibleItemIndex());
            }
        }, new Function0<Integer>() { // from class: androidx.compose.foundation.lazy.staggeredgrid.LazyStaggeredGridItemProviderKt$rememberStaggeredGridItemProvider$nearestItemsRangeState$2
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final Integer invoke() {
                return 90;
            }
        }, new Function0<Integer>() { // from class: androidx.compose.foundation.lazy.staggeredgrid.LazyStaggeredGridItemProviderKt$rememberStaggeredGridItemProvider$nearestItemsRangeState$3
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final Integer invoke() {
                return Integer.valueOf((int) ComposerKt.invocationKey);
            }
        }, $composer, 432);
        $composer.startReplaceableGroup(1157296644);
        ComposerKt.sourceInformation($composer, "CC(remember)P(1):Composables.kt#9igjgp");
        boolean invalid$iv$iv = $composer.changed(state);
        Object it$iv$iv = $composer.rememberedValue();
        if (invalid$iv$iv || it$iv$iv == Composer.Companion.getEmpty()) {
            State itemProviderState = SnapshotStateKt.derivedStateOf(new Function0<LazyStaggeredGridItemProviderKt$rememberStaggeredGridItemProvider$1$itemProviderState$1.AnonymousClass1>() { // from class: androidx.compose.foundation.lazy.staggeredgrid.LazyStaggeredGridItemProviderKt$rememberStaggeredGridItemProvider$1$itemProviderState$1
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                /* JADX WARN: Multi-variable type inference failed */
                {
                    super(0);
                }

                /* compiled from: LazyStaggeredGridItemProvider.kt */
                @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
                /* renamed from: androidx.compose.foundation.lazy.staggeredgrid.LazyStaggeredGridItemProviderKt$rememberStaggeredGridItemProvider$1$itemProviderState$1$1  reason: invalid class name */
                /* loaded from: classes.dex */
                public static final class AnonymousClass1 implements LazyLayoutItemProvider, LazyStaggeredGridItemProvider {
                    private final /* synthetic */ LazyLayoutItemProvider $$delegate_0;
                    private final LazyStaggeredGridSpanProvider spanProvider;

                    @Override // androidx.compose.foundation.lazy.layout.LazyLayoutItemProvider
                    public void Item(int i, Composer composer, int i2) {
                        composer.startReplaceableGroup(1163616889);
                        ComposerKt.sourceInformation(composer, "C(Item)-1@-2:LazyStaggeredGridItemProvider.kt#fzvcnm");
                        if (ComposerKt.isTraceInProgress()) {
                            ComposerKt.traceEventStart(1163616889, i2, -1, "androidx.compose.foundation.lazy.staggeredgrid.rememberStaggeredGridItemProvider.<anonymous>.<anonymous>.<no name provided>.Item (LazyStaggeredGridItemProvider.kt:-1)");
                        }
                        this.$$delegate_0.Item(i, composer, i2 & 14);
                        if (ComposerKt.isTraceInProgress()) {
                            ComposerKt.traceEventEnd();
                        }
                        composer.endReplaceableGroup();
                    }

                    @Override // androidx.compose.foundation.lazy.layout.LazyLayoutItemProvider
                    public Object getContentType(int i) {
                        return this.$$delegate_0.getContentType(i);
                    }

                    @Override // androidx.compose.foundation.lazy.layout.LazyLayoutItemProvider
                    public int getItemCount() {
                        return this.$$delegate_0.getItemCount();
                    }

                    @Override // androidx.compose.foundation.lazy.layout.LazyLayoutItemProvider
                    public Object getKey(int i) {
                        return this.$$delegate_0.getKey(i);
                    }

                    @Override // androidx.compose.foundation.lazy.layout.LazyLayoutItemProvider
                    public Map<Object, Integer> getKeyToIndexMap() {
                        return this.$$delegate_0.getKeyToIndexMap();
                    }

                    AnonymousClass1(LazyStaggeredGridScopeImpl $scope, State<IntRange> state, final LazyStaggeredGridState $state) {
                        this.$$delegate_0 = LazyLayoutItemProviderKt.LazyLayoutItemProvider($scope.getIntervals(), state.getValue(), ComposableLambdaKt.composableLambdaInstance(-364721306, true, new Function4<IntervalList.Interval<? extends LazyStaggeredGridIntervalContent>, Integer, Composer, Integer, Unit>() { // from class: androidx.compose.foundation.lazy.staggeredgrid.LazyStaggeredGridItemProviderKt.rememberStaggeredGridItemProvider.1.itemProviderState.1.1.1
                            {
                                super(4);
                            }

                            @Override // kotlin.jvm.functions.Function4
                            public /* bridge */ /* synthetic */ Unit invoke(IntervalList.Interval<? extends LazyStaggeredGridIntervalContent> interval, Integer num, Composer composer, Integer num2) {
                                invoke((IntervalList.Interval<LazyStaggeredGridIntervalContent>) interval, num.intValue(), composer, num2.intValue());
                                return Unit.INSTANCE;
                            }

                            public final void invoke(final IntervalList.Interval<LazyStaggeredGridIntervalContent> interval, int index, Composer $composer, int $changed) {
                                Intrinsics.checkNotNullParameter(interval, "interval");
                                ComposerKt.sourceInformation($composer, "CP(1)53@2305L332:LazyStaggeredGridItemProvider.kt#fzvcnm");
                                int $dirty = $changed;
                                if (($changed & 14) == 0) {
                                    $dirty |= $composer.changed(interval) ? 4 : 2;
                                }
                                if (($changed & 112) == 0) {
                                    $dirty |= $composer.changed(index) ? 32 : 16;
                                }
                                if (($dirty & 731) != 146 || !$composer.getSkipping()) {
                                    if (ComposerKt.isTraceInProgress()) {
                                        ComposerKt.traceEventStart(-364721306, $dirty, -1, "androidx.compose.foundation.lazy.staggeredgrid.rememberStaggeredGridItemProvider.<anonymous>.<anonymous>.<no name provided>.$$delegate_0.<anonymous> (LazyStaggeredGridItemProvider.kt:51)");
                                    }
                                    final int localIndex = index - interval.getStartIndex();
                                    Function1<Integer, Object> key = interval.getValue().getKey();
                                    LazyLayoutPinnableItemKt.LazyLayoutPinnableItem(key != null ? key.invoke(Integer.valueOf(localIndex)) : null, index, LazyStaggeredGridState.this.getPinnedItems$foundation_release(), ComposableLambdaKt.composableLambda($composer, 1181040114, true, new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.foundation.lazy.staggeredgrid.LazyStaggeredGridItemProviderKt.rememberStaggeredGridItemProvider.1.itemProviderState.1.1.1.1
                                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                        {
                                            super(2);
                                        }

                                        @Override // kotlin.jvm.functions.Function2
                                        public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
                                            invoke(composer, num.intValue());
                                            return Unit.INSTANCE;
                                        }

                                        public final void invoke(Composer $composer2, int $changed2) {
                                            ComposerKt.sourceInformation($composer2, "C58@2565L50:LazyStaggeredGridItemProvider.kt#fzvcnm");
                                            if (($changed2 & 11) == 2 && $composer2.getSkipping()) {
                                                $composer2.skipToGroupEnd();
                                                return;
                                            }
                                            if (ComposerKt.isTraceInProgress()) {
                                                ComposerKt.traceEventStart(1181040114, $changed2, -1, "androidx.compose.foundation.lazy.staggeredgrid.rememberStaggeredGridItemProvider.<anonymous>.<anonymous>.<no name provided>.$$delegate_0.<anonymous>.<anonymous> (LazyStaggeredGridItemProvider.kt:57)");
                                            }
                                            interval.getValue().getItem().invoke(LazyStaggeredGridItemScopeImpl.INSTANCE, Integer.valueOf(localIndex), $composer2, 6);
                                            if (ComposerKt.isTraceInProgress()) {
                                                ComposerKt.traceEventEnd();
                                            }
                                        }
                                    }), $composer, ($dirty & 112) | 3592);
                                    if (ComposerKt.isTraceInProgress()) {
                                        ComposerKt.traceEventEnd();
                                        return;
                                    }
                                    return;
                                }
                                $composer.skipToGroupEnd();
                            }
                        }));
                        this.spanProvider = new LazyStaggeredGridSpanProvider($scope.getIntervals());
                    }

                    @Override // androidx.compose.foundation.lazy.staggeredgrid.LazyStaggeredGridItemProvider
                    public LazyStaggeredGridSpanProvider getSpanProvider() {
                        return this.spanProvider;
                    }
                }

                /* JADX WARN: Can't rename method to resolve collision */
                @Override // kotlin.jvm.functions.Function0
                public final AnonymousClass1 invoke() {
                    LazyStaggeredGridScopeImpl scope = new LazyStaggeredGridScopeImpl();
                    latestContent.getValue().invoke(scope);
                    return new AnonymousClass1(scope, nearestItemsRangeState, state);
                }
            });
            value$iv$iv = new LazyStaggeredGridItemProviderKt$rememberStaggeredGridItemProvider$1$1(itemProviderState);
            $composer.updateRememberedValue(value$iv$iv);
        } else {
            value$iv$iv = it$iv$iv;
        }
        $composer.endReplaceableGroup();
        LazyStaggeredGridItemProviderKt$rememberStaggeredGridItemProvider$1$1 lazyStaggeredGridItemProviderKt$rememberStaggeredGridItemProvider$1$1 = (LazyStaggeredGridItemProviderKt$rememberStaggeredGridItemProvider$1$1) value$iv$iv;
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return lazyStaggeredGridItemProviderKt$rememberStaggeredGridItemProvider$1$1;
    }
}
