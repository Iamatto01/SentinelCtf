package androidx.compose.foundation.pager;

import androidx.compose.animation.core.AnimationSpec;
import androidx.compose.animation.core.AnimationSpecKt;
import androidx.compose.foundation.MutatePriority;
import androidx.compose.foundation.gestures.ScrollScope;
import androidx.compose.foundation.gestures.ScrollableState;
import androidx.compose.foundation.gestures.snapping.LazyListSnapLayoutInfoProviderKt;
import androidx.compose.foundation.interaction.InteractionSource;
import androidx.compose.foundation.lazy.LazyListItemInfo;
import androidx.compose.foundation.lazy.LazyListLayoutInfo;
import androidx.compose.foundation.lazy.LazyListState;
import androidx.compose.runtime.MutableState;
import androidx.compose.runtime.SnapshotStateKt;
import androidx.compose.runtime.SnapshotStateKt__SnapshotStateKt;
import androidx.compose.runtime.State;
import androidx.compose.runtime.saveable.ListSaverKt;
import androidx.compose.runtime.saveable.Saver;
import androidx.compose.runtime.saveable.SaverScope;
import androidx.compose.ui.unit.Density;
import java.util.List;
import java.util.ListIterator;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.math.MathKt;
import kotlin.ranges.RangesKt;
/* compiled from: PagerState.kt */
@Metadata(d1 = {"\u0000\u0084\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0007\n\u0002\b\n\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\"\n\u0002\u0010 \n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\b\b\u0007\u0018\u0000 y2\u00020\u0001:\u0001yB\u0019\u0012\b\b\u0002\u0010\u0002\u001a\u00020\u0003\u0012\b\b\u0002\u0010\u0004\u001a\u00020\u0005¢\u0006\u0002\u0010\u0006J3\u0010\\\u001a\u00020]2\u0006\u0010^\u001a\u00020\u00032\b\b\u0002\u0010_\u001a\u00020\u00052\u000e\b\u0002\u0010`\u001a\b\u0012\u0004\u0012\u00020\u00050aH\u0086@ø\u0001\u0000¢\u0006\u0002\u0010bJ\u0011\u0010c\u001a\u00020]H\u0082@ø\u0001\u0000¢\u0006\u0002\u0010dJ\u0010\u0010e\u001a\u00020\u00052\u0006\u0010f\u001a\u00020\u0005H\u0016J\u0015\u0010g\u001a\u00020]2\u0006\u0010h\u001a\u000206H\u0000¢\u0006\u0002\biJB\u0010j\u001a\u00020]2\u0006\u0010k\u001a\u00020l2'\u0010m\u001a#\b\u0001\u0012\u0004\u0012\u00020o\u0012\n\u0012\b\u0012\u0004\u0012\u00020]0p\u0012\u0006\u0012\u0004\u0018\u00010q0n¢\u0006\u0002\brH\u0096@ø\u0001\u0000¢\u0006\u0002\u0010sJ#\u0010t\u001a\u00020]2\u0006\u0010^\u001a\u00020\u00032\b\b\u0002\u0010_\u001a\u00020\u0005H\u0086@ø\u0001\u0000¢\u0006\u0002\u0010uJ\r\u0010v\u001a\u00020]H\u0000¢\u0006\u0002\bwJ\f\u0010x\u001a\u00020\u0003*\u00020\u0003H\u0002R+\u0010\b\u001a\u00020\u00032\u0006\u0010\u0007\u001a\u00020\u00038B@BX\u0082\u008e\u0002¢\u0006\u0012\n\u0004\b\r\u0010\u000e\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\fR\u000e\u0010\u000f\u001a\u00020\u0010X\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010\u0011\u001a\u00020\u00128VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0013\u0010\u0014R\u0014\u0010\u0015\u001a\u00020\u00128VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0016\u0010\u0014R\u0016\u0010\u0017\u001a\u0004\u0018\u00010\u00188BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u0019\u0010\u001aR\u001b\u0010\u001b\u001a\u00020\u00038FX\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u001e\u001a\u0004\b\u001c\u0010\nR\u001b\u0010\u001f\u001a\u00020\u00058FX\u0086\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010\u001e\u001a\u0004\b \u0010!R\u0014\u0010#\u001a\u00020$8BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b%\u0010&R\u0014\u0010'\u001a\u00020\u00058BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b(\u0010!R\u0016\u0010)\u001a\u0004\u0018\u00010\u00188@X\u0080\u0004¢\u0006\u0006\u001a\u0004\b*\u0010\u001aR\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b+\u0010\nR\u0011\u0010\u0004\u001a\u00020\u0005¢\u0006\b\n\u0000\u001a\u0004\b,\u0010!R\u0011\u0010-\u001a\u00020.8F¢\u0006\u0006\u001a\u0004\b/\u00100R\u0014\u00101\u001a\u00020\u00128VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b1\u0010\u0014R\u0014\u00102\u001a\u0002038@X\u0080\u0004¢\u0006\u0006\u001a\u0004\b4\u00105R/\u00107\u001a\u0004\u0018\u0001062\b\u0010\u0007\u001a\u0004\u0018\u0001068B@BX\u0082\u008e\u0002¢\u0006\u0012\n\u0004\b<\u0010\u000e\u001a\u0004\b8\u00109\"\u0004\b:\u0010;R\u0014\u0010=\u001a\u00020\u00038BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b>\u0010\nR\u0014\u0010?\u001a\u00020\u00038@X\u0080\u0004¢\u0006\u0006\u001a\u0004\b@\u0010\nR\u0014\u0010A\u001a\u00020\u00038@X\u0080\u0004¢\u0006\u0006\u001a\u0004\bB\u0010\nR+\u0010C\u001a\u00020\u00032\u0006\u0010\u0007\u001a\u00020\u00038@@@X\u0080\u008e\u0002¢\u0006\u0012\n\u0004\bF\u0010\u000e\u001a\u0004\bD\u0010\n\"\u0004\bE\u0010\fR\u0014\u0010G\u001a\u00020\u00058BX\u0082\u0004¢\u0006\u0006\u001a\u0004\bH\u0010!R\u001b\u0010I\u001a\u00020\u00038FX\u0086\u0084\u0002¢\u0006\f\n\u0004\bK\u0010\u001e\u001a\u0004\bJ\u0010\nR+\u0010L\u001a\u00020\u00032\u0006\u0010\u0007\u001a\u00020\u00038B@BX\u0082\u008e\u0002¢\u0006\u0012\n\u0004\bO\u0010\u000e\u001a\u0004\bM\u0010\n\"\u0004\bN\u0010\fR+\u0010P\u001a\u00020\u00052\u0006\u0010\u0007\u001a\u00020\u00058@@@X\u0080\u008e\u0002¢\u0006\u0012\n\u0004\bT\u0010\u000e\u001a\u0004\bQ\u0010!\"\u0004\bR\u0010SR\u001b\u0010U\u001a\u00020\u00038FX\u0086\u0084\u0002¢\u0006\f\n\u0004\bW\u0010\u001e\u001a\u0004\bV\u0010\nR\u001a\u0010X\u001a\b\u0012\u0004\u0012\u00020\u00180Y8BX\u0082\u0004¢\u0006\u0006\u001a\u0004\bZ\u0010[\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006z"}, d2 = {"Landroidx/compose/foundation/pager/PagerState;", "Landroidx/compose/foundation/gestures/ScrollableState;", "initialPage", "", "initialPageOffsetFraction", "", "(IF)V", "<set-?>", "animationTargetPage", "getAnimationTargetPage", "()I", "setAnimationTargetPage", "(I)V", "animationTargetPage$delegate", "Landroidx/compose/runtime/MutableState;", "awaitLazyListStateSet", "Landroidx/compose/foundation/pager/AwaitLazyListStateSet;", "canScrollBackward", "", "getCanScrollBackward", "()Z", "canScrollForward", "getCanScrollForward", "closestPageToSnappedPosition", "Landroidx/compose/foundation/lazy/LazyListItemInfo;", "getClosestPageToSnappedPosition", "()Landroidx/compose/foundation/lazy/LazyListItemInfo;", "currentPage", "getCurrentPage", "currentPage$delegate", "Landroidx/compose/runtime/State;", "currentPageOffsetFraction", "getCurrentPageOffsetFraction", "()F", "currentPageOffsetFraction$delegate", "density", "Landroidx/compose/ui/unit/Density;", "getDensity", "()Landroidx/compose/ui/unit/Density;", "distanceToSnapPosition", "getDistanceToSnapPosition", "firstVisiblePage", "getFirstVisiblePage$foundation_release", "getInitialPage", "getInitialPageOffsetFraction", "interactionSource", "Landroidx/compose/foundation/interaction/InteractionSource;", "getInteractionSource", "()Landroidx/compose/foundation/interaction/InteractionSource;", "isScrollInProgress", "layoutInfo", "Landroidx/compose/foundation/lazy/LazyListLayoutInfo;", "getLayoutInfo$foundation_release", "()Landroidx/compose/foundation/lazy/LazyListLayoutInfo;", "Landroidx/compose/foundation/lazy/LazyListState;", "lazyListState", "getLazyListState", "()Landroidx/compose/foundation/lazy/LazyListState;", "setLazyListState", "(Landroidx/compose/foundation/lazy/LazyListState;)V", "lazyListState$delegate", "pageAvailableSpace", "getPageAvailableSpace", "pageCount", "getPageCount$foundation_release", "pageSize", "getPageSize$foundation_release", "pageSpacing", "getPageSpacing$foundation_release", "setPageSpacing$foundation_release", "pageSpacing$delegate", "positionThresholdFraction", "getPositionThresholdFraction", "settledPage", "getSettledPage", "settledPage$delegate", "settledPageState", "getSettledPageState", "setSettledPageState", "settledPageState$delegate", "snapRemainingScrollOffset", "getSnapRemainingScrollOffset$foundation_release", "setSnapRemainingScrollOffset$foundation_release", "(F)V", "snapRemainingScrollOffset$delegate", "targetPage", "getTargetPage", "targetPage$delegate", "visiblePages", "", "getVisiblePages", "()Ljava/util/List;", "animateScrollToPage", "", "page", "pageOffsetFraction", "animationSpec", "Landroidx/compose/animation/core/AnimationSpec;", "(IFLandroidx/compose/animation/core/AnimationSpec;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "awaitScrollDependencies", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "dispatchRawDelta", "delta", "loadNewState", "newState", "loadNewState$foundation_release", "scroll", "scrollPriority", "Landroidx/compose/foundation/MutatePriority;", "block", "Lkotlin/Function2;", "Landroidx/compose/foundation/gestures/ScrollScope;", "Lkotlin/coroutines/Continuation;", "", "Lkotlin/ExtensionFunctionType;", "(Landroidx/compose/foundation/MutatePriority;Lkotlin/jvm/functions/Function2;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "scrollToPage", "(IFLkotlin/coroutines/Continuation;)Ljava/lang/Object;", "updateOnScrollStopped", "updateOnScrollStopped$foundation_release", "coerceInPageRange", "Companion", "foundation_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class PagerState implements ScrollableState {
    public static final int $stable = 0;
    public static final Companion Companion = new Companion(null);
    private static final Saver<PagerState, ?> Saver = ListSaverKt.listSaver(new Function2<SaverScope, PagerState, List<? extends Object>>() { // from class: androidx.compose.foundation.pager.PagerState$Companion$Saver$1
        @Override // kotlin.jvm.functions.Function2
        public final List<Object> invoke(SaverScope listSaver, PagerState it) {
            Intrinsics.checkNotNullParameter(listSaver, "$this$listSaver");
            Intrinsics.checkNotNullParameter(it, "it");
            return CollectionsKt.listOf(Integer.valueOf(it.getCurrentPage()), Float.valueOf(it.getCurrentPageOffsetFraction()));
        }
    }, new Function1<List, PagerState>() { // from class: androidx.compose.foundation.pager.PagerState$Companion$Saver$2
        @Override // kotlin.jvm.functions.Function1
        public /* bridge */ /* synthetic */ PagerState invoke(List list) {
            return invoke2((List<? extends Object>) list);
        }

        /* renamed from: invoke  reason: avoid collision after fix types in other method */
        public final PagerState invoke2(List<? extends Object> it) {
            Intrinsics.checkNotNullParameter(it, "it");
            Object obj = it.get(0);
            Intrinsics.checkNotNull(obj, "null cannot be cast to non-null type kotlin.Int");
            int intValue = ((Integer) obj).intValue();
            Object obj2 = it.get(1);
            Intrinsics.checkNotNull(obj2, "null cannot be cast to non-null type kotlin.Float");
            return new PagerState(intValue, ((Float) obj2).floatValue());
        }
    });
    private final MutableState animationTargetPage$delegate;
    private final AwaitLazyListStateSet awaitLazyListStateSet;
    private final State currentPage$delegate;
    private final State currentPageOffsetFraction$delegate;
    private final int initialPage;
    private final float initialPageOffsetFraction;
    private final MutableState lazyListState$delegate;
    private final MutableState pageSpacing$delegate;
    private final State settledPage$delegate;
    private final MutableState settledPageState$delegate;
    private final MutableState snapRemainingScrollOffset$delegate;
    private final State targetPage$delegate;

    public PagerState() {
        this(0, 0.0f, 3, null);
    }

    public PagerState(int initialPage, float initialPageOffsetFraction) {
        MutableState mutableStateOf$default;
        MutableState mutableStateOf$default2;
        MutableState mutableStateOf$default3;
        MutableState mutableStateOf$default4;
        MutableState mutableStateOf$default5;
        this.initialPage = initialPage;
        this.initialPageOffsetFraction = initialPageOffsetFraction;
        double d = initialPageOffsetFraction;
        if (-0.5d <= d && d <= 0.5d) {
            mutableStateOf$default = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(Float.valueOf(0.0f), null, 2, null);
            this.snapRemainingScrollOffset$delegate = mutableStateOf$default;
            mutableStateOf$default2 = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(null, null, 2, null);
            this.lazyListState$delegate = mutableStateOf$default2;
            mutableStateOf$default3 = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(0, null, 2, null);
            this.pageSpacing$delegate = mutableStateOf$default3;
            this.awaitLazyListStateSet = new AwaitLazyListStateSet();
            this.currentPage$delegate = SnapshotStateKt.derivedStateOf(new Function0<Integer>() { // from class: androidx.compose.foundation.pager.PagerState$currentPage$2
                /* JADX INFO: Access modifiers changed from: package-private */
                {
                    super(0);
                }

                /* JADX WARN: Can't rename method to resolve collision */
                @Override // kotlin.jvm.functions.Function0
                public final Integer invoke() {
                    LazyListItemInfo closestPageToSnappedPosition;
                    closestPageToSnappedPosition = PagerState.this.getClosestPageToSnappedPosition();
                    return Integer.valueOf(closestPageToSnappedPosition != null ? closestPageToSnappedPosition.getIndex() : PagerState.this.getInitialPage());
                }
            });
            mutableStateOf$default4 = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(-1, null, 2, null);
            this.animationTargetPage$delegate = mutableStateOf$default4;
            mutableStateOf$default5 = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(Integer.valueOf(initialPage), null, 2, null);
            this.settledPageState$delegate = mutableStateOf$default5;
            this.settledPage$delegate = SnapshotStateKt.derivedStateOf(new Function0<Integer>() { // from class: androidx.compose.foundation.pager.PagerState$settledPage$2
                /* JADX INFO: Access modifiers changed from: package-private */
                {
                    super(0);
                }

                /* JADX WARN: Can't rename method to resolve collision */
                @Override // kotlin.jvm.functions.Function0
                public final Integer invoke() {
                    int settledPageState;
                    int coerceInPageRange;
                    if (PagerState.this.getPageCount$foundation_release() == 0) {
                        coerceInPageRange = 0;
                    } else {
                        PagerState pagerState = PagerState.this;
                        settledPageState = pagerState.getSettledPageState();
                        coerceInPageRange = pagerState.coerceInPageRange(settledPageState);
                    }
                    return Integer.valueOf(coerceInPageRange);
                }
            });
            this.targetPage$delegate = SnapshotStateKt.derivedStateOf(new Function0<Integer>() { // from class: androidx.compose.foundation.pager.PagerState$targetPage$2
                /* JADX INFO: Access modifiers changed from: package-private */
                {
                    super(0);
                }

                /* JADX WARN: Can't rename method to resolve collision */
                @Override // kotlin.jvm.functions.Function0
                public final Integer invoke() {
                    int animationTargetPage;
                    int pageAvailableSpace;
                    int finalPage;
                    float positionThresholdFraction;
                    int coerceInPageRange;
                    if (PagerState.this.isScrollInProgress()) {
                        animationTargetPage = PagerState.this.getAnimationTargetPage();
                        if (animationTargetPage != -1) {
                            finalPage = PagerState.this.getAnimationTargetPage();
                        } else {
                            if (PagerState.this.getSnapRemainingScrollOffset$foundation_release() == 0.0f) {
                                float abs = Math.abs(PagerState.this.getCurrentPageOffsetFraction());
                                positionThresholdFraction = PagerState.this.getPositionThresholdFraction();
                                if (abs >= Math.abs(positionThresholdFraction)) {
                                    finalPage = PagerState.this.getCurrentPage() + ((int) Math.signum(PagerState.this.getCurrentPageOffsetFraction()));
                                } else {
                                    finalPage = PagerState.this.getCurrentPage();
                                }
                            } else {
                                float snapRemainingScrollOffset$foundation_release = PagerState.this.getSnapRemainingScrollOffset$foundation_release();
                                pageAvailableSpace = PagerState.this.getPageAvailableSpace();
                                float pageDisplacement = snapRemainingScrollOffset$foundation_release / pageAvailableSpace;
                                finalPage = PagerState.this.getCurrentPage() + MathKt.roundToInt(pageDisplacement);
                            }
                        }
                    } else {
                        finalPage = PagerState.this.getCurrentPage();
                    }
                    coerceInPageRange = PagerState.this.coerceInPageRange(finalPage);
                    return Integer.valueOf(coerceInPageRange);
                }
            });
            this.currentPageOffsetFraction$delegate = SnapshotStateKt.derivedStateOf(new Function0<Float>() { // from class: androidx.compose.foundation.pager.PagerState$currentPageOffsetFraction$2
                /* JADX INFO: Access modifiers changed from: package-private */
                {
                    super(0);
                }

                /* JADX WARN: Can't rename method to resolve collision */
                @Override // kotlin.jvm.functions.Function0
                public final Float invoke() {
                    LazyListItemInfo closestPageToSnappedPosition;
                    int pageAvailableSpace;
                    float coerceIn;
                    closestPageToSnappedPosition = PagerState.this.getClosestPageToSnappedPosition();
                    int currentPagePositionOffset = closestPageToSnappedPosition != null ? closestPageToSnappedPosition.getOffset() : 0;
                    pageAvailableSpace = PagerState.this.getPageAvailableSpace();
                    float pageUsedSpace = pageAvailableSpace;
                    if (pageUsedSpace == 0.0f) {
                        coerceIn = PagerState.this.getInitialPageOffsetFraction();
                    } else {
                        coerceIn = RangesKt.coerceIn((-currentPagePositionOffset) / pageUsedSpace, -0.5f, 0.5f);
                    }
                    return Float.valueOf(coerceIn);
                }
            });
            return;
        }
        throw new IllegalArgumentException(("initialPageOffsetFraction " + initialPageOffsetFraction + " is not within the range -0.5 to 0.5").toString());
    }

    public /* synthetic */ PagerState(int i, float f, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? 0 : i, (i2 & 2) != 0 ? 0.0f : f);
    }

    public final int getInitialPage() {
        return this.initialPage;
    }

    public final float getInitialPageOffsetFraction() {
        return this.initialPageOffsetFraction;
    }

    public final float getSnapRemainingScrollOffset$foundation_release() {
        State $this$getValue$iv = this.snapRemainingScrollOffset$delegate;
        return ((Number) $this$getValue$iv.getValue()).floatValue();
    }

    public final void setSnapRemainingScrollOffset$foundation_release(float f) {
        MutableState $this$setValue$iv = this.snapRemainingScrollOffset$delegate;
        $this$setValue$iv.setValue(Float.valueOf(f));
    }

    private final LazyListState getLazyListState() {
        State $this$getValue$iv = this.lazyListState$delegate;
        return (LazyListState) $this$getValue$iv.getValue();
    }

    private final void setLazyListState(LazyListState lazyListState) {
        MutableState $this$setValue$iv = this.lazyListState$delegate;
        $this$setValue$iv.setValue(lazyListState);
    }

    public final int getPageSpacing$foundation_release() {
        State $this$getValue$iv = this.pageSpacing$delegate;
        return ((Number) $this$getValue$iv.getValue()).intValue();
    }

    public final void setPageSpacing$foundation_release(int i) {
        MutableState $this$setValue$iv = this.pageSpacing$delegate;
        $this$setValue$iv.setValue(Integer.valueOf(i));
    }

    public final int getPageSize$foundation_release() {
        LazyListItemInfo lazyListItemInfo = (LazyListItemInfo) CollectionsKt.firstOrNull((List<? extends Object>) getVisiblePages());
        if (lazyListItemInfo != null) {
            return lazyListItemInfo.getSize();
        }
        return 0;
    }

    private final Density getDensity() {
        Density density$foundation_release;
        LazyListState lazyListState = getLazyListState();
        return (lazyListState == null || (density$foundation_release = lazyListState.getDensity$foundation_release()) == null) ? PagerStateKt.access$getUnitDensity$p() : density$foundation_release;
    }

    public final LazyListLayoutInfo getLayoutInfo$foundation_release() {
        LazyListLayoutInfo layoutInfo;
        LazyListState lazyListState = getLazyListState();
        return (lazyListState == null || (layoutInfo = lazyListState.getLayoutInfo()) == null) ? PagerStateKt.access$getEmptyLayoutInfo$p() : layoutInfo;
    }

    private final List<LazyListItemInfo> getVisiblePages() {
        return getLayoutInfo$foundation_release().getVisibleItemsInfo();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final int getPageAvailableSpace() {
        return getPageSize$foundation_release() + getPageSpacing$foundation_release();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final float getPositionThresholdFraction() {
        Density $this$_get_positionThresholdFraction__u24lambda_u241 = getDensity();
        float minThreshold = Math.min($this$_get_positionThresholdFraction__u24lambda_u241.mo301toPx0680j_4(PagerStateKt.getDefaultPositionThreshold()), getPageSize$foundation_release() / 2.0f);
        return minThreshold / getPageSize$foundation_release();
    }

    public final int getPageCount$foundation_release() {
        return getLayoutInfo$foundation_release().getTotalItemsCount();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final LazyListItemInfo getClosestPageToSnappedPosition() {
        Object maxElem$iv;
        List $this$fastMaxBy$iv = getVisiblePages();
        if ($this$fastMaxBy$iv.isEmpty()) {
            maxElem$iv = null;
        } else {
            maxElem$iv = $this$fastMaxBy$iv.get(0);
            LazyListItemInfo it = (LazyListItemInfo) maxElem$iv;
            float maxValue$iv = -Math.abs(LazyListSnapLayoutInfoProviderKt.calculateDistanceToDesiredSnapPosition(getDensity(), getLayoutInfo$foundation_release(), it, PagerStateKt.getSnapAlignmentStartToStart()));
            int i$iv = 1;
            int lastIndex = CollectionsKt.getLastIndex($this$fastMaxBy$iv);
            if (1 <= lastIndex) {
                while (true) {
                    Object e$iv = $this$fastMaxBy$iv.get(i$iv);
                    LazyListItemInfo it2 = (LazyListItemInfo) e$iv;
                    float v$iv = -Math.abs(LazyListSnapLayoutInfoProviderKt.calculateDistanceToDesiredSnapPosition(getDensity(), getLayoutInfo$foundation_release(), it2, PagerStateKt.getSnapAlignmentStartToStart()));
                    if (Float.compare(maxValue$iv, v$iv) < 0) {
                        maxElem$iv = e$iv;
                        maxValue$iv = v$iv;
                    }
                    if (i$iv == lastIndex) {
                        break;
                    }
                    i$iv++;
                }
            }
        }
        return (LazyListItemInfo) maxElem$iv;
    }

    public final LazyListItemInfo getFirstVisiblePage$foundation_release() {
        Object element$iv;
        boolean z;
        List $this$lastOrNull$iv = getVisiblePages();
        ListIterator iterator$iv = $this$lastOrNull$iv.listIterator($this$lastOrNull$iv.size());
        while (true) {
            if (iterator$iv.hasPrevious()) {
                element$iv = iterator$iv.previous();
                LazyListItemInfo it = (LazyListItemInfo) element$iv;
                if (LazyListSnapLayoutInfoProviderKt.calculateDistanceToDesiredSnapPosition(getDensity(), getLayoutInfo$foundation_release(), it, PagerStateKt.getSnapAlignmentStartToStart()) <= 0.0f) {
                    z = true;
                    continue;
                } else {
                    z = false;
                    continue;
                }
                if (z) {
                    break;
                }
            } else {
                element$iv = null;
                break;
            }
        }
        return (LazyListItemInfo) element$iv;
    }

    private final float getDistanceToSnapPosition() {
        LazyListItemInfo it = getClosestPageToSnappedPosition();
        if (it != null) {
            return LazyListSnapLayoutInfoProviderKt.calculateDistanceToDesiredSnapPosition(getDensity(), getLayoutInfo$foundation_release(), it, PagerStateKt.getSnapAlignmentStartToStart());
        }
        return 0.0f;
    }

    public final InteractionSource getInteractionSource() {
        InteractionSource interactionSource;
        LazyListState lazyListState = getLazyListState();
        return (lazyListState == null || (interactionSource = lazyListState.getInteractionSource()) == null) ? PagerStateKt.access$getEmptyInteractionSources$p() : interactionSource;
    }

    public final int getCurrentPage() {
        State $this$getValue$iv = this.currentPage$delegate;
        return ((Number) $this$getValue$iv.getValue()).intValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final int getAnimationTargetPage() {
        State $this$getValue$iv = this.animationTargetPage$delegate;
        return ((Number) $this$getValue$iv.getValue()).intValue();
    }

    private final void setAnimationTargetPage(int i) {
        MutableState $this$setValue$iv = this.animationTargetPage$delegate;
        $this$setValue$iv.setValue(Integer.valueOf(i));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final int getSettledPageState() {
        State $this$getValue$iv = this.settledPageState$delegate;
        return ((Number) $this$getValue$iv.getValue()).intValue();
    }

    private final void setSettledPageState(int i) {
        MutableState $this$setValue$iv = this.settledPageState$delegate;
        $this$setValue$iv.setValue(Integer.valueOf(i));
    }

    public final int getSettledPage() {
        State $this$getValue$iv = this.settledPage$delegate;
        return ((Number) $this$getValue$iv.getValue()).intValue();
    }

    public final int getTargetPage() {
        State $this$getValue$iv = this.targetPage$delegate;
        return ((Number) $this$getValue$iv.getValue()).intValue();
    }

    public final float getCurrentPageOffsetFraction() {
        State $this$getValue$iv = this.currentPageOffsetFraction$delegate;
        return ((Number) $this$getValue$iv.getValue()).floatValue();
    }

    public static /* synthetic */ Object scrollToPage$default(PagerState pagerState, int i, float f, Continuation continuation, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            f = 0.0f;
        }
        return pagerState.scrollToPage(i, f, continuation);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0026  */
    /* JADX WARN: Removed duplicated region for block: B:12:0x002e  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x0032  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x003e  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0069  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0099  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object scrollToPage(int r12, float r13, kotlin.coroutines.Continuation<? super kotlin.Unit> r14) {
        /*
            r11 = this;
            boolean r0 = r14 instanceof androidx.compose.foundation.pager.PagerState$scrollToPage$1
            if (r0 == 0) goto L14
            r0 = r14
            androidx.compose.foundation.pager.PagerState$scrollToPage$1 r0 = (androidx.compose.foundation.pager.PagerState$scrollToPage$1) r0
            int r1 = r0.label
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r1 = r1 & r2
            if (r1 == 0) goto L14
            int r14 = r0.label
            int r14 = r14 - r2
            r0.label = r14
            goto L19
        L14:
            androidx.compose.foundation.pager.PagerState$scrollToPage$1 r0 = new androidx.compose.foundation.pager.PagerState$scrollToPage$1
            r0.<init>(r11, r14)
        L19:
            r14 = r0
            java.lang.Object r0 = r14.result
            java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r14.label
            r3 = 1
            switch(r2) {
                case 0: goto L3e;
                case 1: goto L32;
                case 2: goto L2e;
                default: goto L26;
            }
        L26:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r13 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r13)
            throw r12
        L2e:
            kotlin.ResultKt.throwOnFailure(r0)
            goto L8a
        L32:
            float r12 = r14.F$0
            int r13 = r14.I$0
            java.lang.Object r2 = r14.L$0
            androidx.compose.foundation.pager.PagerState r2 = (androidx.compose.foundation.pager.PagerState) r2
            kotlin.ResultKt.throwOnFailure(r0)
            goto L57
        L3e:
            kotlin.ResultKt.throwOnFailure(r0)
            r2 = r11
            r4 = 0
            r14.L$0 = r2
            r14.I$0 = r12
            r14.F$0 = r13
            r14.label = r3
            java.lang.Object r4 = r2.awaitScrollDependencies(r14)
            if (r4 != r1) goto L54
            return r1
        L54:
            r10 = r13
            r13 = r12
            r12 = r10
        L57:
            double r4 = (double) r12
            r6 = -4620693217682128896(0xbfe0000000000000, double:-0.5)
            int r6 = (r6 > r4 ? 1 : (r6 == r4 ? 0 : -1))
            r7 = 0
            if (r6 > 0) goto L66
            r8 = 4602678819172646912(0x3fe0000000000000, double:0.5)
            int r4 = (r4 > r8 ? 1 : (r4 == r8 ? 0 : -1))
            if (r4 > 0) goto L66
            goto L67
        L66:
            r3 = r7
        L67:
            if (r3 == 0) goto L99
            int r13 = r2.coerceInPageRange(r13)
            int r3 = r2.getPageAvailableSpace()
            float r3 = (float) r3
            float r3 = r3 * r12
            int r12 = kotlin.math.MathKt.roundToInt(r3)
            androidx.compose.foundation.lazy.LazyListState r2 = r2.getLazyListState()
            if (r2 == 0) goto L8d
            r3 = 0
            r14.L$0 = r3
            r3 = 2
            r14.label = r3
            java.lang.Object r12 = r2.scrollToItem(r13, r12, r14)
            if (r12 != r1) goto L8a
            return r1
        L8a:
            kotlin.Unit r12 = kotlin.Unit.INSTANCE
            return r12
        L8d:
            java.lang.IllegalArgumentException r1 = new java.lang.IllegalArgumentException
            java.lang.String r2 = "Required value was null."
            java.lang.String r2 = r2.toString()
            r1.<init>(r2)
            throw r1
        L99:
            r13 = 0
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            java.lang.String r2 = "pageOffsetFraction "
            java.lang.StringBuilder r1 = r1.append(r2)
            java.lang.StringBuilder r1 = r1.append(r12)
            java.lang.String r2 = " is not within the range -0.5 to 0.5"
            java.lang.StringBuilder r1 = r1.append(r2)
            java.lang.String r12 = r1.toString()
            java.lang.IllegalArgumentException r13 = new java.lang.IllegalArgumentException
            java.lang.String r12 = r12.toString()
            r13.<init>(r12)
            throw r13
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.pager.PagerState.scrollToPage(int, float, kotlin.coroutines.Continuation):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ Object animateScrollToPage$default(PagerState pagerState, int i, float f, AnimationSpec animationSpec, Continuation continuation, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            f = 0.0f;
        }
        if ((i2 & 4) != 0) {
            animationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, null, 5, null);
        }
        return pagerState.animateScrollToPage(i, f, animationSpec, continuation);
    }

    /* JADX WARN: Code restructure failed: missing block: B:35:0x00d7, code lost:
        if (r2 < r3) goto L32;
     */
    /* JADX WARN: Removed duplicated region for block: B:10:0x0030  */
    /* JADX WARN: Removed duplicated region for block: B:12:0x0038  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x0041  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0054  */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0067  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x00a2  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0164  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x017b  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0185  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object animateScrollToPage(int r17, float r18, androidx.compose.animation.core.AnimationSpec<java.lang.Float> r19, kotlin.coroutines.Continuation<? super kotlin.Unit> r20) {
        /*
            Method dump skipped, instructions count: 438
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.pager.PagerState.animateScrollToPage(int, float, androidx.compose.animation.core.AnimationSpec, kotlin.coroutines.Continuation):java.lang.Object");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:10:0x0025  */
    /* JADX WARN: Removed duplicated region for block: B:12:0x002d  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x0031  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0039  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0052  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0066  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object awaitScrollDependencies(kotlin.coroutines.Continuation<? super kotlin.Unit> r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof androidx.compose.foundation.pager.PagerState$awaitScrollDependencies$1
            if (r0 == 0) goto L14
            r0 = r6
            androidx.compose.foundation.pager.PagerState$awaitScrollDependencies$1 r0 = (androidx.compose.foundation.pager.PagerState$awaitScrollDependencies$1) r0
            int r1 = r0.label
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r1 = r1 & r2
            if (r1 == 0) goto L14
            int r6 = r0.label
            int r6 = r6 - r2
            r0.label = r6
            goto L19
        L14:
            androidx.compose.foundation.pager.PagerState$awaitScrollDependencies$1 r0 = new androidx.compose.foundation.pager.PagerState$awaitScrollDependencies$1
            r0.<init>(r5, r6)
        L19:
            r6 = r0
            java.lang.Object r0 = r6.result
            java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r6.label
            switch(r2) {
                case 0: goto L39;
                case 1: goto L31;
                case 2: goto L2d;
                default: goto L25;
            }
        L25:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L2d:
            kotlin.ResultKt.throwOnFailure(r0)
            goto L63
        L31:
            java.lang.Object r2 = r6.L$0
            androidx.compose.foundation.pager.PagerState r2 = (androidx.compose.foundation.pager.PagerState) r2
            kotlin.ResultKt.throwOnFailure(r0)
            goto L4b
        L39:
            kotlin.ResultKt.throwOnFailure(r0)
            r2 = r5
            androidx.compose.foundation.pager.AwaitLazyListStateSet r3 = r2.awaitLazyListStateSet
            r6.L$0 = r2
            r4 = 1
            r6.label = r4
            java.lang.Object r3 = r3.waitFinalLazyListSetting(r6)
            if (r3 != r1) goto L4b
            return r1
        L4b:
            androidx.compose.foundation.lazy.LazyListState r2 = r2.getLazyListState()
            if (r2 == 0) goto L66
            androidx.compose.foundation.lazy.AwaitFirstLayoutModifier r2 = r2.getAwaitLayoutModifier$foundation_release()
            r3 = 0
            r6.L$0 = r3
            r3 = 2
            r6.label = r3
            java.lang.Object r2 = r2.waitForFirstLayout(r6)
            if (r2 != r1) goto L63
            return r1
        L63:
            kotlin.Unit r1 = kotlin.Unit.INSTANCE
            return r1
        L66:
            java.lang.IllegalArgumentException r1 = new java.lang.IllegalArgumentException
            java.lang.String r2 = "Required value was null."
            java.lang.String r2 = r2.toString()
            r1.<init>(r2)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.pager.PagerState.awaitScrollDependencies(kotlin.coroutines.Continuation):java.lang.Object");
    }

    @Override // androidx.compose.foundation.gestures.ScrollableState
    public Object scroll(MutatePriority scrollPriority, Function2<? super ScrollScope, ? super Continuation<? super Unit>, ? extends Object> function2, Continuation<? super Unit> continuation) {
        Object scroll;
        LazyListState lazyListState = getLazyListState();
        return (lazyListState == null || (scroll = lazyListState.scroll(scrollPriority, function2, continuation)) != IntrinsicsKt.getCOROUTINE_SUSPENDED()) ? Unit.INSTANCE : scroll;
    }

    @Override // androidx.compose.foundation.gestures.ScrollableState
    public float dispatchRawDelta(float delta) {
        LazyListState lazyListState = getLazyListState();
        if (lazyListState != null) {
            return lazyListState.dispatchRawDelta(delta);
        }
        return 0.0f;
    }

    @Override // androidx.compose.foundation.gestures.ScrollableState
    public boolean isScrollInProgress() {
        LazyListState lazyListState = getLazyListState();
        if (lazyListState != null) {
            return lazyListState.isScrollInProgress();
        }
        return false;
    }

    @Override // androidx.compose.foundation.gestures.ScrollableState
    public boolean getCanScrollForward() {
        LazyListState lazyListState = getLazyListState();
        if (lazyListState != null) {
            return lazyListState.getCanScrollForward();
        }
        return true;
    }

    @Override // androidx.compose.foundation.gestures.ScrollableState
    public boolean getCanScrollBackward() {
        LazyListState lazyListState = getLazyListState();
        if (lazyListState != null) {
            return lazyListState.getCanScrollBackward();
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final int coerceInPageRange(int $this$coerceInPageRange) {
        if (getPageCount$foundation_release() > 0) {
            return RangesKt.coerceIn($this$coerceInPageRange, 0, getPageCount$foundation_release() - 1);
        }
        return 0;
    }

    public final void updateOnScrollStopped$foundation_release() {
        setSettledPageState(getCurrentPage());
    }

    public final void loadNewState$foundation_release(LazyListState newState) {
        Intrinsics.checkNotNullParameter(newState, "newState");
        setLazyListState(newState);
        this.awaitLazyListStateSet.onStateLoaded();
    }

    /* compiled from: PagerState.kt */
    @Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u001b\u0010\u0003\u001a\f\u0012\u0004\u0012\u00020\u0005\u0012\u0002\b\u00030\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0006\u0010\u0007¨\u0006\b"}, d2 = {"Landroidx/compose/foundation/pager/PagerState$Companion;", "", "()V", "Saver", "Landroidx/compose/runtime/saveable/Saver;", "Landroidx/compose/foundation/pager/PagerState;", "getSaver", "()Landroidx/compose/runtime/saveable/Saver;", "foundation_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        public final Saver<PagerState, ?> getSaver() {
            return PagerState.Saver;
        }
    }
}
