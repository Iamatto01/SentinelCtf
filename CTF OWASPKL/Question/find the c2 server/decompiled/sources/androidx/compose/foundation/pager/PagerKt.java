package androidx.compose.foundation.pager;

import androidx.autofill.HintConstants;
import androidx.compose.animation.core.DecayAnimationSpec;
import androidx.compose.animation.core.DecayAnimationSpecKt;
import androidx.compose.foundation.gestures.Orientation;
import androidx.compose.foundation.gestures.snapping.LazyListSnapLayoutInfoProviderKt;
import androidx.compose.foundation.gestures.snapping.SnapFlingBehavior;
import androidx.compose.foundation.gestures.snapping.SnapLayoutInfoProvider;
import androidx.compose.foundation.layout.PaddingKt;
import androidx.compose.foundation.layout.PaddingValues;
import androidx.compose.foundation.lazy.LazyListItemInfo;
import androidx.compose.foundation.lazy.LazyListLayoutInfo;
import androidx.compose.foundation.pager.PageSize;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.CompositionScopedCoroutineScopeCanceller;
import androidx.compose.runtime.EffectsKt;
import androidx.compose.runtime.RecomposeScopeImplKt;
import androidx.compose.runtime.ScopeUpdateScope;
import androidx.compose.ui.Alignment;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection;
import androidx.compose.ui.semantics.SemanticsModifierKt;
import androidx.compose.ui.semantics.SemanticsPropertiesKt;
import androidx.compose.ui.semantics.SemanticsPropertyReceiver;
import androidx.compose.ui.unit.Density;
import androidx.compose.ui.unit.Dp;
import androidx.compose.ui.unit.LayoutDirection;
import androidx.profileinstaller.ProfileVerifier;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.ClosedFloatingPointRange;
import kotlin.ranges.RangesKt;
import kotlinx.coroutines.BuildersKt__Builders_commonKt;
import kotlinx.coroutines.CoroutineScope;
/* compiled from: Pager.kt */
@Metadata(d1 = {"\u0000ª\u0001\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0004\u001aÚ\u0001\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\u00062\b\b\u0002\u0010\n\u001a\u00020\u000b2\b\b\u0002\u0010\f\u001a\u00020\r2\b\b\u0002\u0010\u000e\u001a\u00020\u000f2\b\b\u0002\u0010\u0010\u001a\u00020\u00112\b\b\u0002\u0010\u0012\u001a\u00020\u00062\b\b\u0002\u0010\u0013\u001a\u00020\u00142\b\b\u0002\u0010\u0015\u001a\u00020\u00162\b\b\u0002\u0010\u0017\u001a\u00020\u00182\b\b\u0002\u0010\u0019\u001a\u00020\u00042\b\b\u0002\u0010\u001a\u001a\u00020\u00042%\b\u0002\u0010\u001b\u001a\u001f\u0012\u0013\u0012\u00110\u0006¢\u0006\f\b\u001d\u0012\b\b\u001e\u0012\u0004\b\b(\u001f\u0012\u0004\u0012\u00020 \u0018\u00010\u001c2\b\b\u0002\u0010!\u001a\u00020\"2&\u0010#\u001a\"\u0012\u0013\u0012\u00110\u0006¢\u0006\f\b\u001d\u0012\b\b\u001e\u0012\u0004\b\b($\u0012\u0004\u0012\u00020\b0\u001c¢\u0006\u0002\b%H\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b&\u0010'\u001aÖ\u0001\u0010(\u001a\u00020\b2\u0006\u0010\n\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\r2\u0006\u0010\t\u001a\u00020\u00062\u0006\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0013\u001a\u00020\u00142\u0006\u0010)\u001a\u00020*2\u0006\u0010\u0012\u001a\u00020\u00062\b\b\u0002\u0010\u0015\u001a\u00020\u00162\b\b\u0002\u0010+\u001a\u00020,2\u0006\u0010\u000e\u001a\u00020\u000f2\u0006\u0010\u0017\u001a\u00020\u00182\u0006\u0010\u0019\u001a\u00020\u00042\u0006\u0010\u001a\u001a\u00020\u00042#\u0010\u001b\u001a\u001f\u0012\u0013\u0012\u00110\u0006¢\u0006\f\b\u001d\u0012\b\b\u001e\u0012\u0004\b\b(\u001f\u0012\u0004\u0012\u00020 \u0018\u00010\u001c2\u0006\u0010!\u001a\u00020\"2&\u0010#\u001a\"\u0012\u0013\u0012\u00110\u0006¢\u0006\f\b\u001d\u0012\b\b\u001e\u0012\u0004\b\b($\u0012\u0004\u0012\u00020\b0\u001c¢\u0006\u0002\b%H\u0001ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b-\u0010.\u001a&\u0010/\u001a\u0002002\u0006\u00101\u001a\u00020\r2\u0006\u00102\u001a\u0002032\f\u00104\u001a\b\u0012\u0004\u0012\u00020605H\u0002\u001aÚ\u0001\u00107\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\u00062\b\b\u0002\u0010\n\u001a\u00020\u000b2\b\b\u0002\u0010\f\u001a\u00020\r2\b\b\u0002\u0010\u000e\u001a\u00020\u000f2\b\b\u0002\u0010\u0010\u001a\u00020\u00112\b\b\u0002\u0010\u0012\u001a\u00020\u00062\b\b\u0002\u0010\u0013\u001a\u00020\u00142\b\b\u0002\u0010+\u001a\u00020,2\b\b\u0002\u0010\u0017\u001a\u00020\u00182\b\b\u0002\u0010\u0019\u001a\u00020\u00042\b\b\u0002\u0010\u001a\u001a\u00020\u00042%\b\u0002\u0010\u001b\u001a\u001f\u0012\u0013\u0012\u00110\u0006¢\u0006\f\b\u001d\u0012\b\b\u001e\u0012\u0004\b\b(\u001f\u0012\u0004\u0012\u00020 \u0018\u00010\u001c2\b\b\u0002\u0010!\u001a\u00020\"2&\u0010#\u001a\"\u0012\u0013\u0012\u00110\u0006¢\u0006\f\b\u001d\u0012\b\b\u001e\u0012\u0004\b\b($\u0012\u0004\u0012\u00020\b0\u001c¢\u0006\u0002\b%H\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b8\u00109\u001a(\u0010:\u001a\u00020\u00142\u0006\u0010\u000e\u001a\u00020\u000f2\u0006\u0010)\u001a\u00020*2\u0006\u0010;\u001a\u00020<H\u0002ø\u0001\u0001¢\u0006\u0002\u0010=\u001a\u0017\u0010>\u001a\u00020\b2\f\u0010?\u001a\b\u0012\u0004\u0012\u00020A0@H\u0082\b\u001a!\u0010B\u001a\u00020\u000b*\u00020\u000b2\u0006\u0010\f\u001a\u00020\r2\u0006\u0010C\u001a\u00020\u0004H\u0003¢\u0006\u0002\u0010D\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082\u0004¢\u0006\u0002\n\u0000\"\u000e\u0010\u0002\u001a\u00020\u0001X\u0082\u0004¢\u0006\u0002\n\u0000\"\u000e\u0010\u0003\u001a\u00020\u0004X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0005\u001a\u00020\u0006X\u0082T¢\u0006\u0002\n\u0000\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006E"}, d2 = {"ConsumeHorizontalFlingNestedScrollConnection", "Landroidx/compose/foundation/pager/ConsumeAllFlingOnDirection;", "ConsumeVerticalFlingNestedScrollConnection", "DEBUG", "", "LowVelocityAnimationDefaultDuration", "", "HorizontalPager", "", "pageCount", "modifier", "Landroidx/compose/ui/Modifier;", "state", "Landroidx/compose/foundation/pager/PagerState;", "contentPadding", "Landroidx/compose/foundation/layout/PaddingValues;", "pageSize", "Landroidx/compose/foundation/pager/PageSize;", "beyondBoundsPageCount", "pageSpacing", "Landroidx/compose/ui/unit/Dp;", "verticalAlignment", "Landroidx/compose/ui/Alignment$Vertical;", "flingBehavior", "Landroidx/compose/foundation/gestures/snapping/SnapFlingBehavior;", "userScrollEnabled", "reverseLayout", "key", "Lkotlin/Function1;", "Lkotlin/ParameterName;", HintConstants.AUTOFILL_HINT_NAME, "index", "", "pageNestedScrollConnection", "Landroidx/compose/ui/input/nestedscroll/NestedScrollConnection;", "pageContent", "page", "Landroidx/compose/runtime/Composable;", "HorizontalPager-AlbwjTQ", "(ILandroidx/compose/ui/Modifier;Landroidx/compose/foundation/pager/PagerState;Landroidx/compose/foundation/layout/PaddingValues;Landroidx/compose/foundation/pager/PageSize;IFLandroidx/compose/ui/Alignment$Vertical;Landroidx/compose/foundation/gestures/snapping/SnapFlingBehavior;ZZLkotlin/jvm/functions/Function1;Landroidx/compose/ui/input/nestedscroll/NestedScrollConnection;Lkotlin/jvm/functions/Function3;Landroidx/compose/runtime/Composer;III)V", "Pager", "orientation", "Landroidx/compose/foundation/gestures/Orientation;", "horizontalAlignment", "Landroidx/compose/ui/Alignment$Horizontal;", "Pager-wKDqQAw", "(Landroidx/compose/ui/Modifier;Landroidx/compose/foundation/pager/PagerState;ILandroidx/compose/foundation/pager/PageSize;FLandroidx/compose/foundation/gestures/Orientation;ILandroidx/compose/ui/Alignment$Vertical;Landroidx/compose/ui/Alignment$Horizontal;Landroidx/compose/foundation/layout/PaddingValues;Landroidx/compose/foundation/gestures/snapping/SnapFlingBehavior;ZZLkotlin/jvm/functions/Function1;Landroidx/compose/ui/input/nestedscroll/NestedScrollConnection;Lkotlin/jvm/functions/Function3;Landroidx/compose/runtime/Composer;III)V", "SnapLayoutInfoProvider", "Landroidx/compose/foundation/gestures/snapping/SnapLayoutInfoProvider;", "pagerState", "pagerSnapDistance", "Landroidx/compose/foundation/pager/PagerSnapDistance;", "decayAnimationSpec", "Landroidx/compose/animation/core/DecayAnimationSpec;", "", "VerticalPager", "VerticalPager-AlbwjTQ", "(ILandroidx/compose/ui/Modifier;Landroidx/compose/foundation/pager/PagerState;Landroidx/compose/foundation/layout/PaddingValues;Landroidx/compose/foundation/pager/PageSize;IFLandroidx/compose/ui/Alignment$Horizontal;Landroidx/compose/foundation/gestures/snapping/SnapFlingBehavior;ZZLkotlin/jvm/functions/Function1;Landroidx/compose/ui/input/nestedscroll/NestedScrollConnection;Lkotlin/jvm/functions/Function3;Landroidx/compose/runtime/Composer;III)V", "calculateContentPaddings", "layoutDirection", "Landroidx/compose/ui/unit/LayoutDirection;", "(Landroidx/compose/foundation/layout/PaddingValues;Landroidx/compose/foundation/gestures/Orientation;Landroidx/compose/ui/unit/LayoutDirection;)F", "debugLog", "generateMsg", "Lkotlin/Function0;", "", "pagerSemantics", "isVertical", "(Landroidx/compose/ui/Modifier;Landroidx/compose/foundation/pager/PagerState;ZLandroidx/compose/runtime/Composer;I)Landroidx/compose/ui/Modifier;", "foundation_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class PagerKt {
    private static final ConsumeAllFlingOnDirection ConsumeHorizontalFlingNestedScrollConnection = new ConsumeAllFlingOnDirection(Orientation.Horizontal);
    private static final ConsumeAllFlingOnDirection ConsumeVerticalFlingNestedScrollConnection = new ConsumeAllFlingOnDirection(Orientation.Vertical);
    private static final boolean DEBUG = false;
    private static final int LowVelocityAnimationDefaultDuration = 500;

    /* renamed from: HorizontalPager-AlbwjTQ  reason: not valid java name */
    public static final void m656HorizontalPagerAlbwjTQ(final int pageCount, Modifier modifier, PagerState state, PaddingValues contentPadding, PageSize pageSize, int beyondBoundsPageCount, float pageSpacing, Alignment.Vertical verticalAlignment, SnapFlingBehavior flingBehavior, boolean userScrollEnabled, boolean reverseLayout, Function1<? super Integer, ? extends Object> function1, NestedScrollConnection pageNestedScrollConnection, final Function3<? super Integer, ? super Composer, ? super Integer, Unit> pageContent, Composer $composer, final int $changed, final int $changed1, final int i) {
        Object obj;
        int i2;
        float f;
        int i3;
        int i4;
        int i5;
        PagerState state2;
        int $dirty;
        int $dirty1;
        int i6;
        int i7;
        int i8;
        int i9;
        SnapFlingBehavior flingBehavior2;
        NestedScrollConnection pageNestedScrollConnection2;
        Alignment.Vertical verticalAlignment2;
        SnapFlingBehavior flingBehavior3;
        boolean userScrollEnabled2;
        boolean reverseLayout2;
        Function1 key;
        int $dirty12;
        Modifier modifier2;
        int beyondBoundsPageCount2;
        int $dirty2;
        float pageSpacing2;
        PaddingValues contentPadding2;
        PagerState state3;
        PageSize pageSize2;
        Composer $composer2;
        int i10;
        int i11;
        Intrinsics.checkNotNullParameter(pageContent, "pageContent");
        Composer $composer3 = $composer.startRestartGroup(-547020879);
        ComposerKt.sourceInformation($composer3, "C(HorizontalPager)P(6,4,11,1,8!1,9:c#ui.unit.Dp,13!1,12,10!1,7)124@6522L20,130@6830L28,139@7169L591:Pager.kt#g6yjnt");
        int $dirty3 = $changed;
        int $dirty13 = $changed1;
        if ((i & 1) != 0) {
            $dirty3 |= 6;
        } else if (($changed & 14) == 0) {
            $dirty3 |= $composer3.changed(pageCount) ? 4 : 2;
        }
        int i12 = i & 2;
        if (i12 != 0) {
            $dirty3 |= 48;
            obj = modifier;
        } else if (($changed & 112) == 0) {
            obj = modifier;
            $dirty3 |= $composer3.changed(obj) ? 32 : 16;
        } else {
            obj = modifier;
        }
        if (($changed & 896) == 0) {
            if ((i & 4) == 0 && $composer3.changed(state)) {
                i11 = 256;
                $dirty3 |= i11;
            }
            i11 = 128;
            $dirty3 |= i11;
        }
        int i13 = i & 8;
        if (i13 != 0) {
            $dirty3 |= 3072;
        } else if (($changed & 7168) == 0) {
            $dirty3 |= $composer3.changed(contentPadding) ? 2048 : 1024;
        }
        int i14 = i & 16;
        if (i14 != 0) {
            $dirty3 |= 24576;
        } else if (($changed & 57344) == 0) {
            $dirty3 |= $composer3.changed(pageSize) ? 16384 : 8192;
        }
        int i15 = i & 32;
        if (i15 != 0) {
            $dirty3 |= ProfileVerifier.CompilationStatus.RESULT_CODE_ERROR_CANT_WRITE_PROFILE_VERIFICATION_RESULT_CACHE_FILE;
            i2 = beyondBoundsPageCount;
        } else if (($changed & 458752) == 0) {
            i2 = beyondBoundsPageCount;
            $dirty3 |= $composer3.changed(i2) ? 131072 : 65536;
        } else {
            i2 = beyondBoundsPageCount;
        }
        int i16 = i & 64;
        if (i16 != 0) {
            $dirty3 |= 1572864;
            f = pageSpacing;
        } else if (($changed & 3670016) == 0) {
            f = pageSpacing;
            $dirty3 |= $composer3.changed(f) ? 1048576 : 524288;
        } else {
            f = pageSpacing;
        }
        int i17 = i & 128;
        if (i17 != 0) {
            $dirty3 |= 12582912;
        } else if (($changed & 29360128) == 0) {
            $dirty3 |= $composer3.changed(verticalAlignment) ? 8388608 : 4194304;
        }
        if (($changed & 234881024) == 0) {
            if ((i & 256) == 0 && $composer3.changed(flingBehavior)) {
                i10 = 67108864;
                $dirty3 |= i10;
            }
            i10 = 33554432;
            $dirty3 |= i10;
        }
        int i18 = i & 512;
        if (i18 != 0) {
            $dirty3 |= 805306368;
            i3 = i18;
        } else if (($changed & 1879048192) == 0) {
            i3 = i18;
            $dirty3 |= $composer3.changed(userScrollEnabled) ? 536870912 : 268435456;
        } else {
            i3 = i18;
        }
        int i19 = i & 1024;
        if (i19 != 0) {
            $dirty13 |= 6;
            i4 = i19;
        } else if (($changed1 & 14) == 0) {
            i4 = i19;
            $dirty13 |= $composer3.changed(reverseLayout) ? 4 : 2;
        } else {
            i4 = i19;
        }
        int i20 = i & 2048;
        if (i20 != 0) {
            $dirty13 |= 48;
            i5 = i20;
        } else if (($changed1 & 112) == 0) {
            i5 = i20;
            $dirty13 |= $composer3.changedInstance(function1) ? 32 : 16;
        } else {
            i5 = i20;
        }
        int i21 = i & 4096;
        if (i21 != 0) {
            $dirty13 |= 128;
        }
        if ((i & 8192) != 0) {
            $dirty13 |= 3072;
        } else if (($changed1 & 7168) == 0) {
            $dirty13 |= $composer3.changedInstance(pageContent) ? 2048 : 1024;
        }
        int $dirty14 = $dirty13;
        if (i21 == 4096 && (1533916891 & $dirty3) == 306783378 && ($dirty14 & 5851) == 1170 && $composer3.getSkipping()) {
            $composer3.skipToGroupEnd();
            state3 = state;
            contentPadding2 = contentPadding;
            pageSize2 = pageSize;
            verticalAlignment2 = verticalAlignment;
            flingBehavior3 = flingBehavior;
            userScrollEnabled2 = userScrollEnabled;
            reverseLayout2 = reverseLayout;
            key = function1;
            pageNestedScrollConnection2 = pageNestedScrollConnection;
            beyondBoundsPageCount2 = i2;
            pageSpacing2 = f;
            modifier2 = obj;
            $composer2 = $composer3;
        } else {
            $composer3.startDefaults();
            if (($changed & 1) == 0 || $composer3.getDefaultsInvalid()) {
                Modifier modifier3 = i12 != 0 ? Modifier.Companion : obj;
                if ((i & 4) != 0) {
                    $dirty = $dirty3 & (-897);
                    state2 = PagerStateKt.rememberPagerState(0, 0.0f, $composer3, 0, 3);
                } else {
                    state2 = state;
                    $dirty = $dirty3;
                }
                PaddingValues contentPadding3 = i13 != 0 ? PaddingKt.m407PaddingValues0680j_4(Dp.m5122constructorimpl(0)) : contentPadding;
                PageSize pageSize3 = i14 != 0 ? PageSize.Fill.INSTANCE : pageSize;
                int beyondBoundsPageCount3 = i15 != 0 ? 0 : i2;
                float pageSpacing3 = i16 != 0 ? Dp.m5122constructorimpl(0) : f;
                Alignment.Vertical verticalAlignment3 = i17 != 0 ? Alignment.Companion.getCenterVertically() : verticalAlignment;
                if ((i & 256) != 0) {
                    $dirty1 = $dirty14;
                    i6 = i21;
                    int i22 = i4;
                    i7 = i5;
                    i8 = i3;
                    i9 = i22;
                    flingBehavior2 = PagerDefaults.INSTANCE.flingBehavior(state2, null, null, null, null, $composer3, (($dirty >> 6) & 14) | ProfileVerifier.CompilationStatus.RESULT_CODE_ERROR_CANT_WRITE_PROFILE_VERIFICATION_RESULT_CACHE_FILE, 30);
                    $dirty &= -234881025;
                } else {
                    $dirty1 = $dirty14;
                    i6 = i21;
                    int i23 = i4;
                    i7 = i5;
                    i8 = i3;
                    i9 = i23;
                    flingBehavior2 = flingBehavior;
                }
                boolean userScrollEnabled3 = i8 != 0 ? true : userScrollEnabled;
                boolean reverseLayout3 = i9 != 0 ? false : reverseLayout;
                Function1 key2 = i7 != 0 ? null : function1;
                if (i6 != 0) {
                    verticalAlignment2 = verticalAlignment3;
                    flingBehavior3 = flingBehavior2;
                    userScrollEnabled2 = userScrollEnabled3;
                    reverseLayout2 = reverseLayout3;
                    key = key2;
                    pageNestedScrollConnection2 = PagerDefaults.INSTANCE.pageNestedScrollConnection(Orientation.Horizontal);
                    $dirty12 = $dirty1 & (-897);
                    modifier2 = modifier3;
                    beyondBoundsPageCount2 = beyondBoundsPageCount3;
                    $dirty2 = $dirty;
                    pageSpacing2 = pageSpacing3;
                    contentPadding2 = contentPadding3;
                    state3 = state2;
                    pageSize2 = pageSize3;
                } else {
                    int $dirty15 = $dirty1;
                    pageNestedScrollConnection2 = pageNestedScrollConnection;
                    verticalAlignment2 = verticalAlignment3;
                    flingBehavior3 = flingBehavior2;
                    userScrollEnabled2 = userScrollEnabled3;
                    reverseLayout2 = reverseLayout3;
                    key = key2;
                    $dirty12 = $dirty15;
                    modifier2 = modifier3;
                    beyondBoundsPageCount2 = beyondBoundsPageCount3;
                    $dirty2 = $dirty;
                    pageSpacing2 = pageSpacing3;
                    contentPadding2 = contentPadding3;
                    state3 = state2;
                    pageSize2 = pageSize3;
                }
            } else {
                $composer3.skipToGroupEnd();
                if ((i & 4) != 0) {
                    $dirty3 &= -897;
                }
                if ((i & 256) != 0) {
                    $dirty3 &= -234881025;
                }
                if (i21 != 0) {
                    state3 = state;
                    contentPadding2 = contentPadding;
                    pageSize2 = pageSize;
                    verticalAlignment2 = verticalAlignment;
                    flingBehavior3 = flingBehavior;
                    userScrollEnabled2 = userScrollEnabled;
                    reverseLayout2 = reverseLayout;
                    key = function1;
                    pageNestedScrollConnection2 = pageNestedScrollConnection;
                    $dirty2 = $dirty3;
                    beyondBoundsPageCount2 = i2;
                    pageSpacing2 = f;
                    modifier2 = obj;
                    $dirty12 = $dirty14 & (-897);
                } else {
                    state3 = state;
                    contentPadding2 = contentPadding;
                    pageSize2 = pageSize;
                    verticalAlignment2 = verticalAlignment;
                    flingBehavior3 = flingBehavior;
                    userScrollEnabled2 = userScrollEnabled;
                    reverseLayout2 = reverseLayout;
                    key = function1;
                    pageNestedScrollConnection2 = pageNestedScrollConnection;
                    $dirty2 = $dirty3;
                    beyondBoundsPageCount2 = i2;
                    pageSpacing2 = f;
                    modifier2 = obj;
                    $dirty12 = $dirty14;
                }
            }
            $composer3.endDefaults();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(-547020879, $dirty2, $dirty12, "androidx.compose.foundation.pager.HorizontalPager (Pager.kt:121)");
            }
            $composer2 = $composer3;
            m657PagerwKDqQAw(modifier2, state3, pageCount, pageSize2, pageSpacing2, Orientation.Horizontal, beyondBoundsPageCount2, verticalAlignment2, null, contentPadding2, flingBehavior3, userScrollEnabled2, reverseLayout2, key, pageNestedScrollConnection2, pageContent, $composer2, (($dirty2 >> 3) & 14) | ProfileVerifier.CompilationStatus.RESULT_CODE_ERROR_CANT_WRITE_PROFILE_VERIFICATION_RESULT_CACHE_FILE | (($dirty2 >> 3) & 112) | (($dirty2 << 6) & 896) | (($dirty2 >> 3) & 7168) | (($dirty2 >> 6) & 57344) | (($dirty2 << 3) & 3670016) | (29360128 & $dirty2) | (($dirty2 << 18) & 1879048192), (($dirty2 >> 24) & 14) | 32768 | (($dirty2 >> 24) & 112) | (($dirty12 << 6) & 896) | (($dirty12 << 6) & 7168) | (($dirty12 << 6) & 458752), 256);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Modifier modifier4 = modifier2;
        final PagerState pagerState = state3;
        final PaddingValues paddingValues = contentPadding2;
        final PageSize pageSize4 = pageSize2;
        final int i24 = beyondBoundsPageCount2;
        final float f2 = pageSpacing2;
        final Alignment.Vertical vertical = verticalAlignment2;
        final SnapFlingBehavior snapFlingBehavior = flingBehavior3;
        final boolean z = userScrollEnabled2;
        final boolean z2 = reverseLayout2;
        final Function1 function12 = key;
        final NestedScrollConnection nestedScrollConnection = pageNestedScrollConnection2;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.foundation.pager.PagerKt$HorizontalPager$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
                invoke(composer, num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(Composer composer, int i25) {
                PagerKt.m656HorizontalPagerAlbwjTQ(pageCount, modifier4, pagerState, paddingValues, pageSize4, i24, f2, vertical, snapFlingBehavior, z, z2, function12, nestedScrollConnection, pageContent, composer, RecomposeScopeImplKt.updateChangedFlags($changed | 1), RecomposeScopeImplKt.updateChangedFlags($changed1), i);
            }
        });
    }

    /* renamed from: VerticalPager-AlbwjTQ  reason: not valid java name */
    public static final void m658VerticalPagerAlbwjTQ(final int pageCount, Modifier modifier, PagerState state, PaddingValues contentPadding, PageSize pageSize, int beyondBoundsPageCount, float pageSpacing, Alignment.Horizontal horizontalAlignment, SnapFlingBehavior flingBehavior, boolean userScrollEnabled, boolean reverseLayout, Function1<? super Integer, ? extends Object> function1, NestedScrollConnection pageNestedScrollConnection, final Function3<? super Integer, ? super Composer, ? super Integer, Unit> pageContent, Composer $composer, final int $changed, final int $changed1, final int i) {
        Object obj;
        int i2;
        float f;
        int i3;
        int i4;
        int i5;
        PagerState state2;
        int $dirty;
        int $dirty1;
        int i6;
        int i7;
        int i8;
        int i9;
        SnapFlingBehavior flingBehavior2;
        NestedScrollConnection pageNestedScrollConnection2;
        Alignment.Horizontal horizontalAlignment2;
        SnapFlingBehavior flingBehavior3;
        boolean userScrollEnabled2;
        boolean reverseLayout2;
        Function1 key;
        int $dirty12;
        Modifier modifier2;
        int beyondBoundsPageCount2;
        int $dirty2;
        float pageSpacing2;
        PaddingValues contentPadding2;
        PagerState state3;
        PageSize pageSize2;
        Composer $composer2;
        int i10;
        int i11;
        Intrinsics.checkNotNullParameter(pageContent, "pageContent");
        Composer $composer3 = $composer.startRestartGroup(26030705);
        ComposerKt.sourceInformation($composer3, "C(VerticalPager)P(7,5,12,1,9!1,10:c#ui.unit.Dp,3!1,13,11!1,8)204@10765L20,210@11079L28,219@11416L593:Pager.kt#g6yjnt");
        int $dirty3 = $changed;
        int $dirty13 = $changed1;
        if ((i & 1) != 0) {
            $dirty3 |= 6;
        } else if (($changed & 14) == 0) {
            $dirty3 |= $composer3.changed(pageCount) ? 4 : 2;
        }
        int i12 = i & 2;
        if (i12 != 0) {
            $dirty3 |= 48;
            obj = modifier;
        } else if (($changed & 112) == 0) {
            obj = modifier;
            $dirty3 |= $composer3.changed(obj) ? 32 : 16;
        } else {
            obj = modifier;
        }
        if (($changed & 896) == 0) {
            if ((i & 4) == 0 && $composer3.changed(state)) {
                i11 = 256;
                $dirty3 |= i11;
            }
            i11 = 128;
            $dirty3 |= i11;
        }
        int i13 = i & 8;
        if (i13 != 0) {
            $dirty3 |= 3072;
        } else if (($changed & 7168) == 0) {
            $dirty3 |= $composer3.changed(contentPadding) ? 2048 : 1024;
        }
        int i14 = i & 16;
        if (i14 != 0) {
            $dirty3 |= 24576;
        } else if (($changed & 57344) == 0) {
            $dirty3 |= $composer3.changed(pageSize) ? 16384 : 8192;
        }
        int i15 = i & 32;
        if (i15 != 0) {
            $dirty3 |= ProfileVerifier.CompilationStatus.RESULT_CODE_ERROR_CANT_WRITE_PROFILE_VERIFICATION_RESULT_CACHE_FILE;
            i2 = beyondBoundsPageCount;
        } else if (($changed & 458752) == 0) {
            i2 = beyondBoundsPageCount;
            $dirty3 |= $composer3.changed(i2) ? 131072 : 65536;
        } else {
            i2 = beyondBoundsPageCount;
        }
        int i16 = i & 64;
        if (i16 != 0) {
            $dirty3 |= 1572864;
            f = pageSpacing;
        } else if (($changed & 3670016) == 0) {
            f = pageSpacing;
            $dirty3 |= $composer3.changed(f) ? 1048576 : 524288;
        } else {
            f = pageSpacing;
        }
        int i17 = i & 128;
        if (i17 != 0) {
            $dirty3 |= 12582912;
        } else if (($changed & 29360128) == 0) {
            $dirty3 |= $composer3.changed(horizontalAlignment) ? 8388608 : 4194304;
        }
        if (($changed & 234881024) == 0) {
            if ((i & 256) == 0 && $composer3.changed(flingBehavior)) {
                i10 = 67108864;
                $dirty3 |= i10;
            }
            i10 = 33554432;
            $dirty3 |= i10;
        }
        int i18 = i & 512;
        if (i18 != 0) {
            $dirty3 |= 805306368;
            i3 = i18;
        } else if (($changed & 1879048192) == 0) {
            i3 = i18;
            $dirty3 |= $composer3.changed(userScrollEnabled) ? 536870912 : 268435456;
        } else {
            i3 = i18;
        }
        int i19 = i & 1024;
        if (i19 != 0) {
            $dirty13 |= 6;
            i4 = i19;
        } else if (($changed1 & 14) == 0) {
            i4 = i19;
            $dirty13 |= $composer3.changed(reverseLayout) ? 4 : 2;
        } else {
            i4 = i19;
        }
        int i20 = i & 2048;
        if (i20 != 0) {
            $dirty13 |= 48;
            i5 = i20;
        } else if (($changed1 & 112) == 0) {
            i5 = i20;
            $dirty13 |= $composer3.changedInstance(function1) ? 32 : 16;
        } else {
            i5 = i20;
        }
        int i21 = i & 4096;
        if (i21 != 0) {
            $dirty13 |= 128;
        }
        if ((i & 8192) != 0) {
            $dirty13 |= 3072;
        } else if (($changed1 & 7168) == 0) {
            $dirty13 |= $composer3.changedInstance(pageContent) ? 2048 : 1024;
        }
        int $dirty14 = $dirty13;
        if (i21 == 4096 && (1533916891 & $dirty3) == 306783378 && ($dirty14 & 5851) == 1170 && $composer3.getSkipping()) {
            $composer3.skipToGroupEnd();
            state3 = state;
            contentPadding2 = contentPadding;
            pageSize2 = pageSize;
            horizontalAlignment2 = horizontalAlignment;
            flingBehavior3 = flingBehavior;
            userScrollEnabled2 = userScrollEnabled;
            reverseLayout2 = reverseLayout;
            key = function1;
            pageNestedScrollConnection2 = pageNestedScrollConnection;
            beyondBoundsPageCount2 = i2;
            pageSpacing2 = f;
            modifier2 = obj;
            $composer2 = $composer3;
        } else {
            $composer3.startDefaults();
            if (($changed & 1) == 0 || $composer3.getDefaultsInvalid()) {
                Modifier modifier3 = i12 != 0 ? Modifier.Companion : obj;
                if ((i & 4) != 0) {
                    $dirty = $dirty3 & (-897);
                    state2 = PagerStateKt.rememberPagerState(0, 0.0f, $composer3, 0, 3);
                } else {
                    state2 = state;
                    $dirty = $dirty3;
                }
                PaddingValues contentPadding3 = i13 != 0 ? PaddingKt.m407PaddingValues0680j_4(Dp.m5122constructorimpl(0)) : contentPadding;
                PageSize pageSize3 = i14 != 0 ? PageSize.Fill.INSTANCE : pageSize;
                int beyondBoundsPageCount3 = i15 != 0 ? 0 : i2;
                float pageSpacing3 = i16 != 0 ? Dp.m5122constructorimpl(0) : f;
                Alignment.Horizontal horizontalAlignment3 = i17 != 0 ? Alignment.Companion.getCenterHorizontally() : horizontalAlignment;
                if ((i & 256) != 0) {
                    $dirty1 = $dirty14;
                    i6 = i21;
                    int i22 = i4;
                    i7 = i5;
                    i8 = i3;
                    i9 = i22;
                    flingBehavior2 = PagerDefaults.INSTANCE.flingBehavior(state2, null, null, null, null, $composer3, (($dirty >> 6) & 14) | ProfileVerifier.CompilationStatus.RESULT_CODE_ERROR_CANT_WRITE_PROFILE_VERIFICATION_RESULT_CACHE_FILE, 30);
                    $dirty &= -234881025;
                } else {
                    $dirty1 = $dirty14;
                    i6 = i21;
                    int i23 = i4;
                    i7 = i5;
                    i8 = i3;
                    i9 = i23;
                    flingBehavior2 = flingBehavior;
                }
                boolean userScrollEnabled3 = i8 != 0 ? true : userScrollEnabled;
                boolean reverseLayout3 = i9 != 0 ? false : reverseLayout;
                Function1 key2 = i7 != 0 ? null : function1;
                if (i6 != 0) {
                    horizontalAlignment2 = horizontalAlignment3;
                    flingBehavior3 = flingBehavior2;
                    userScrollEnabled2 = userScrollEnabled3;
                    reverseLayout2 = reverseLayout3;
                    key = key2;
                    pageNestedScrollConnection2 = PagerDefaults.INSTANCE.pageNestedScrollConnection(Orientation.Vertical);
                    $dirty12 = $dirty1 & (-897);
                    modifier2 = modifier3;
                    beyondBoundsPageCount2 = beyondBoundsPageCount3;
                    $dirty2 = $dirty;
                    pageSpacing2 = pageSpacing3;
                    contentPadding2 = contentPadding3;
                    state3 = state2;
                    pageSize2 = pageSize3;
                } else {
                    int $dirty15 = $dirty1;
                    pageNestedScrollConnection2 = pageNestedScrollConnection;
                    horizontalAlignment2 = horizontalAlignment3;
                    flingBehavior3 = flingBehavior2;
                    userScrollEnabled2 = userScrollEnabled3;
                    reverseLayout2 = reverseLayout3;
                    key = key2;
                    $dirty12 = $dirty15;
                    modifier2 = modifier3;
                    beyondBoundsPageCount2 = beyondBoundsPageCount3;
                    $dirty2 = $dirty;
                    pageSpacing2 = pageSpacing3;
                    contentPadding2 = contentPadding3;
                    state3 = state2;
                    pageSize2 = pageSize3;
                }
            } else {
                $composer3.skipToGroupEnd();
                if ((i & 4) != 0) {
                    $dirty3 &= -897;
                }
                if ((i & 256) != 0) {
                    $dirty3 &= -234881025;
                }
                if (i21 != 0) {
                    state3 = state;
                    contentPadding2 = contentPadding;
                    pageSize2 = pageSize;
                    horizontalAlignment2 = horizontalAlignment;
                    flingBehavior3 = flingBehavior;
                    userScrollEnabled2 = userScrollEnabled;
                    reverseLayout2 = reverseLayout;
                    key = function1;
                    pageNestedScrollConnection2 = pageNestedScrollConnection;
                    $dirty2 = $dirty3;
                    beyondBoundsPageCount2 = i2;
                    pageSpacing2 = f;
                    modifier2 = obj;
                    $dirty12 = $dirty14 & (-897);
                } else {
                    state3 = state;
                    contentPadding2 = contentPadding;
                    pageSize2 = pageSize;
                    horizontalAlignment2 = horizontalAlignment;
                    flingBehavior3 = flingBehavior;
                    userScrollEnabled2 = userScrollEnabled;
                    reverseLayout2 = reverseLayout;
                    key = function1;
                    pageNestedScrollConnection2 = pageNestedScrollConnection;
                    $dirty2 = $dirty3;
                    beyondBoundsPageCount2 = i2;
                    pageSpacing2 = f;
                    modifier2 = obj;
                    $dirty12 = $dirty14;
                }
            }
            $composer3.endDefaults();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(26030705, $dirty2, $dirty12, "androidx.compose.foundation.pager.VerticalPager (Pager.kt:201)");
            }
            $composer2 = $composer3;
            m657PagerwKDqQAw(modifier2, state3, pageCount, pageSize2, pageSpacing2, Orientation.Vertical, beyondBoundsPageCount2, null, horizontalAlignment2, contentPadding2, flingBehavior3, userScrollEnabled2, reverseLayout2, key, pageNestedScrollConnection2, pageContent, $composer2, (($dirty2 >> 3) & 14) | ProfileVerifier.CompilationStatus.RESULT_CODE_ERROR_CANT_WRITE_PROFILE_VERIFICATION_RESULT_CACHE_FILE | (($dirty2 >> 3) & 112) | (($dirty2 << 6) & 896) | (($dirty2 >> 3) & 7168) | (($dirty2 >> 6) & 57344) | (($dirty2 << 3) & 3670016) | (($dirty2 << 3) & 234881024) | (($dirty2 << 18) & 1879048192), (($dirty2 >> 24) & 14) | 32768 | (($dirty2 >> 24) & 112) | (($dirty12 << 6) & 896) | (($dirty12 << 6) & 7168) | (($dirty12 << 6) & 458752), 128);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Modifier modifier4 = modifier2;
        final PagerState pagerState = state3;
        final PaddingValues paddingValues = contentPadding2;
        final PageSize pageSize4 = pageSize2;
        final int i24 = beyondBoundsPageCount2;
        final float f2 = pageSpacing2;
        final Alignment.Horizontal horizontal = horizontalAlignment2;
        final SnapFlingBehavior snapFlingBehavior = flingBehavior3;
        final boolean z = userScrollEnabled2;
        final boolean z2 = reverseLayout2;
        final Function1 function12 = key;
        final NestedScrollConnection nestedScrollConnection = pageNestedScrollConnection2;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.foundation.pager.PagerKt$VerticalPager$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
                invoke(composer, num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(Composer composer, int i25) {
                PagerKt.m658VerticalPagerAlbwjTQ(pageCount, modifier4, pagerState, paddingValues, pageSize4, i24, f2, horizontal, snapFlingBehavior, z, z2, function12, nestedScrollConnection, pageContent, composer, RecomposeScopeImplKt.updateChangedFlags($changed | 1), RecomposeScopeImplKt.updateChangedFlags($changed1), i);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:53:0x0263  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0270  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x02cc  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x02d5  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x02de  */
    /* renamed from: Pager-wKDqQAw  reason: not valid java name */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void m657PagerwKDqQAw(final androidx.compose.ui.Modifier r44, final androidx.compose.foundation.pager.PagerState r45, final int r46, final androidx.compose.foundation.pager.PageSize r47, final float r48, final androidx.compose.foundation.gestures.Orientation r49, final int r50, androidx.compose.ui.Alignment.Vertical r51, androidx.compose.ui.Alignment.Horizontal r52, final androidx.compose.foundation.layout.PaddingValues r53, final androidx.compose.foundation.gestures.snapping.SnapFlingBehavior r54, final boolean r55, final boolean r56, final kotlin.jvm.functions.Function1<? super java.lang.Integer, ? extends java.lang.Object> r57, final androidx.compose.ui.input.nestedscroll.NestedScrollConnection r58, final kotlin.jvm.functions.Function3<? super java.lang.Integer, ? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r59, androidx.compose.runtime.Composer r60, final int r61, final int r62, final int r63) {
        /*
            Method dump skipped, instructions count: 832
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.pager.PagerKt.m657PagerwKDqQAw(androidx.compose.ui.Modifier, androidx.compose.foundation.pager.PagerState, int, androidx.compose.foundation.pager.PageSize, float, androidx.compose.foundation.gestures.Orientation, int, androidx.compose.ui.Alignment$Vertical, androidx.compose.ui.Alignment$Horizontal, androidx.compose.foundation.layout.PaddingValues, androidx.compose.foundation.gestures.snapping.SnapFlingBehavior, boolean, boolean, kotlin.jvm.functions.Function1, androidx.compose.ui.input.nestedscroll.NestedScrollConnection, kotlin.jvm.functions.Function3, androidx.compose.runtime.Composer, int, int, int):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final float calculateContentPaddings(PaddingValues contentPadding, Orientation orientation, LayoutDirection layoutDirection) {
        float startPadding;
        float endPadding;
        if (orientation == Orientation.Vertical) {
            startPadding = contentPadding.mo397calculateTopPaddingD9Ej5fM();
        } else {
            startPadding = contentPadding.mo395calculateLeftPaddingu2uoSUM(layoutDirection);
        }
        if (orientation == Orientation.Vertical) {
            endPadding = contentPadding.mo394calculateBottomPaddingD9Ej5fM();
        } else {
            endPadding = contentPadding.mo396calculateRightPaddingu2uoSUM(layoutDirection);
        }
        return Dp.m5122constructorimpl(startPadding + endPadding);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final SnapLayoutInfoProvider SnapLayoutInfoProvider(final PagerState pagerState, final PagerSnapDistance pagerSnapDistance, final DecayAnimationSpec<Float> decayAnimationSpec) {
        return new SnapLayoutInfoProvider() { // from class: androidx.compose.foundation.pager.PagerKt$SnapLayoutInfoProvider$1
            public final LazyListLayoutInfo getLayoutInfo() {
                return PagerState.this.getLayoutInfo$foundation_release();
            }

            @Override // androidx.compose.foundation.gestures.snapping.SnapLayoutInfoProvider
            public ClosedFloatingPointRange<Float> calculateSnappingOffsetBounds(Density $this$calculateSnappingOffsetBounds) {
                Intrinsics.checkNotNullParameter($this$calculateSnappingOffsetBounds, "<this>");
                float lowerBoundOffset = Float.NEGATIVE_INFINITY;
                float upperBoundOffset = Float.POSITIVE_INFINITY;
                List $this$fastForEach$iv = getLayoutInfo().getVisibleItemsInfo();
                int size = $this$fastForEach$iv.size();
                for (int index$iv = 0; index$iv < size; index$iv++) {
                    Object item$iv = $this$fastForEach$iv.get(index$iv);
                    LazyListItemInfo item = (LazyListItemInfo) item$iv;
                    float offset = LazyListSnapLayoutInfoProviderKt.calculateDistanceToDesiredSnapPosition($this$calculateSnappingOffsetBounds, getLayoutInfo(), item, PagerStateKt.getSnapAlignmentStartToStart());
                    if (offset <= 0.0f && offset > lowerBoundOffset) {
                        lowerBoundOffset = offset;
                    }
                    if (offset >= 0.0f && offset < upperBoundOffset) {
                        upperBoundOffset = offset;
                    }
                }
                return RangesKt.rangeTo(lowerBoundOffset, upperBoundOffset);
            }

            @Override // androidx.compose.foundation.gestures.snapping.SnapLayoutInfoProvider
            public float calculateSnapStepSize(Density $this$calculateSnapStepSize) {
                Intrinsics.checkNotNullParameter($this$calculateSnapStepSize, "<this>");
                LazyListLayoutInfo $this$calculateSnapStepSize_u24lambda_u242 = getLayoutInfo();
                if (!$this$calculateSnapStepSize_u24lambda_u242.getVisibleItemsInfo().isEmpty()) {
                    List $this$fastSumBy$iv = $this$calculateSnapStepSize_u24lambda_u242.getVisibleItemsInfo();
                    int sum$iv = 0;
                    int size = $this$fastSumBy$iv.size();
                    for (int index$iv$iv = 0; index$iv$iv < size; index$iv$iv++) {
                        Object item$iv$iv = $this$fastSumBy$iv.get(index$iv$iv);
                        LazyListItemInfo it = (LazyListItemInfo) item$iv$iv;
                        sum$iv += it.getSize();
                    }
                    return sum$iv / $this$calculateSnapStepSize_u24lambda_u242.getVisibleItemsInfo().size();
                }
                return 0.0f;
            }

            @Override // androidx.compose.foundation.gestures.snapping.SnapLayoutInfoProvider
            public float calculateApproachOffset(Density $this$calculateApproachOffset, float initialVelocity) {
                int currentPage;
                Object it$iv;
                float floor;
                float signum;
                Intrinsics.checkNotNullParameter($this$calculateApproachOffset, "<this>");
                int effectivePageSizePx = PagerState.this.getPageSize$foundation_release() + PagerState.this.getPageSpacing$foundation_release();
                float animationOffsetPx = DecayAnimationSpecKt.calculateTargetValue(decayAnimationSpec, 0.0f, initialVelocity);
                LazyListItemInfo it = PagerState.this.getFirstVisiblePage$foundation_release();
                if (it != null) {
                    currentPage = initialVelocity < 0.0f ? it.getIndex() + 1 : it.getIndex();
                } else {
                    currentPage = PagerState.this.getCurrentPage();
                }
                int startPage = currentPage;
                List $this$fastFirstOrNull$iv = getLayoutInfo().getVisibleItemsInfo();
                int index$iv$iv = 0;
                int size = $this$fastFirstOrNull$iv.size();
                while (true) {
                    if (index$iv$iv < size) {
                        Object item$iv$iv = $this$fastFirstOrNull$iv.get(index$iv$iv);
                        it$iv = item$iv$iv;
                        if (((LazyListItemInfo) it$iv).getIndex() == startPage) {
                            break;
                        }
                        index$iv$iv++;
                    } else {
                        it$iv = null;
                        break;
                    }
                }
                LazyListItemInfo lazyListItemInfo = (LazyListItemInfo) it$iv;
                int scrollOffset = lazyListItemInfo != null ? lazyListItemInfo.getOffset() : 0;
                int $i$f$debugLog = startPage * effectivePageSizePx;
                float targetOffsetPx = $i$f$debugLog + animationOffsetPx;
                float targetPageValue = targetOffsetPx / effectivePageSizePx;
                if (initialVelocity > 0.0f) {
                    floor = (float) Math.ceil(targetPageValue);
                } else {
                    floor = (float) Math.floor(targetPageValue);
                }
                int targetPage = RangesKt.coerceIn((int) floor, 0, PagerState.this.getPageCount$foundation_release());
                int correctedTargetPage = RangesKt.coerceIn(pagerSnapDistance.calculateTargetPage(startPage, targetPage, initialVelocity, PagerState.this.getPageSize$foundation_release(), PagerState.this.getPageSpacing$foundation_release()), 0, PagerState.this.getPageCount$foundation_release());
                int $i$f$debugLog2 = correctedTargetPage - startPage;
                int proposedFlingOffset = $i$f$debugLog2 * effectivePageSizePx;
                int $i$f$debugLog3 = Math.abs(proposedFlingOffset);
                int flingApproachOffsetPx = RangesKt.coerceAtLeast($i$f$debugLog3 - Math.abs(scrollOffset), 0);
                if (flingApproachOffsetPx == 0) {
                    signum = flingApproachOffsetPx;
                } else {
                    signum = flingApproachOffsetPx * Math.signum(initialVelocity);
                }
                return signum;
            }
        };
    }

    private static final Modifier pagerSemantics(Modifier $this$pagerSemantics, final PagerState state, final boolean isVertical, Composer $composer, int $changed) {
        Object value$iv$iv$iv;
        $composer.startReplaceableGroup(1509835088);
        ComposerKt.sourceInformation($composer, "C(pagerSemantics)P(1)739@30533L24:Pager.kt#g6yjnt");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(1509835088, $changed, -1, "androidx.compose.foundation.pager.pagerSemantics (Pager.kt:738)");
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
        Modifier then = $this$pagerSemantics.then(SemanticsModifierKt.semantics$default(Modifier.Companion, false, new Function1<SemanticsPropertyReceiver, Unit>() { // from class: androidx.compose.foundation.pager.PagerKt$pagerSemantics$1
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
                if (isVertical) {
                    final PagerState pagerState = state;
                    final CoroutineScope coroutineScope = scope;
                    SemanticsPropertiesKt.pageUp$default(semantics, null, new Function0<Boolean>() { // from class: androidx.compose.foundation.pager.PagerKt$pagerSemantics$1.1
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(0);
                        }

                        /* JADX WARN: Can't rename method to resolve collision */
                        @Override // kotlin.jvm.functions.Function0
                        public final Boolean invoke() {
                            boolean pagerSemantics$performBackwardPaging;
                            pagerSemantics$performBackwardPaging = PagerKt.pagerSemantics$performBackwardPaging(PagerState.this, coroutineScope);
                            return Boolean.valueOf(pagerSemantics$performBackwardPaging);
                        }
                    }, 1, null);
                    final PagerState pagerState2 = state;
                    final CoroutineScope coroutineScope2 = scope;
                    SemanticsPropertiesKt.pageDown$default(semantics, null, new Function0<Boolean>() { // from class: androidx.compose.foundation.pager.PagerKt$pagerSemantics$1.2
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(0);
                        }

                        /* JADX WARN: Can't rename method to resolve collision */
                        @Override // kotlin.jvm.functions.Function0
                        public final Boolean invoke() {
                            boolean pagerSemantics$performForwardPaging;
                            pagerSemantics$performForwardPaging = PagerKt.pagerSemantics$performForwardPaging(PagerState.this, coroutineScope2);
                            return Boolean.valueOf(pagerSemantics$performForwardPaging);
                        }
                    }, 1, null);
                    return;
                }
                final PagerState pagerState3 = state;
                final CoroutineScope coroutineScope3 = scope;
                SemanticsPropertiesKt.pageLeft$default(semantics, null, new Function0<Boolean>() { // from class: androidx.compose.foundation.pager.PagerKt$pagerSemantics$1.3
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(0);
                    }

                    /* JADX WARN: Can't rename method to resolve collision */
                    @Override // kotlin.jvm.functions.Function0
                    public final Boolean invoke() {
                        boolean pagerSemantics$performBackwardPaging;
                        pagerSemantics$performBackwardPaging = PagerKt.pagerSemantics$performBackwardPaging(PagerState.this, coroutineScope3);
                        return Boolean.valueOf(pagerSemantics$performBackwardPaging);
                    }
                }, 1, null);
                final PagerState pagerState4 = state;
                final CoroutineScope coroutineScope4 = scope;
                SemanticsPropertiesKt.pageRight$default(semantics, null, new Function0<Boolean>() { // from class: androidx.compose.foundation.pager.PagerKt$pagerSemantics$1.4
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(0);
                    }

                    /* JADX WARN: Can't rename method to resolve collision */
                    @Override // kotlin.jvm.functions.Function0
                    public final Boolean invoke() {
                        boolean pagerSemantics$performForwardPaging;
                        pagerSemantics$performForwardPaging = PagerKt.pagerSemantics$performForwardPaging(PagerState.this, coroutineScope4);
                        return Boolean.valueOf(pagerSemantics$performForwardPaging);
                    }
                }, 1, null);
            }
        }, 1, null));
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return then;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean pagerSemantics$performForwardPaging(PagerState $state, CoroutineScope scope) {
        if ($state.getCanScrollForward()) {
            BuildersKt__Builders_commonKt.launch$default(scope, null, null, new PagerKt$pagerSemantics$performForwardPaging$1($state, null), 3, null);
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean pagerSemantics$performBackwardPaging(PagerState $state, CoroutineScope scope) {
        if ($state.getCanScrollBackward()) {
            BuildersKt__Builders_commonKt.launch$default(scope, null, null, new PagerKt$pagerSemantics$performBackwardPaging$1($state, null), 3, null);
            return true;
        }
        return false;
    }

    private static final void debugLog(Function0<String> function0) {
    }
}
