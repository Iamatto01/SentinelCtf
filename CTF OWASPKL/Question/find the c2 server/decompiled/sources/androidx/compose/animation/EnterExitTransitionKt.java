package androidx.compose.animation;

import androidx.autofill.HintConstants;
import androidx.compose.animation.core.AnimationSpecKt;
import androidx.compose.animation.core.AnimationVector2D;
import androidx.compose.animation.core.FiniteAnimationSpec;
import androidx.compose.animation.core.SpringSpec;
import androidx.compose.animation.core.Transition;
import androidx.compose.animation.core.TwoWayConverter;
import androidx.compose.animation.core.VectorConvertersKt;
import androidx.compose.animation.core.VisibilityThresholdsKt;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.MutableState;
import androidx.compose.runtime.SnapshotStateKt;
import androidx.compose.runtime.SnapshotStateKt__SnapshotStateKt;
import androidx.compose.runtime.State;
import androidx.compose.ui.Alignment;
import androidx.compose.ui.ComposedModifierKt;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.graphics.GraphicsLayerModifierKt;
import androidx.compose.ui.graphics.GraphicsLayerScope;
import androidx.compose.ui.graphics.TransformOrigin;
import androidx.compose.ui.graphics.TransformOriginKt;
import androidx.compose.ui.unit.IntOffset;
import androidx.compose.ui.unit.IntOffsetKt;
import androidx.compose.ui.unit.IntSize;
import androidx.compose.ui.unit.IntSizeKt;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.FloatCompanionObject;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: EnterExitTransition.kt */
@Metadata(d1 = {"\u0000\u0098\u0001\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\u001aT\u0010\r\u001a\u00020\u000e2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\b0\u00102\b\b\u0002\u0010\u0011\u001a\u00020\u00122\b\b\u0002\u0010\u0013\u001a\u00020\u00142#\b\u0002\u0010\u0015\u001a\u001d\u0012\u0013\u0012\u00110\u0017¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\u001a\u0012\u0004\u0012\u00020\u00170\u0016H\u0007ø\u0001\u0000\u001aT\u0010\u001b\u001a\u00020\u000e2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\b0\u00102\b\b\u0002\u0010\u0011\u001a\u00020\u001c2\b\b\u0002\u0010\u0013\u001a\u00020\u00142#\b\u0002\u0010\u001d\u001a\u001d\u0012\u0013\u0012\u00110\b¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\u001e\u0012\u0004\u0012\u00020\b0\u0016H\u0007ø\u0001\u0000\u001aT\u0010\u001f\u001a\u00020\u000e2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\b0\u00102\b\b\u0002\u0010\u0011\u001a\u00020 2\b\b\u0002\u0010\u0013\u001a\u00020\u00142#\b\u0002\u0010!\u001a\u001d\u0012\u0013\u0012\u00110\u0017¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u00170\u0016H\u0007ø\u0001\u0000\u001a\"\u0010#\u001a\u00020\u000e2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00020\u00102\b\b\u0002\u0010$\u001a\u00020\u0002H\u0007\u001a\"\u0010%\u001a\u00020&2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00020\u00102\b\b\u0002\u0010'\u001a\u00020\u0002H\u0007\u001a9\u0010(\u001a\u00020\u000e2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00020\u00102\b\b\u0002\u0010)\u001a\u00020\u00022\b\b\u0002\u0010*\u001a\u00020\u000bH\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b+\u0010,\u001a9\u0010-\u001a\u00020&2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00020\u00102\b\b\u0002\u0010.\u001a\u00020\u00022\b\b\u0002\u0010*\u001a\u00020\u000bH\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b/\u00100\u001aT\u00101\u001a\u00020&2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\b0\u00102\b\b\u0002\u00102\u001a\u00020\u00122\b\b\u0002\u0010\u0013\u001a\u00020\u00142#\b\u0002\u00103\u001a\u001d\u0012\u0013\u0012\u00110\u0017¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\u001a\u0012\u0004\u0012\u00020\u00170\u0016H\u0007ø\u0001\u0000\u001aT\u00104\u001a\u00020&2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\b0\u00102\b\b\u0002\u00102\u001a\u00020\u001c2\b\b\u0002\u0010\u0013\u001a\u00020\u00142#\b\u0002\u00105\u001a\u001d\u0012\u0013\u0012\u00110\b¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\u001e\u0012\u0004\u0012\u00020\b0\u0016H\u0007ø\u0001\u0000\u001aT\u00106\u001a\u00020&2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\b0\u00102\b\b\u0002\u00102\u001a\u00020 2\b\b\u0002\u0010\u0013\u001a\u00020\u00142#\b\u0002\u00107\u001a\u001d\u0012\u0013\u0012\u00110\u0017¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u00170\u0016H\u0007ø\u0001\u0000\u001a>\u00108\u001a\u00020\u000e2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00060\u00102!\u00109\u001a\u001d\u0012\u0013\u0012\u00110\b¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\u001e\u0012\u0004\u0012\u00020\u00060\u0016H\u0007ø\u0001\u0000\u001a@\u0010:\u001a\u00020\u000e2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00060\u00102#\b\u0002\u0010;\u001a\u001d\u0012\u0013\u0012\u00110\u0017¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\u001a\u0012\u0004\u0012\u00020\u00170\u0016H\u0007ø\u0001\u0000\u001a@\u0010<\u001a\u00020\u000e2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00060\u00102#\b\u0002\u0010=\u001a\u001d\u0012\u0013\u0012\u00110\u0017¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u00170\u0016H\u0007ø\u0001\u0000\u001a>\u0010>\u001a\u00020&2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00060\u00102!\u0010?\u001a\u001d\u0012\u0013\u0012\u00110\b¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\u001e\u0012\u0004\u0012\u00020\u00060\u0016H\u0007ø\u0001\u0000\u001a@\u0010@\u001a\u00020&2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00060\u00102#\b\u0002\u0010A\u001a\u001d\u0012\u0013\u0012\u00110\u0017¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\u001a\u0012\u0004\u0012\u00020\u00170\u0016H\u0007ø\u0001\u0000\u001a@\u0010B\u001a\u00020&2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00060\u00102#\b\u0002\u0010C\u001a\u001d\u0012\u0013\u0012\u00110\u0017¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u00170\u0016H\u0007ø\u0001\u0000\u001a/\u0010D\u001a\u00020E*\b\u0012\u0004\u0012\u00020G0F2\u0006\u0010H\u001a\u00020\u000e2\u0006\u0010I\u001a\u00020&2\u0006\u0010J\u001a\u00020KH\u0001¢\u0006\u0002\u0010L\u001aB\u0010M\u001a\u00020E*\u00020E2\f\u0010N\u001a\b\u0012\u0004\u0012\u00020G0F2\u000e\u0010O\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010Q0P2\u000e\u0010R\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010Q0P2\u0006\u0010S\u001a\u00020KH\u0002\u001aB\u0010T\u001a\u00020E*\u00020E2\f\u0010N\u001a\b\u0012\u0004\u0012\u00020G0F2\u000e\u00108\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010U0P2\u000e\u0010>\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010U0P2\u0006\u0010S\u001a\u00020KH\u0002\u001a\f\u0010V\u001a\u00020\u001c*\u00020\u0012H\u0002\u001a\f\u0010V\u001a\u00020\u001c*\u00020 H\u0002\"\u0014\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\u00020\u0001X\u0082\u0004¢\u0006\u0002\n\u0000\"\u0014\u0010\u0003\u001a\b\u0012\u0004\u0012\u00020\u00020\u0004X\u0082\u0004¢\u0006\u0002\n\u0000\"\u0017\u0010\u0005\u001a\b\u0012\u0004\u0012\u00020\u00060\u0004X\u0082\u0004ø\u0001\u0000¢\u0006\u0002\n\u0000\"\u0017\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\b0\u0004X\u0082\u0004ø\u0001\u0000¢\u0006\u0002\n\u0000\"\u001d\u0010\t\u001a\u000e\u0012\u0004\u0012\u00020\u000b\u0012\u0004\u0012\u00020\f0\nX\u0082\u0004ø\u0001\u0000¢\u0006\u0002\n\u0000\u0082\u0002\u000b\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001¨\u0006W"}, d2 = {"DefaultAlpha", "Landroidx/compose/runtime/MutableState;", "", "DefaultAlphaAndScaleSpring", "Landroidx/compose/animation/core/SpringSpec;", "DefaultOffsetAnimationSpec", "Landroidx/compose/ui/unit/IntOffset;", "DefaultSizeAnimationSpec", "Landroidx/compose/ui/unit/IntSize;", "TransformOriginVectorConverter", "Landroidx/compose/animation/core/TwoWayConverter;", "Landroidx/compose/ui/graphics/TransformOrigin;", "Landroidx/compose/animation/core/AnimationVector2D;", "expandHorizontally", "Landroidx/compose/animation/EnterTransition;", "animationSpec", "Landroidx/compose/animation/core/FiniteAnimationSpec;", "expandFrom", "Landroidx/compose/ui/Alignment$Horizontal;", "clip", "", "initialWidth", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", HintConstants.AUTOFILL_HINT_NAME, "fullWidth", "expandIn", "Landroidx/compose/ui/Alignment;", "initialSize", "fullSize", "expandVertically", "Landroidx/compose/ui/Alignment$Vertical;", "initialHeight", "fullHeight", "fadeIn", "initialAlpha", "fadeOut", "Landroidx/compose/animation/ExitTransition;", "targetAlpha", "scaleIn", "initialScale", "transformOrigin", "scaleIn-L8ZKh-E", "(Landroidx/compose/animation/core/FiniteAnimationSpec;FJ)Landroidx/compose/animation/EnterTransition;", "scaleOut", "targetScale", "scaleOut-L8ZKh-E", "(Landroidx/compose/animation/core/FiniteAnimationSpec;FJ)Landroidx/compose/animation/ExitTransition;", "shrinkHorizontally", "shrinkTowards", "targetWidth", "shrinkOut", "targetSize", "shrinkVertically", "targetHeight", "slideIn", "initialOffset", "slideInHorizontally", "initialOffsetX", "slideInVertically", "initialOffsetY", "slideOut", "targetOffset", "slideOutHorizontally", "targetOffsetX", "slideOutVertically", "targetOffsetY", "createModifier", "Landroidx/compose/ui/Modifier;", "Landroidx/compose/animation/core/Transition;", "Landroidx/compose/animation/EnterExitState;", "enter", "exit", "label", "", "(Landroidx/compose/animation/core/Transition;Landroidx/compose/animation/EnterTransition;Landroidx/compose/animation/ExitTransition;Ljava/lang/String;Landroidx/compose/runtime/Composer;I)Landroidx/compose/ui/Modifier;", "shrinkExpand", "transition", "expand", "Landroidx/compose/runtime/State;", "Landroidx/compose/animation/ChangeSize;", "shrink", "labelPrefix", "slideInOut", "Landroidx/compose/animation/Slide;", "toAlignment", "animation_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class EnterExitTransitionKt {
    private static final MutableState<Float> DefaultAlpha;
    private static final SpringSpec<Float> DefaultAlphaAndScaleSpring;
    private static final SpringSpec<IntOffset> DefaultOffsetAnimationSpec;
    private static final SpringSpec<IntSize> DefaultSizeAnimationSpec;
    private static final TwoWayConverter<TransformOrigin, AnimationVector2D> TransformOriginVectorConverter = VectorConvertersKt.TwoWayConverter(new Function1<TransformOrigin, AnimationVector2D>() { // from class: androidx.compose.animation.EnterExitTransitionKt$TransformOriginVectorConverter$1
        @Override // kotlin.jvm.functions.Function1
        public /* bridge */ /* synthetic */ AnimationVector2D invoke(TransformOrigin transformOrigin) {
            return m46invoke__ExYCQ(transformOrigin.m2986unboximpl());
        }

        /* renamed from: invoke-__ExYCQ  reason: not valid java name */
        public final AnimationVector2D m46invoke__ExYCQ(long it) {
            return new AnimationVector2D(TransformOrigin.m2982getPivotFractionXimpl(it), TransformOrigin.m2983getPivotFractionYimpl(it));
        }
    }, new Function1<AnimationVector2D, TransformOrigin>() { // from class: androidx.compose.animation.EnterExitTransitionKt$TransformOriginVectorConverter$2
        @Override // kotlin.jvm.functions.Function1
        public /* bridge */ /* synthetic */ TransformOrigin invoke(AnimationVector2D animationVector2D) {
            return TransformOrigin.m2974boximpl(m47invokeLIALnN8(animationVector2D));
        }

        /* renamed from: invoke-LIALnN8  reason: not valid java name */
        public final long m47invokeLIALnN8(AnimationVector2D it) {
            Intrinsics.checkNotNullParameter(it, "it");
            return TransformOriginKt.TransformOrigin(it.getV1(), it.getV2());
        }
    });

    /* compiled from: EnterExitTransition.kt */
    @Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[EnterExitState.values().length];
            try {
                iArr[EnterExitState.Visible.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                iArr[EnterExitState.PreEnter.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                iArr[EnterExitState.PostExit.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            $EnumSwitchMapping$0 = iArr;
        }
    }

    public static /* synthetic */ EnterTransition fadeIn$default(FiniteAnimationSpec finiteAnimationSpec, float f, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, null, 5, null);
        }
        if ((i & 2) != 0) {
            f = 0.0f;
        }
        return fadeIn(finiteAnimationSpec, f);
    }

    public static final EnterTransition fadeIn(FiniteAnimationSpec<Float> animationSpec, float initialAlpha) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        return new EnterTransitionImpl(new TransitionData(new Fade(initialAlpha, animationSpec), null, null, null, 14, null));
    }

    public static /* synthetic */ ExitTransition fadeOut$default(FiniteAnimationSpec finiteAnimationSpec, float f, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, null, 5, null);
        }
        if ((i & 2) != 0) {
            f = 0.0f;
        }
        return fadeOut(finiteAnimationSpec, f);
    }

    public static final ExitTransition fadeOut(FiniteAnimationSpec<Float> animationSpec, float targetAlpha) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        return new ExitTransitionImpl(new TransitionData(new Fade(targetAlpha, animationSpec), null, null, null, 14, null));
    }

    public static /* synthetic */ EnterTransition slideIn$default(FiniteAnimationSpec finiteAnimationSpec, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntOffset.m5231boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntOffset.Companion)), 1, null);
        }
        return slideIn(finiteAnimationSpec, function1);
    }

    public static final EnterTransition slideIn(FiniteAnimationSpec<IntOffset> animationSpec, Function1<? super IntSize, IntOffset> initialOffset) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        Intrinsics.checkNotNullParameter(initialOffset, "initialOffset");
        return new EnterTransitionImpl(new TransitionData(null, new Slide(initialOffset, animationSpec), null, null, 13, null));
    }

    public static /* synthetic */ ExitTransition slideOut$default(FiniteAnimationSpec finiteAnimationSpec, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntOffset.m5231boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntOffset.Companion)), 1, null);
        }
        return slideOut(finiteAnimationSpec, function1);
    }

    public static final ExitTransition slideOut(FiniteAnimationSpec<IntOffset> animationSpec, Function1<? super IntSize, IntOffset> targetOffset) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        Intrinsics.checkNotNullParameter(targetOffset, "targetOffset");
        return new ExitTransitionImpl(new TransitionData(null, new Slide(targetOffset, animationSpec), null, null, 13, null));
    }

    /* renamed from: scaleIn-L8ZKh-E$default  reason: not valid java name */
    public static /* synthetic */ EnterTransition m43scaleInL8ZKhE$default(FiniteAnimationSpec finiteAnimationSpec, float f, long j, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, null, 5, null);
        }
        if ((i & 2) != 0) {
            f = 0.0f;
        }
        if ((i & 4) != 0) {
            j = TransformOrigin.Companion.m2987getCenterSzJe1aQ();
        }
        return m42scaleInL8ZKhE(finiteAnimationSpec, f, j);
    }

    /* renamed from: scaleIn-L8ZKh-E  reason: not valid java name */
    public static final EnterTransition m42scaleInL8ZKhE(FiniteAnimationSpec<Float> animationSpec, float initialScale, long transformOrigin) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        return new EnterTransitionImpl(new TransitionData(null, null, null, new Scale(initialScale, transformOrigin, animationSpec, null), 7, null));
    }

    /* renamed from: scaleOut-L8ZKh-E$default  reason: not valid java name */
    public static /* synthetic */ ExitTransition m45scaleOutL8ZKhE$default(FiniteAnimationSpec finiteAnimationSpec, float f, long j, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, null, 5, null);
        }
        if ((i & 2) != 0) {
            f = 0.0f;
        }
        if ((i & 4) != 0) {
            j = TransformOrigin.Companion.m2987getCenterSzJe1aQ();
        }
        return m44scaleOutL8ZKhE(finiteAnimationSpec, f, j);
    }

    /* renamed from: scaleOut-L8ZKh-E  reason: not valid java name */
    public static final ExitTransition m44scaleOutL8ZKhE(FiniteAnimationSpec<Float> animationSpec, float targetScale, long transformOrigin) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        return new ExitTransitionImpl(new TransitionData(null, null, null, new Scale(targetScale, transformOrigin, animationSpec, null), 7, null));
    }

    public static /* synthetic */ EnterTransition expandIn$default(FiniteAnimationSpec finiteAnimationSpec, Alignment alignment, boolean z, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntSize.m5274boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntSize.Companion)), 1, null);
        }
        if ((i & 2) != 0) {
            alignment = Alignment.Companion.getBottomEnd();
        }
        if ((i & 4) != 0) {
            z = true;
        }
        if ((i & 8) != 0) {
            function1 = new Function1<IntSize, IntSize>() { // from class: androidx.compose.animation.EnterExitTransitionKt$expandIn$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ IntSize invoke(IntSize intSize) {
                    return IntSize.m5274boximpl(m49invokemzRDjE0(intSize.m5286unboximpl()));
                }

                /* renamed from: invoke-mzRDjE0  reason: not valid java name */
                public final long m49invokemzRDjE0(long it) {
                    return IntSizeKt.IntSize(0, 0);
                }
            };
        }
        return expandIn(finiteAnimationSpec, alignment, z, function1);
    }

    public static final EnterTransition expandIn(FiniteAnimationSpec<IntSize> animationSpec, Alignment expandFrom, boolean clip, Function1<? super IntSize, IntSize> initialSize) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        Intrinsics.checkNotNullParameter(expandFrom, "expandFrom");
        Intrinsics.checkNotNullParameter(initialSize, "initialSize");
        return new EnterTransitionImpl(new TransitionData(null, null, new ChangeSize(expandFrom, initialSize, animationSpec, clip), null, 11, null));
    }

    public static /* synthetic */ ExitTransition shrinkOut$default(FiniteAnimationSpec finiteAnimationSpec, Alignment alignment, boolean z, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntSize.m5274boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntSize.Companion)), 1, null);
        }
        if ((i & 2) != 0) {
            alignment = Alignment.Companion.getBottomEnd();
        }
        if ((i & 4) != 0) {
            z = true;
        }
        if ((i & 8) != 0) {
            function1 = new Function1<IntSize, IntSize>() { // from class: androidx.compose.animation.EnterExitTransitionKt$shrinkOut$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ IntSize invoke(IntSize intSize) {
                    return IntSize.m5274boximpl(m52invokemzRDjE0(intSize.m5286unboximpl()));
                }

                /* renamed from: invoke-mzRDjE0  reason: not valid java name */
                public final long m52invokemzRDjE0(long it) {
                    return IntSizeKt.IntSize(0, 0);
                }
            };
        }
        return shrinkOut(finiteAnimationSpec, alignment, z, function1);
    }

    public static final ExitTransition shrinkOut(FiniteAnimationSpec<IntSize> animationSpec, Alignment shrinkTowards, boolean clip, Function1<? super IntSize, IntSize> targetSize) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        Intrinsics.checkNotNullParameter(shrinkTowards, "shrinkTowards");
        Intrinsics.checkNotNullParameter(targetSize, "targetSize");
        return new ExitTransitionImpl(new TransitionData(null, null, new ChangeSize(shrinkTowards, targetSize, animationSpec, clip), null, 11, null));
    }

    public static /* synthetic */ EnterTransition expandHorizontally$default(FiniteAnimationSpec finiteAnimationSpec, Alignment.Horizontal horizontal, boolean z, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntSize.m5274boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntSize.Companion)), 1, null);
        }
        if ((i & 2) != 0) {
            horizontal = Alignment.Companion.getEnd();
        }
        if ((i & 4) != 0) {
            z = true;
        }
        if ((i & 8) != 0) {
            function1 = new Function1<Integer, Integer>() { // from class: androidx.compose.animation.EnterExitTransitionKt$expandHorizontally$1
                public final Integer invoke(int it) {
                    return 0;
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Integer invoke(Integer num) {
                    return invoke(num.intValue());
                }
            };
        }
        return expandHorizontally(finiteAnimationSpec, horizontal, z, function1);
    }

    public static final EnterTransition expandHorizontally(FiniteAnimationSpec<IntSize> animationSpec, Alignment.Horizontal expandFrom, boolean clip, final Function1<? super Integer, Integer> initialWidth) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        Intrinsics.checkNotNullParameter(expandFrom, "expandFrom");
        Intrinsics.checkNotNullParameter(initialWidth, "initialWidth");
        return expandIn(animationSpec, toAlignment(expandFrom), clip, new Function1<IntSize, IntSize>() { // from class: androidx.compose.animation.EnterExitTransitionKt$expandHorizontally$2
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ IntSize invoke(IntSize intSize) {
                return IntSize.m5274boximpl(m48invokemzRDjE0(intSize.m5286unboximpl()));
            }

            /* renamed from: invoke-mzRDjE0  reason: not valid java name */
            public final long m48invokemzRDjE0(long it) {
                return IntSizeKt.IntSize(initialWidth.invoke(Integer.valueOf(IntSize.m5282getWidthimpl(it))).intValue(), IntSize.m5281getHeightimpl(it));
            }
        });
    }

    public static /* synthetic */ EnterTransition expandVertically$default(FiniteAnimationSpec finiteAnimationSpec, Alignment.Vertical vertical, boolean z, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntSize.m5274boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntSize.Companion)), 1, null);
        }
        if ((i & 2) != 0) {
            vertical = Alignment.Companion.getBottom();
        }
        if ((i & 4) != 0) {
            z = true;
        }
        if ((i & 8) != 0) {
            function1 = new Function1<Integer, Integer>() { // from class: androidx.compose.animation.EnterExitTransitionKt$expandVertically$1
                public final Integer invoke(int it) {
                    return 0;
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Integer invoke(Integer num) {
                    return invoke(num.intValue());
                }
            };
        }
        return expandVertically(finiteAnimationSpec, vertical, z, function1);
    }

    public static final EnterTransition expandVertically(FiniteAnimationSpec<IntSize> animationSpec, Alignment.Vertical expandFrom, boolean clip, final Function1<? super Integer, Integer> initialHeight) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        Intrinsics.checkNotNullParameter(expandFrom, "expandFrom");
        Intrinsics.checkNotNullParameter(initialHeight, "initialHeight");
        return expandIn(animationSpec, toAlignment(expandFrom), clip, new Function1<IntSize, IntSize>() { // from class: androidx.compose.animation.EnterExitTransitionKt$expandVertically$2
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ IntSize invoke(IntSize intSize) {
                return IntSize.m5274boximpl(m50invokemzRDjE0(intSize.m5286unboximpl()));
            }

            /* renamed from: invoke-mzRDjE0  reason: not valid java name */
            public final long m50invokemzRDjE0(long it) {
                return IntSizeKt.IntSize(IntSize.m5282getWidthimpl(it), initialHeight.invoke(Integer.valueOf(IntSize.m5281getHeightimpl(it))).intValue());
            }
        });
    }

    public static /* synthetic */ ExitTransition shrinkHorizontally$default(FiniteAnimationSpec finiteAnimationSpec, Alignment.Horizontal horizontal, boolean z, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntSize.m5274boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntSize.Companion)), 1, null);
        }
        if ((i & 2) != 0) {
            horizontal = Alignment.Companion.getEnd();
        }
        if ((i & 4) != 0) {
            z = true;
        }
        if ((i & 8) != 0) {
            function1 = new Function1<Integer, Integer>() { // from class: androidx.compose.animation.EnterExitTransitionKt$shrinkHorizontally$1
                public final Integer invoke(int it) {
                    return 0;
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Integer invoke(Integer num) {
                    return invoke(num.intValue());
                }
            };
        }
        return shrinkHorizontally(finiteAnimationSpec, horizontal, z, function1);
    }

    public static final ExitTransition shrinkHorizontally(FiniteAnimationSpec<IntSize> animationSpec, Alignment.Horizontal shrinkTowards, boolean clip, final Function1<? super Integer, Integer> targetWidth) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        Intrinsics.checkNotNullParameter(shrinkTowards, "shrinkTowards");
        Intrinsics.checkNotNullParameter(targetWidth, "targetWidth");
        return shrinkOut(animationSpec, toAlignment(shrinkTowards), clip, new Function1<IntSize, IntSize>() { // from class: androidx.compose.animation.EnterExitTransitionKt$shrinkHorizontally$2
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ IntSize invoke(IntSize intSize) {
                return IntSize.m5274boximpl(m51invokemzRDjE0(intSize.m5286unboximpl()));
            }

            /* renamed from: invoke-mzRDjE0  reason: not valid java name */
            public final long m51invokemzRDjE0(long it) {
                return IntSizeKt.IntSize(targetWidth.invoke(Integer.valueOf(IntSize.m5282getWidthimpl(it))).intValue(), IntSize.m5281getHeightimpl(it));
            }
        });
    }

    public static /* synthetic */ ExitTransition shrinkVertically$default(FiniteAnimationSpec finiteAnimationSpec, Alignment.Vertical vertical, boolean z, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntSize.m5274boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntSize.Companion)), 1, null);
        }
        if ((i & 2) != 0) {
            vertical = Alignment.Companion.getBottom();
        }
        if ((i & 4) != 0) {
            z = true;
        }
        if ((i & 8) != 0) {
            function1 = new Function1<Integer, Integer>() { // from class: androidx.compose.animation.EnterExitTransitionKt$shrinkVertically$1
                public final Integer invoke(int it) {
                    return 0;
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Integer invoke(Integer num) {
                    return invoke(num.intValue());
                }
            };
        }
        return shrinkVertically(finiteAnimationSpec, vertical, z, function1);
    }

    public static final ExitTransition shrinkVertically(FiniteAnimationSpec<IntSize> animationSpec, Alignment.Vertical shrinkTowards, boolean clip, final Function1<? super Integer, Integer> targetHeight) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        Intrinsics.checkNotNullParameter(shrinkTowards, "shrinkTowards");
        Intrinsics.checkNotNullParameter(targetHeight, "targetHeight");
        return shrinkOut(animationSpec, toAlignment(shrinkTowards), clip, new Function1<IntSize, IntSize>() { // from class: androidx.compose.animation.EnterExitTransitionKt$shrinkVertically$2
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ IntSize invoke(IntSize intSize) {
                return IntSize.m5274boximpl(m53invokemzRDjE0(intSize.m5286unboximpl()));
            }

            /* renamed from: invoke-mzRDjE0  reason: not valid java name */
            public final long m53invokemzRDjE0(long it) {
                return IntSizeKt.IntSize(IntSize.m5282getWidthimpl(it), targetHeight.invoke(Integer.valueOf(IntSize.m5281getHeightimpl(it))).intValue());
            }
        });
    }

    public static /* synthetic */ EnterTransition slideInHorizontally$default(FiniteAnimationSpec finiteAnimationSpec, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntOffset.m5231boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntOffset.Companion)), 1, null);
        }
        if ((i & 2) != 0) {
            function1 = new Function1<Integer, Integer>() { // from class: androidx.compose.animation.EnterExitTransitionKt$slideInHorizontally$1
                public final Integer invoke(int it) {
                    return Integer.valueOf((-it) / 2);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Integer invoke(Integer num) {
                    return invoke(num.intValue());
                }
            };
        }
        return slideInHorizontally(finiteAnimationSpec, function1);
    }

    public static final EnterTransition slideInHorizontally(FiniteAnimationSpec<IntOffset> animationSpec, final Function1<? super Integer, Integer> initialOffsetX) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        Intrinsics.checkNotNullParameter(initialOffsetX, "initialOffsetX");
        return slideIn(animationSpec, new Function1<IntSize, IntOffset>() { // from class: androidx.compose.animation.EnterExitTransitionKt$slideInHorizontally$2
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ IntOffset invoke(IntSize intSize) {
                return IntOffset.m5231boximpl(m54invokemHKZG7I(intSize.m5286unboximpl()));
            }

            /* renamed from: invoke-mHKZG7I  reason: not valid java name */
            public final long m54invokemHKZG7I(long it) {
                return IntOffsetKt.IntOffset(initialOffsetX.invoke(Integer.valueOf(IntSize.m5282getWidthimpl(it))).intValue(), 0);
            }
        });
    }

    public static /* synthetic */ EnterTransition slideInVertically$default(FiniteAnimationSpec finiteAnimationSpec, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntOffset.m5231boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntOffset.Companion)), 1, null);
        }
        if ((i & 2) != 0) {
            function1 = new Function1<Integer, Integer>() { // from class: androidx.compose.animation.EnterExitTransitionKt$slideInVertically$1
                public final Integer invoke(int it) {
                    return Integer.valueOf((-it) / 2);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Integer invoke(Integer num) {
                    return invoke(num.intValue());
                }
            };
        }
        return slideInVertically(finiteAnimationSpec, function1);
    }

    public static final EnterTransition slideInVertically(FiniteAnimationSpec<IntOffset> animationSpec, final Function1<? super Integer, Integer> initialOffsetY) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        Intrinsics.checkNotNullParameter(initialOffsetY, "initialOffsetY");
        return slideIn(animationSpec, new Function1<IntSize, IntOffset>() { // from class: androidx.compose.animation.EnterExitTransitionKt$slideInVertically$2
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ IntOffset invoke(IntSize intSize) {
                return IntOffset.m5231boximpl(m55invokemHKZG7I(intSize.m5286unboximpl()));
            }

            /* renamed from: invoke-mHKZG7I  reason: not valid java name */
            public final long m55invokemHKZG7I(long it) {
                return IntOffsetKt.IntOffset(0, initialOffsetY.invoke(Integer.valueOf(IntSize.m5281getHeightimpl(it))).intValue());
            }
        });
    }

    public static /* synthetic */ ExitTransition slideOutHorizontally$default(FiniteAnimationSpec finiteAnimationSpec, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntOffset.m5231boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntOffset.Companion)), 1, null);
        }
        if ((i & 2) != 0) {
            function1 = new Function1<Integer, Integer>() { // from class: androidx.compose.animation.EnterExitTransitionKt$slideOutHorizontally$1
                public final Integer invoke(int it) {
                    return Integer.valueOf((-it) / 2);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Integer invoke(Integer num) {
                    return invoke(num.intValue());
                }
            };
        }
        return slideOutHorizontally(finiteAnimationSpec, function1);
    }

    public static final ExitTransition slideOutHorizontally(FiniteAnimationSpec<IntOffset> animationSpec, final Function1<? super Integer, Integer> targetOffsetX) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        Intrinsics.checkNotNullParameter(targetOffsetX, "targetOffsetX");
        return slideOut(animationSpec, new Function1<IntSize, IntOffset>() { // from class: androidx.compose.animation.EnterExitTransitionKt$slideOutHorizontally$2
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ IntOffset invoke(IntSize intSize) {
                return IntOffset.m5231boximpl(m56invokemHKZG7I(intSize.m5286unboximpl()));
            }

            /* renamed from: invoke-mHKZG7I  reason: not valid java name */
            public final long m56invokemHKZG7I(long it) {
                return IntOffsetKt.IntOffset(targetOffsetX.invoke(Integer.valueOf(IntSize.m5282getWidthimpl(it))).intValue(), 0);
            }
        });
    }

    public static /* synthetic */ ExitTransition slideOutVertically$default(FiniteAnimationSpec finiteAnimationSpec, Function1 function1, int i, Object obj) {
        if ((i & 1) != 0) {
            finiteAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntOffset.m5231boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntOffset.Companion)), 1, null);
        }
        if ((i & 2) != 0) {
            function1 = new Function1<Integer, Integer>() { // from class: androidx.compose.animation.EnterExitTransitionKt$slideOutVertically$1
                public final Integer invoke(int it) {
                    return Integer.valueOf((-it) / 2);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Integer invoke(Integer num) {
                    return invoke(num.intValue());
                }
            };
        }
        return slideOutVertically(finiteAnimationSpec, function1);
    }

    public static final ExitTransition slideOutVertically(FiniteAnimationSpec<IntOffset> animationSpec, final Function1<? super Integer, Integer> targetOffsetY) {
        Intrinsics.checkNotNullParameter(animationSpec, "animationSpec");
        Intrinsics.checkNotNullParameter(targetOffsetY, "targetOffsetY");
        return slideOut(animationSpec, new Function1<IntSize, IntOffset>() { // from class: androidx.compose.animation.EnterExitTransitionKt$slideOutVertically$2
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ IntOffset invoke(IntSize intSize) {
                return IntOffset.m5231boximpl(m57invokemHKZG7I(intSize.m5286unboximpl()));
            }

            /* renamed from: invoke-mHKZG7I  reason: not valid java name */
            public final long m57invokemHKZG7I(long it) {
                return IntOffsetKt.IntOffset(0, targetOffsetY.invoke(Integer.valueOf(IntSize.m5281getHeightimpl(it))).intValue());
            }
        });
    }

    private static final Alignment toAlignment(Alignment.Horizontal $this$toAlignment) {
        return Intrinsics.areEqual($this$toAlignment, Alignment.Companion.getStart()) ? Alignment.Companion.getCenterStart() : Intrinsics.areEqual($this$toAlignment, Alignment.Companion.getEnd()) ? Alignment.Companion.getCenterEnd() : Alignment.Companion.getCenter();
    }

    private static final Alignment toAlignment(Alignment.Vertical $this$toAlignment) {
        return Intrinsics.areEqual($this$toAlignment, Alignment.Companion.getTop()) ? Alignment.Companion.getTopCenter() : Intrinsics.areEqual($this$toAlignment, Alignment.Companion.getBottom()) ? Alignment.Companion.getBottomCenter() : Alignment.Companion.getCenter();
    }

    public static final Modifier createModifier(Transition<EnterExitState> transition, final EnterTransition enter, final ExitTransition exit, String label, Composer $composer, int $changed) {
        Object value$iv$iv;
        Object value$iv$iv2;
        TransformOrigin transformOrigin;
        Object value$iv$iv3;
        Object value$iv$iv4;
        String str;
        String str2;
        String str3;
        TransformOrigin transformOrigin2;
        Modifier modifier;
        MutableState shouldAnimateAlpha$delegate;
        MutableState<Float> mutableState;
        Modifier modifier2;
        Object value$iv$iv5;
        Object obj;
        String str4;
        float f;
        String str5;
        TransformOrigin m2974boximpl;
        TransformOrigin transformOrigin3;
        TransformOrigin transformOrigin4;
        Object value$iv$iv6;
        String str6;
        float f2;
        float f3;
        Intrinsics.checkNotNullParameter(transition, "<this>");
        Intrinsics.checkNotNullParameter(enter, "enter");
        Intrinsics.checkNotNullParameter(exit, "exit");
        Intrinsics.checkNotNullParameter(label, "label");
        $composer.startReplaceableGroup(914000546);
        ComposerKt.sourceInformation($composer, "C(createModifier)832@36300L38,833@36348L37,837@36443L43,838@36496L42,845@36867L40,846@36938L40:EnterExitTransition.kt#xbi5r1");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(914000546, $changed, -1, "androidx.compose.animation.createModifier (EnterExitTransition.kt:820)");
        }
        Modifier modifier3 = shrinkExpand(slideInOut(Modifier.Companion, transition, SnapshotStateKt.rememberUpdatedState(enter.getData$animation_release().getSlide(), $composer, 0), SnapshotStateKt.rememberUpdatedState(exit.getData$animation_release().getSlide(), $composer, 0), label), transition, SnapshotStateKt.rememberUpdatedState(enter.getData$animation_release().getChangeSize(), $composer, 0), SnapshotStateKt.rememberUpdatedState(exit.getData$animation_release().getChangeSize(), $composer, 0), label);
        int i = $changed & 14;
        $composer.startReplaceableGroup(1157296644);
        ComposerKt.sourceInformation($composer, "C(remember)P(1):Composables.kt#9igjgp");
        boolean invalid$iv$iv = $composer.changed(transition);
        Object it$iv$iv = $composer.rememberedValue();
        if (invalid$iv$iv || it$iv$iv == Composer.Companion.getEmpty()) {
            value$iv$iv = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(false, null, 2, null);
            $composer.updateRememberedValue(value$iv$iv);
            value$iv$iv2 = value$iv$iv;
        } else {
            value$iv$iv2 = it$iv$iv;
        }
        $composer.endReplaceableGroup();
        MutableState shouldAnimateAlpha$delegate2 = (MutableState) value$iv$iv2;
        int i2 = $changed & 14;
        $composer.startReplaceableGroup(1157296644);
        ComposerKt.sourceInformation($composer, "C(remember)P(1):Composables.kt#9igjgp");
        boolean invalid$iv$iv2 = $composer.changed(transition);
        Object it$iv$iv2 = $composer.rememberedValue();
        if (invalid$iv$iv2 || it$iv$iv2 == Composer.Companion.getEmpty()) {
            transformOrigin = null;
            value$iv$iv3 = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(false, null, 2, null);
            $composer.updateRememberedValue(value$iv$iv3);
            value$iv$iv4 = value$iv$iv3;
        } else {
            value$iv$iv4 = it$iv$iv2;
            transformOrigin = null;
        }
        $composer.endReplaceableGroup();
        MutableState shouldAnimateScale$delegate = (MutableState) value$iv$iv4;
        if (transition.getCurrentState() != transition.getTargetState() || transition.isSeeking()) {
            if (enter.getData$animation_release().getFade() != null || exit.getData$animation_release().getFade() != null) {
                createModifier$lambda$2(shouldAnimateAlpha$delegate2, true);
            }
            if (enter.getData$animation_release().getScale() != null || exit.getData$animation_release().getScale() != null) {
                createModifier$lambda$5(shouldAnimateScale$delegate, true);
            }
        } else {
            createModifier$lambda$2(shouldAnimateAlpha$delegate2, false);
            createModifier$lambda$5(shouldAnimateScale$delegate, false);
        }
        $composer.startReplaceableGroup(1657241561);
        ComposerKt.sourceInformation($composer, "870@37922L27,860@37401L796");
        float f4 = 1.0f;
        if (createModifier$lambda$1(shouldAnimateAlpha$delegate2)) {
            Function3 transitionSpec$iv = new Function3<Transition.Segment<EnterExitState>, Composer, Integer, FiniteAnimationSpec<Float>>() { // from class: androidx.compose.animation.EnterExitTransitionKt$createModifier$alpha$2
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(3);
                }

                @Override // kotlin.jvm.functions.Function3
                public /* bridge */ /* synthetic */ FiniteAnimationSpec<Float> invoke(Transition.Segment<EnterExitState> segment, Composer composer, Integer num) {
                    return invoke(segment, composer, num.intValue());
                }

                public final FiniteAnimationSpec<Float> invoke(Transition.Segment<EnterExitState> animateFloat, Composer $composer2, int $changed2) {
                    SpringSpec springSpec;
                    SpringSpec springSpec2;
                    SpringSpec springSpec3;
                    SpringSpec springSpec4;
                    Intrinsics.checkNotNullParameter(animateFloat, "$this$animateFloat");
                    $composer2.startReplaceableGroup(-57153604);
                    if (ComposerKt.isTraceInProgress()) {
                        ComposerKt.traceEventStart(-57153604, $changed2, -1, "androidx.compose.animation.createModifier.<anonymous> (EnterExitTransition.kt:861)");
                    }
                    if (animateFloat.isTransitioningTo(EnterExitState.PreEnter, EnterExitState.Visible)) {
                        Fade fade = EnterTransition.this.getData$animation_release().getFade();
                        if (fade == null || (springSpec2 = fade.getAnimationSpec()) == null) {
                            springSpec4 = EnterExitTransitionKt.DefaultAlphaAndScaleSpring;
                            springSpec2 = springSpec4;
                        }
                    } else if (!animateFloat.isTransitioningTo(EnterExitState.Visible, EnterExitState.PostExit)) {
                        springSpec = EnterExitTransitionKt.DefaultAlphaAndScaleSpring;
                        springSpec2 = springSpec;
                    } else {
                        Fade fade2 = exit.getData$animation_release().getFade();
                        if (fade2 == null || (springSpec2 = fade2.getAnimationSpec()) == null) {
                            springSpec3 = EnterExitTransitionKt.DefaultAlphaAndScaleSpring;
                            springSpec2 = springSpec3;
                        }
                    }
                    if (ComposerKt.isTraceInProgress()) {
                        ComposerKt.traceEventEnd();
                    }
                    $composer2.endReplaceableGroup();
                    return springSpec2;
                }
            };
            $composer.startReplaceableGroup(-492369756);
            ComposerKt.sourceInformation($composer, "C(remember):Composables.kt#9igjgp");
            Object value$iv$iv7 = $composer.rememberedValue();
            if (value$iv$iv7 == Composer.Companion.getEmpty()) {
                value$iv$iv7 = label + " alpha";
                $composer.updateRememberedValue(value$iv$iv7);
            }
            $composer.endReplaceableGroup();
            String label$iv = (String) value$iv$iv7;
            int $changed$iv = ($changed & 14) | 384;
            $composer.startReplaceableGroup(-1338768149);
            ComposerKt.sourceInformation($composer, "CC(animateFloat)P(2)938@37489L78:Transition.kt#pdpnli");
            TwoWayConverter typeConverter$iv$iv = VectorConvertersKt.getVectorConverter(FloatCompanionObject.INSTANCE);
            int $changed$iv$iv = (($changed$iv << 3) & 57344) | ($changed$iv & 14) | (($changed$iv << 3) & 896) | (($changed$iv << 3) & 7168);
            $composer.startReplaceableGroup(-142660079);
            ComposerKt.sourceInformation($composer, "CC(animateValue)P(3,2)856@34079L32,857@34134L31,858@34190L23,860@34226L89:Transition.kt#pdpnli");
            int $changed2 = ($changed$iv$iv >> 9) & 112;
            EnterExitState it = transition.getCurrentState();
            $composer.startReplaceableGroup(755689166);
            ComposerKt.sourceInformation($composer, "C:EnterExitTransition.kt#xbi5r1");
            if (ComposerKt.isTraceInProgress()) {
                str6 = "C:EnterExitTransition.kt#xbi5r1";
                ComposerKt.traceEventStart(755689166, $changed2, -1, "androidx.compose.animation.createModifier.<anonymous> (EnterExitTransition.kt:871)");
            } else {
                str6 = "C:EnterExitTransition.kt#xbi5r1";
            }
            switch (WhenMappings.$EnumSwitchMapping$0[it.ordinal()]) {
                case 1:
                    f2 = 1.0f;
                    break;
                case 2:
                    Fade fade = enter.getData$animation_release().getFade();
                    if (fade == null) {
                        f2 = 1.0f;
                        break;
                    } else {
                        f2 = fade.getAlpha();
                        break;
                    }
                case 3:
                    Fade fade2 = exit.getData$animation_release().getFade();
                    if (fade2 == null) {
                        f2 = 1.0f;
                        break;
                    } else {
                        f2 = fade2.getAlpha();
                        break;
                    }
                default:
                    throw new NoWhenBranchMatchedException();
            }
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            $composer.endReplaceableGroup();
            Object initialValue$iv$iv = Float.valueOf(f2);
            String str7 = str6;
            int $changed3 = ($changed$iv$iv >> 9) & 112;
            EnterExitState it2 = transition.getTargetState();
            $composer.startReplaceableGroup(755689166);
            ComposerKt.sourceInformation($composer, str7);
            if (ComposerKt.isTraceInProgress()) {
                shouldAnimateAlpha$delegate = shouldAnimateAlpha$delegate2;
                str = str7;
                ComposerKt.traceEventStart(755689166, $changed3, -1, "androidx.compose.animation.createModifier.<anonymous> (EnterExitTransition.kt:871)");
            } else {
                str = str7;
                shouldAnimateAlpha$delegate = shouldAnimateAlpha$delegate2;
            }
            switch (WhenMappings.$EnumSwitchMapping$0[it2.ordinal()]) {
                case 1:
                    f3 = 1.0f;
                    break;
                case 2:
                    Fade fade3 = enter.getData$animation_release().getFade();
                    if (fade3 == null) {
                        f3 = 1.0f;
                        break;
                    } else {
                        f3 = fade3.getAlpha();
                        break;
                    }
                case 3:
                    Fade fade4 = exit.getData$animation_release().getFade();
                    if (fade4 == null) {
                        f3 = 1.0f;
                        break;
                    } else {
                        f3 = fade4.getAlpha();
                        break;
                    }
                default:
                    throw new NoWhenBranchMatchedException();
            }
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            $composer.endReplaceableGroup();
            Object targetValue$iv$iv = Float.valueOf(f3);
            FiniteAnimationSpec<Float> animationSpec$iv$iv = transitionSpec$iv.invoke(transition.getSegment(), $composer, Integer.valueOf(($changed$iv$iv >> 3) & 112));
            str2 = "CC(animateValue)P(3,2)856@34079L32,857@34134L31,858@34190L23,860@34226L89:Transition.kt#pdpnli";
            str3 = "C(remember)P(1):Composables.kt#9igjgp";
            transformOrigin2 = null;
            modifier = modifier3;
            mutableState = androidx.compose.animation.core.TransitionKt.createTransitionAnimation(transition, initialValue$iv$iv, targetValue$iv$iv, animationSpec$iv$iv, typeConverter$iv$iv, label$iv, $composer, ($changed$iv$iv & 14) | (($changed$iv$iv << 9) & 57344) | (($changed$iv$iv << 6) & 458752));
            $composer.endReplaceableGroup();
            $composer.endReplaceableGroup();
        } else {
            str = "C:EnterExitTransition.kt#xbi5r1";
            str2 = "CC(animateValue)P(3,2)856@34079L32,857@34134L31,858@34190L23,860@34226L89:Transition.kt#pdpnli";
            str3 = "C(remember)P(1):Composables.kt#9igjgp";
            transformOrigin2 = transformOrigin;
            modifier = modifier3;
            shouldAnimateAlpha$delegate = shouldAnimateAlpha$delegate2;
            mutableState = DefaultAlpha;
        }
        $composer.endReplaceableGroup();
        final State alpha$delegate = mutableState;
        if (createModifier$lambda$4(shouldAnimateScale$delegate)) {
            $composer.startReplaceableGroup(1657242461);
            ComposerKt.sourceInformation($composer, "893@38813L27,883@38290L800,909@39583L536,922@40163L157");
            Function3 transitionSpec$iv2 = new Function3<Transition.Segment<EnterExitState>, Composer, Integer, FiniteAnimationSpec<Float>>() { // from class: androidx.compose.animation.EnterExitTransitionKt$createModifier$scale$2
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(3);
                }

                @Override // kotlin.jvm.functions.Function3
                public /* bridge */ /* synthetic */ FiniteAnimationSpec<Float> invoke(Transition.Segment<EnterExitState> segment, Composer composer, Integer num) {
                    return invoke(segment, composer, num.intValue());
                }

                public final FiniteAnimationSpec<Float> invoke(Transition.Segment<EnterExitState> animateFloat, Composer $composer2, int $changed4) {
                    SpringSpec springSpec;
                    SpringSpec springSpec2;
                    SpringSpec springSpec3;
                    SpringSpec springSpec4;
                    Intrinsics.checkNotNullParameter(animateFloat, "$this$animateFloat");
                    $composer2.startReplaceableGroup(-53984035);
                    if (ComposerKt.isTraceInProgress()) {
                        ComposerKt.traceEventStart(-53984035, $changed4, -1, "androidx.compose.animation.createModifier.<anonymous> (EnterExitTransition.kt:884)");
                    }
                    if (animateFloat.isTransitioningTo(EnterExitState.PreEnter, EnterExitState.Visible)) {
                        Scale scale = EnterTransition.this.getData$animation_release().getScale();
                        if (scale == null || (springSpec2 = scale.getAnimationSpec()) == null) {
                            springSpec4 = EnterExitTransitionKt.DefaultAlphaAndScaleSpring;
                            springSpec2 = springSpec4;
                        }
                    } else if (!animateFloat.isTransitioningTo(EnterExitState.Visible, EnterExitState.PostExit)) {
                        springSpec = EnterExitTransitionKt.DefaultAlphaAndScaleSpring;
                        springSpec2 = springSpec;
                    } else {
                        Scale scale2 = exit.getData$animation_release().getScale();
                        if (scale2 == null || (springSpec2 = scale2.getAnimationSpec()) == null) {
                            springSpec3 = EnterExitTransitionKt.DefaultAlphaAndScaleSpring;
                            springSpec2 = springSpec3;
                        }
                    }
                    if (ComposerKt.isTraceInProgress()) {
                        ComposerKt.traceEventEnd();
                    }
                    $composer2.endReplaceableGroup();
                    return springSpec2;
                }
            };
            $composer.startReplaceableGroup(-492369756);
            ComposerKt.sourceInformation($composer, "C(remember):Composables.kt#9igjgp");
            Object it$iv$iv3 = $composer.rememberedValue();
            if (it$iv$iv3 == Composer.Companion.getEmpty()) {
                Object value$iv$iv8 = label + " scale";
                $composer.updateRememberedValue(value$iv$iv8);
                obj = value$iv$iv8;
            } else {
                obj = it$iv$iv3;
            }
            $composer.endReplaceableGroup();
            String label$iv2 = (String) obj;
            int $changed$iv2 = ($changed & 14) | 384;
            $composer.startReplaceableGroup(-1338768149);
            ComposerKt.sourceInformation($composer, "CC(animateFloat)P(2)938@37489L78:Transition.kt#pdpnli");
            TwoWayConverter typeConverter$iv$iv2 = VectorConvertersKt.getVectorConverter(FloatCompanionObject.INSTANCE);
            int $changed$iv$iv2 = (($changed$iv2 << 3) & 57344) | ($changed$iv2 & 14) | (($changed$iv2 << 3) & 896) | (($changed$iv2 << 3) & 7168);
            $composer.startReplaceableGroup(-142660079);
            String str8 = str2;
            ComposerKt.sourceInformation($composer, str8);
            int $changed4 = ($changed$iv$iv2 >> 9) & 112;
            EnterExitState it3 = transition.getCurrentState();
            $composer.startReplaceableGroup(-596129937);
            String str9 = str;
            ComposerKt.sourceInformation($composer, str9);
            if (ComposerKt.isTraceInProgress()) {
                str4 = str8;
                ComposerKt.traceEventStart(-596129937, $changed4, -1, "androidx.compose.animation.createModifier.<anonymous> (EnterExitTransition.kt:894)");
            } else {
                str4 = str8;
            }
            switch (WhenMappings.$EnumSwitchMapping$0[it3.ordinal()]) {
                case 1:
                    f = 1.0f;
                    break;
                case 2:
                    Scale scale = enter.getData$animation_release().getScale();
                    if (scale == null) {
                        f = 1.0f;
                        break;
                    } else {
                        f = scale.getScale();
                        break;
                    }
                case 3:
                    Scale scale2 = exit.getData$animation_release().getScale();
                    if (scale2 == null) {
                        f = 1.0f;
                        break;
                    } else {
                        f = scale2.getScale();
                        break;
                    }
                default:
                    throw new NoWhenBranchMatchedException();
            }
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            $composer.endReplaceableGroup();
            Object initialValue$iv$iv2 = Float.valueOf(f);
            int $changed5 = ($changed$iv$iv2 >> 9) & 112;
            EnterExitState it4 = transition.getTargetState();
            $composer.startReplaceableGroup(-596129937);
            ComposerKt.sourceInformation($composer, str9);
            if (ComposerKt.isTraceInProgress()) {
                str5 = str9;
                ComposerKt.traceEventStart(-596129937, $changed5, -1, "androidx.compose.animation.createModifier.<anonymous> (EnterExitTransition.kt:894)");
            } else {
                str5 = str9;
            }
            switch (WhenMappings.$EnumSwitchMapping$0[it4.ordinal()]) {
                case 1:
                    break;
                case 2:
                    Scale scale3 = enter.getData$animation_release().getScale();
                    if (scale3 != null) {
                        f4 = scale3.getScale();
                        break;
                    }
                    break;
                case 3:
                    Scale scale4 = exit.getData$animation_release().getScale();
                    if (scale4 != null) {
                        f4 = scale4.getScale();
                        break;
                    }
                    break;
                default:
                    throw new NoWhenBranchMatchedException();
            }
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            $composer.endReplaceableGroup();
            Object targetValue$iv$iv2 = Float.valueOf(f4);
            FiniteAnimationSpec<Float> animationSpec$iv$iv2 = transitionSpec$iv2.invoke(transition.getSegment(), $composer, Integer.valueOf(($changed$iv$iv2 >> 3) & 112));
            String str10 = str5;
            String str11 = str4;
            final State scale$delegate = androidx.compose.animation.core.TransitionKt.createTransitionAnimation(transition, initialValue$iv$iv2, targetValue$iv$iv2, animationSpec$iv$iv2, typeConverter$iv$iv2, label$iv2, $composer, ($changed$iv$iv2 & 14) | (($changed$iv$iv2 << 9) & 57344) | (($changed$iv$iv2 << 6) & 458752));
            $composer.endReplaceableGroup();
            $composer.endReplaceableGroup();
            if (transition.getCurrentState() == EnterExitState.PreEnter) {
                Scale scale5 = enter.getData$animation_release().getScale();
                m2974boximpl = (scale5 == null && (scale5 = exit.getData$animation_release().getScale()) == null) ? transformOrigin2 : TransformOrigin.m2974boximpl(scale5.m65getTransformOriginSzJe1aQ());
            } else {
                Scale scale6 = exit.getData$animation_release().getScale();
                m2974boximpl = (scale6 == null && (scale6 = enter.getData$animation_release().getScale()) == null) ? transformOrigin2 : TransformOrigin.m2974boximpl(scale6.m65getTransformOriginSzJe1aQ());
            }
            TransformOrigin transformOriginWhenVisible = m2974boximpl;
            TwoWayConverter typeConverter$iv = TransformOriginVectorConverter;
            int $changed$iv3 = ($changed & 14) | 3136;
            $composer.startReplaceableGroup(-142660079);
            ComposerKt.sourceInformation($composer, str11);
            Function3 transitionSpec$iv3 = new Function3<Transition.Segment<EnterExitState>, Composer, Integer, SpringSpec<TransformOrigin>>() { // from class: androidx.compose.animation.EnterExitTransitionKt$createModifier$$inlined$animateValue$1
                public final SpringSpec<TransformOrigin> invoke(Transition.Segment<EnterExitState> segment, Composer $composer2, int $changed6) {
                    Intrinsics.checkNotNullParameter(segment, "$this$null");
                    $composer2.startReplaceableGroup(-895531546);
                    if (ComposerKt.isTraceInProgress()) {
                        ComposerKt.traceEventStart(-895531546, $changed6, -1, "androidx.compose.animation.core.animateValue.<anonymous> (Transition.kt:851)");
                    }
                    SpringSpec<TransformOrigin> spring$default = AnimationSpecKt.spring$default(0.0f, 0.0f, null, 7, null);
                    if (ComposerKt.isTraceInProgress()) {
                        ComposerKt.traceEventEnd();
                    }
                    $composer2.endReplaceableGroup();
                    return spring$default;
                }

                @Override // kotlin.jvm.functions.Function3
                public /* bridge */ /* synthetic */ SpringSpec<TransformOrigin> invoke(Transition.Segment<EnterExitState> segment, Composer composer, Integer num) {
                    return invoke(segment, composer, num.intValue());
                }
            };
            int $changed6 = ($changed$iv3 >> 9) & 112;
            EnterExitState it5 = transition.getCurrentState();
            $composer.startReplaceableGroup(-288165413);
            ComposerKt.sourceInformation($composer, str10);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(-288165413, $changed6, -1, "androidx.compose.animation.createModifier.<anonymous> (EnterExitTransition.kt:912)");
            }
            switch (WhenMappings.$EnumSwitchMapping$0[it5.ordinal()]) {
                case 1:
                    transformOrigin3 = transformOriginWhenVisible;
                    break;
                case 2:
                    Scale scale7 = enter.getData$animation_release().getScale();
                    if (scale7 != null || (scale7 = exit.getData$animation_release().getScale()) != null) {
                        transformOrigin3 = TransformOrigin.m2974boximpl(scale7.m65getTransformOriginSzJe1aQ());
                        break;
                    } else {
                        transformOrigin3 = transformOrigin2;
                        break;
                    }
                case 3:
                    Scale scale8 = exit.getData$animation_release().getScale();
                    if (scale8 != null || (scale8 = enter.getData$animation_release().getScale()) != null) {
                        transformOrigin3 = TransformOrigin.m2974boximpl(scale8.m65getTransformOriginSzJe1aQ());
                        break;
                    } else {
                        transformOrigin3 = transformOrigin2;
                        break;
                    }
                    break;
                default:
                    throw new NoWhenBranchMatchedException();
            }
            long m2986unboximpl = transformOrigin3 != null ? transformOrigin3.m2986unboximpl() : TransformOrigin.Companion.m2987getCenterSzJe1aQ();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            $composer.endReplaceableGroup();
            Object initialValue$iv = TransformOrigin.m2974boximpl(m2986unboximpl);
            int $changed7 = ($changed$iv3 >> 9) & 112;
            EnterExitState it6 = transition.getTargetState();
            $composer.startReplaceableGroup(-288165413);
            ComposerKt.sourceInformation($composer, str10);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(-288165413, $changed7, -1, "androidx.compose.animation.createModifier.<anonymous> (EnterExitTransition.kt:912)");
            }
            switch (WhenMappings.$EnumSwitchMapping$0[it6.ordinal()]) {
                case 1:
                    transformOrigin4 = transformOriginWhenVisible;
                    break;
                case 2:
                    Scale scale9 = enter.getData$animation_release().getScale();
                    if (scale9 != null || (scale9 = exit.getData$animation_release().getScale()) != null) {
                        transformOrigin4 = TransformOrigin.m2974boximpl(scale9.m65getTransformOriginSzJe1aQ());
                        break;
                    } else {
                        transformOrigin4 = transformOrigin2;
                        break;
                    }
                    break;
                case 3:
                    Scale scale10 = exit.getData$animation_release().getScale();
                    if (scale10 != null || (scale10 = enter.getData$animation_release().getScale()) != null) {
                        transformOrigin4 = TransformOrigin.m2974boximpl(scale10.m65getTransformOriginSzJe1aQ());
                        break;
                    } else {
                        transformOrigin4 = transformOrigin2;
                        break;
                    }
                    break;
                default:
                    throw new NoWhenBranchMatchedException();
            }
            long m2986unboximpl2 = transformOrigin4 != null ? transformOrigin4.m2986unboximpl() : TransformOrigin.Companion.m2987getCenterSzJe1aQ();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            $composer.endReplaceableGroup();
            Object targetValue$iv = TransformOrigin.m2974boximpl(m2986unboximpl2);
            SpringSpec<TransformOrigin> animationSpec$iv = transitionSpec$iv3.invoke(transition.getSegment(), $composer, Integer.valueOf(($changed$iv3 >> 3) & 112));
            final State transformOrigin$delegate = androidx.compose.animation.core.TransitionKt.createTransitionAnimation(transition, initialValue$iv, targetValue$iv, animationSpec$iv, typeConverter$iv, "TransformOriginInterruptionHandling", $composer, ($changed$iv3 & 14) | (($changed$iv3 << 9) & 57344) | (($changed$iv3 << 6) & 458752));
            $composer.endReplaceableGroup();
            $composer.startReplaceableGroup(1618982084);
            ComposerKt.sourceInformation($composer, "C(remember)P(1,2,3):Composables.kt#9igjgp");
            boolean invalid$iv$iv3 = $composer.changed(alpha$delegate) | $composer.changed(scale$delegate) | $composer.changed(transformOrigin$delegate);
            Object it$iv$iv4 = $composer.rememberedValue();
            if (invalid$iv$iv3 || it$iv$iv4 == Composer.Companion.getEmpty()) {
                Object value$iv$iv9 = (Function1) new Function1<GraphicsLayerScope, Unit>() { // from class: androidx.compose.animation.EnterExitTransitionKt$createModifier$1$1
                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(GraphicsLayerScope graphicsLayerScope) {
                        invoke2(graphicsLayerScope);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke  reason: avoid collision after fix types in other method */
                    public final void invoke2(GraphicsLayerScope graphicsLayer) {
                        float createModifier$lambda$8;
                        float createModifier$lambda$11;
                        float createModifier$lambda$112;
                        long createModifier$lambda$13;
                        Intrinsics.checkNotNullParameter(graphicsLayer, "$this$graphicsLayer");
                        createModifier$lambda$8 = EnterExitTransitionKt.createModifier$lambda$8(alpha$delegate);
                        graphicsLayer.setAlpha(createModifier$lambda$8);
                        createModifier$lambda$11 = EnterExitTransitionKt.createModifier$lambda$11(scale$delegate);
                        graphicsLayer.setScaleX(createModifier$lambda$11);
                        createModifier$lambda$112 = EnterExitTransitionKt.createModifier$lambda$11(scale$delegate);
                        graphicsLayer.setScaleY(createModifier$lambda$112);
                        createModifier$lambda$13 = EnterExitTransitionKt.createModifier$lambda$13(transformOrigin$delegate);
                        graphicsLayer.mo2794setTransformOrigin__ExYCQ(createModifier$lambda$13);
                    }
                };
                $composer.updateRememberedValue(value$iv$iv9);
                value$iv$iv6 = value$iv$iv9;
            } else {
                value$iv$iv6 = it$iv$iv4;
            }
            $composer.endReplaceableGroup();
            modifier2 = GraphicsLayerModifierKt.graphicsLayer(modifier, (Function1) value$iv$iv6);
            $composer.endReplaceableGroup();
        } else {
            modifier2 = modifier;
            if (createModifier$lambda$1(shouldAnimateAlpha$delegate)) {
                $composer.startReplaceableGroup(1657244550);
                ComposerKt.sourceInformation($composer, "929@40400L42");
                $composer.startReplaceableGroup(1157296644);
                ComposerKt.sourceInformation($composer, str3);
                boolean invalid$iv$iv4 = $composer.changed(alpha$delegate);
                Object it$iv$iv5 = $composer.rememberedValue();
                if (invalid$iv$iv4 || it$iv$iv5 == Composer.Companion.getEmpty()) {
                    Object value$iv$iv10 = (Function1) new Function1<GraphicsLayerScope, Unit>() { // from class: androidx.compose.animation.EnterExitTransitionKt$createModifier$2$1
                        /* JADX INFO: Access modifiers changed from: package-private */
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(GraphicsLayerScope graphicsLayerScope) {
                            invoke2(graphicsLayerScope);
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke  reason: avoid collision after fix types in other method */
                        public final void invoke2(GraphicsLayerScope graphicsLayer) {
                            float createModifier$lambda$8;
                            Intrinsics.checkNotNullParameter(graphicsLayer, "$this$graphicsLayer");
                            createModifier$lambda$8 = EnterExitTransitionKt.createModifier$lambda$8(alpha$delegate);
                            graphicsLayer.setAlpha(createModifier$lambda$8);
                        }
                    };
                    $composer.updateRememberedValue(value$iv$iv10);
                    value$iv$iv5 = value$iv$iv10;
                } else {
                    value$iv$iv5 = it$iv$iv5;
                }
                $composer.endReplaceableGroup();
                modifier2 = GraphicsLayerModifierKt.graphicsLayer(modifier2, (Function1) value$iv$iv5);
                $composer.endReplaceableGroup();
            } else {
                $composer.startReplaceableGroup(1657244642);
                $composer.endReplaceableGroup();
            }
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return modifier2;
    }

    private static final boolean createModifier$lambda$1(MutableState<Boolean> mutableState) {
        MutableState<Boolean> $this$getValue$iv = mutableState;
        return $this$getValue$iv.getValue().booleanValue();
    }

    private static final void createModifier$lambda$2(MutableState<Boolean> mutableState, boolean value) {
        mutableState.setValue(Boolean.valueOf(value));
    }

    private static final boolean createModifier$lambda$4(MutableState<Boolean> mutableState) {
        MutableState<Boolean> $this$getValue$iv = mutableState;
        return $this$getValue$iv.getValue().booleanValue();
    }

    private static final void createModifier$lambda$5(MutableState<Boolean> mutableState, boolean value) {
        mutableState.setValue(Boolean.valueOf(value));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final float createModifier$lambda$8(State<Float> state) {
        Object thisObj$iv = state.getValue();
        return ((Number) thisObj$iv).floatValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final float createModifier$lambda$11(State<Float> state) {
        Object thisObj$iv = state.getValue();
        return ((Number) thisObj$iv).floatValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final long createModifier$lambda$13(State<TransformOrigin> state) {
        Object thisObj$iv = state.getValue();
        return ((TransformOrigin) thisObj$iv).m2986unboximpl();
    }

    static {
        MutableState<Float> mutableStateOf$default;
        mutableStateOf$default = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(Float.valueOf(1.0f), null, 2, null);
        DefaultAlpha = mutableStateOf$default;
        DefaultAlphaAndScaleSpring = AnimationSpecKt.spring$default(0.0f, 400.0f, null, 5, null);
        DefaultOffsetAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntOffset.m5231boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntOffset.Companion)), 1, null);
        DefaultSizeAnimationSpec = AnimationSpecKt.spring$default(0.0f, 400.0f, IntSize.m5274boximpl(VisibilityThresholdsKt.getVisibilityThreshold(IntSize.Companion)), 1, null);
    }

    private static final Modifier slideInOut(Modifier $this$slideInOut, final Transition<EnterExitState> transition, final State<Slide> state, final State<Slide> state2, final String labelPrefix) {
        return ComposedModifierKt.composed$default($this$slideInOut, null, new Function3<Modifier, Composer, Integer, Modifier>() { // from class: androidx.compose.animation.EnterExitTransitionKt$slideInOut$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(3);
            }

            @Override // kotlin.jvm.functions.Function3
            public /* bridge */ /* synthetic */ Modifier invoke(Modifier modifier, Composer composer, Integer num) {
                return invoke(modifier, composer, num.intValue());
            }

            private static final boolean invoke$lambda$1(MutableState<Boolean> mutableState) {
                MutableState<Boolean> $this$getValue$iv = mutableState;
                return $this$getValue$iv.getValue().booleanValue();
            }

            private static final void invoke$lambda$2(MutableState<Boolean> mutableState, boolean value) {
                mutableState.setValue(Boolean.valueOf(value));
            }

            public final Modifier invoke(Modifier composed, Composer $composer, int $changed) {
                MutableState key1$iv;
                Modifier modifier;
                Object value$iv$iv;
                Object value$iv$iv2;
                Intrinsics.checkNotNullParameter(composed, "$this$composed");
                $composer.startReplaceableGroup(158379472);
                ComposerKt.sourceInformation($composer, "C954@41309L46,966@41734L33,964@41658L119,968@41801L88:EnterExitTransition.kt#xbi5r1");
                if (ComposerKt.isTraceInProgress()) {
                    ComposerKt.traceEventStart(158379472, $changed, -1, "androidx.compose.animation.slideInOut.<anonymous> (EnterExitTransition.kt:951)");
                }
                Object key1$iv2 = transition;
                $composer.startReplaceableGroup(1157296644);
                ComposerKt.sourceInformation($composer, "C(remember)P(1):Composables.kt#9igjgp");
                boolean invalid$iv$iv = $composer.changed(key1$iv2);
                Object it$iv$iv = $composer.rememberedValue();
                if (invalid$iv$iv || it$iv$iv == Composer.Companion.getEmpty()) {
                    key1$iv = SnapshotStateKt__SnapshotStateKt.mutableStateOf$default(false, null, 2, null);
                    $composer.updateRememberedValue(key1$iv);
                } else {
                    key1$iv = it$iv$iv;
                }
                $composer.endReplaceableGroup();
                MutableState shouldAnimate$delegate = key1$iv;
                if (transition.getCurrentState() == transition.getTargetState() && !transition.isSeeking()) {
                    invoke$lambda$2(shouldAnimate$delegate, false);
                } else if (state.getValue() != null || state2.getValue() != null) {
                    invoke$lambda$2(shouldAnimate$delegate, true);
                }
                if (invoke$lambda$1(shouldAnimate$delegate)) {
                    Transition<EnterExitState> transition2 = transition;
                    TwoWayConverter<IntOffset, AnimationVector2D> vectorConverter = VectorConvertersKt.getVectorConverter(IntOffset.Companion);
                    String str = labelPrefix;
                    $composer.startReplaceableGroup(-492369756);
                    ComposerKt.sourceInformation($composer, "C(remember):Composables.kt#9igjgp");
                    Object it$iv$iv2 = $composer.rememberedValue();
                    if (it$iv$iv2 == Composer.Companion.getEmpty()) {
                        value$iv$iv = str + " slide";
                        $composer.updateRememberedValue(value$iv$iv);
                    } else {
                        value$iv$iv = it$iv$iv2;
                    }
                    $composer.endReplaceableGroup();
                    Transition.DeferredAnimation animation = androidx.compose.animation.core.TransitionKt.createDeferredAnimation(transition2, vectorConverter, (String) value$iv$iv, $composer, 448, 0);
                    Object key1$iv3 = transition;
                    State<Slide> state3 = state;
                    State<Slide> state4 = state2;
                    $composer.startReplaceableGroup(1157296644);
                    ComposerKt.sourceInformation($composer, "C(remember)P(1):Composables.kt#9igjgp");
                    boolean invalid$iv$iv2 = $composer.changed(key1$iv3);
                    Object it$iv$iv3 = $composer.rememberedValue();
                    if (invalid$iv$iv2 || it$iv$iv3 == Composer.Companion.getEmpty()) {
                        value$iv$iv2 = new SlideModifier(animation, state3, state4);
                        $composer.updateRememberedValue(value$iv$iv2);
                    } else {
                        value$iv$iv2 = it$iv$iv3;
                    }
                    $composer.endReplaceableGroup();
                    SlideModifier modifier2 = (SlideModifier) value$iv$iv2;
                    modifier = composed.then(modifier2);
                } else {
                    modifier = composed;
                }
                if (ComposerKt.isTraceInProgress()) {
                    ComposerKt.traceEventEnd();
                }
                $composer.endReplaceableGroup();
                return modifier;
            }
        }, 1, null);
    }

    private static final Modifier shrinkExpand(Modifier $this$shrinkExpand, final Transition<EnterExitState> transition, final State<ChangeSize> state, final State<ChangeSize> state2, final String labelPrefix) {
        return ComposedModifierKt.composed$default($this$shrinkExpand, null, new Function3<Modifier, Composer, Integer, Modifier>() { // from class: androidx.compose.animation.EnterExitTransitionKt$shrinkExpand$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(3);
            }

            @Override // kotlin.jvm.functions.Function3
            public /* bridge */ /* synthetic */ Modifier invoke(Modifier modifier, Composer composer, Integer num) {
                return invoke(modifier, composer, num.intValue());
            }

            private static final boolean invoke$lambda$1(MutableState<Boolean> mutableState) {
                MutableState<Boolean> $this$getValue$iv = mutableState;
                return $this$getValue$iv.getValue().booleanValue();
            }

            private static final void invoke$lambda$2(MutableState<Boolean> mutableState, boolean value) {
                mutableState.setValue(Boolean.valueOf(value));
            }

            /* JADX WARN: Removed duplicated region for block: B:67:0x0233  */
            /* JADX WARN: Removed duplicated region for block: B:68:0x0238  */
            /* JADX WARN: Removed duplicated region for block: B:81:0x0264  */
            /* JADX WARN: Removed duplicated region for block: B:94:0x0288  */
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public final androidx.compose.ui.Modifier invoke(androidx.compose.ui.Modifier r27, androidx.compose.runtime.Composer r28, int r29) {
                /*
                    Method dump skipped, instructions count: 678
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.EnterExitTransitionKt$shrinkExpand$1.invoke(androidx.compose.ui.Modifier, androidx.compose.runtime.Composer, int):androidx.compose.ui.Modifier");
            }
        }, 1, null);
    }
}
