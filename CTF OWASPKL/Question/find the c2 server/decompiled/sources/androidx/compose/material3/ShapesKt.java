package androidx.compose.material3;

import androidx.compose.foundation.shape.CornerBasedShape;
import androidx.compose.foundation.shape.CornerSizeKt;
import androidx.compose.foundation.shape.RoundedCornerShapeKt;
import androidx.compose.material3.tokens.ShapeKeyTokens;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.CompositionLocalKt;
import androidx.compose.runtime.ProvidableCompositionLocal;
import androidx.compose.ui.graphics.RectangleShapeKt;
import androidx.compose.ui.graphics.Shape;
import androidx.compose.ui.unit.Dp;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: Shapes.kt */
@Metadata(d1 = {"\u0000\"\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\u001a\f\u0010\u0005\u001a\u00020\u0006*\u00020\u0006H\u0000\u001a\u0014\u0010\u0007\u001a\u00020\b*\u00020\u00022\u0006\u0010\t\u001a\u00020\nH\u0000\u001a\u0011\u0010\u000b\u001a\u00020\b*\u00020\nH\u0001¢\u0006\u0002\u0010\f\u001a\f\u0010\r\u001a\u00020\u0006*\u00020\u0006H\u0000\"\u001a\u0010\u0000\u001a\b\u0012\u0004\u0012\u00020\u00020\u0001X\u0080\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0003\u0010\u0004¨\u0006\u000e"}, d2 = {"LocalShapes", "Landroidx/compose/runtime/ProvidableCompositionLocal;", "Landroidx/compose/material3/Shapes;", "getLocalShapes", "()Landroidx/compose/runtime/ProvidableCompositionLocal;", "end", "Landroidx/compose/foundation/shape/CornerBasedShape;", "fromToken", "Landroidx/compose/ui/graphics/Shape;", "value", "Landroidx/compose/material3/tokens/ShapeKeyTokens;", "toShape", "(Landroidx/compose/material3/tokens/ShapeKeyTokens;Landroidx/compose/runtime/Composer;I)Landroidx/compose/ui/graphics/Shape;", "top", "material3_release"}, k = 2, mv = {1, 7, 1}, xi = 48)
/* loaded from: classes.dex */
public final class ShapesKt {
    private static final ProvidableCompositionLocal<Shapes> LocalShapes = CompositionLocalKt.staticCompositionLocalOf(new Function0<Shapes>() { // from class: androidx.compose.material3.ShapesKt$LocalShapes$1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        public final Shapes invoke() {
            return new Shapes(null, null, null, null, null, 31, null);
        }
    });

    /* compiled from: Shapes.kt */
    @Metadata(k = 3, mv = {1, 7, 1}, xi = 48)
    /* loaded from: classes.dex */
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[ShapeKeyTokens.values().length];
            iArr[ShapeKeyTokens.CornerExtraLarge.ordinal()] = 1;
            iArr[ShapeKeyTokens.CornerExtraLargeTop.ordinal()] = 2;
            iArr[ShapeKeyTokens.CornerExtraSmall.ordinal()] = 3;
            iArr[ShapeKeyTokens.CornerExtraSmallTop.ordinal()] = 4;
            iArr[ShapeKeyTokens.CornerFull.ordinal()] = 5;
            iArr[ShapeKeyTokens.CornerLarge.ordinal()] = 6;
            iArr[ShapeKeyTokens.CornerLargeEnd.ordinal()] = 7;
            iArr[ShapeKeyTokens.CornerLargeTop.ordinal()] = 8;
            iArr[ShapeKeyTokens.CornerMedium.ordinal()] = 9;
            iArr[ShapeKeyTokens.CornerNone.ordinal()] = 10;
            iArr[ShapeKeyTokens.CornerSmall.ordinal()] = 11;
            $EnumSwitchMapping$0 = iArr;
        }
    }

    public static final CornerBasedShape top(CornerBasedShape $this$top) {
        Intrinsics.checkNotNullParameter($this$top, "<this>");
        return CornerBasedShape.copy$default($this$top, null, null, CornerSizeKt.m680CornerSize0680j_4(Dp.m5122constructorimpl((float) 0.0d)), CornerSizeKt.m680CornerSize0680j_4(Dp.m5122constructorimpl((float) 0.0d)), 3, null);
    }

    public static final CornerBasedShape end(CornerBasedShape $this$end) {
        Intrinsics.checkNotNullParameter($this$end, "<this>");
        return CornerBasedShape.copy$default($this$end, CornerSizeKt.m680CornerSize0680j_4(Dp.m5122constructorimpl((float) 0.0d)), null, null, CornerSizeKt.m680CornerSize0680j_4(Dp.m5122constructorimpl((float) 0.0d)), 6, null);
    }

    public static final Shape fromToken(Shapes $this$fromToken, ShapeKeyTokens value) {
        Intrinsics.checkNotNullParameter($this$fromToken, "<this>");
        Intrinsics.checkNotNullParameter(value, "value");
        switch (WhenMappings.$EnumSwitchMapping$0[value.ordinal()]) {
            case 1:
                return $this$fromToken.getExtraLarge();
            case 2:
                return top($this$fromToken.getExtraLarge());
            case 3:
                return $this$fromToken.getExtraSmall();
            case 4:
                return top($this$fromToken.getExtraSmall());
            case 5:
                return RoundedCornerShapeKt.getCircleShape();
            case 6:
                return $this$fromToken.getLarge();
            case 7:
                return end($this$fromToken.getLarge());
            case 8:
                return top($this$fromToken.getLarge());
            case 9:
                return $this$fromToken.getMedium();
            case 10:
                return RectangleShapeKt.getRectangleShape();
            case 11:
                return $this$fromToken.getSmall();
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    public static final Shape toShape(ShapeKeyTokens $this$toShape, Composer $composer, int $changed) {
        Intrinsics.checkNotNullParameter($this$toShape, "<this>");
        $composer.startReplaceableGroup(-612531606);
        ComposerKt.sourceInformation($composer, "C(toShape)175@7160L6:Shapes.kt#uh7d8r");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-612531606, $changed, -1, "androidx.compose.material3.toShape (Shapes.kt:174)");
        }
        Shape fromToken = fromToken(MaterialTheme.INSTANCE.getShapes($composer, 6), $this$toShape);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return fromToken;
    }

    public static final ProvidableCompositionLocal<Shapes> getLocalShapes() {
        return LocalShapes;
    }
}
