package androidx.compose.foundation.layout;

import androidx.compose.foundation.layout.Arrangement;
import androidx.compose.runtime.Applier;
import androidx.compose.runtime.ComposablesKt;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.ScopeUpdateScope;
import androidx.compose.runtime.SkippableUpdater;
import androidx.compose.runtime.Updater;
import androidx.compose.runtime.collection.MutableVector;
import androidx.compose.ui.Alignment;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.layout.IntrinsicMeasurable;
import androidx.compose.ui.layout.IntrinsicMeasureScope;
import androidx.compose.ui.layout.LayoutKt;
import androidx.compose.ui.layout.Measurable;
import androidx.compose.ui.layout.MeasurePolicy;
import androidx.compose.ui.layout.MeasureResult;
import androidx.compose.ui.layout.MeasureScope;
import androidx.compose.ui.layout.Placeable;
import androidx.compose.ui.node.ComposeUiNode;
import androidx.compose.ui.platform.CompositionLocalsKt;
import androidx.compose.ui.platform.ViewConfiguration;
import androidx.compose.ui.unit.ConstraintsKt;
import androidx.compose.ui.unit.Density;
import androidx.compose.ui.unit.LayoutDirection;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.ArraysKt;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.functions.Function5;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
/* compiled from: FlowLayout.kt */
@Metadata(d1 = {"\u0000¶\u0001\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\u0010\u0015\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\u001aS\u0010\u0007\u001a\u00020\u00052\b\b\u0002\u0010\b\u001a\u00020\t2\b\b\u0002\u0010\n\u001a\u00020\u000b2\b\b\u0002\u0010\f\u001a\u00020\r2\b\b\u0002\u0010\u000e\u001a\u00020\u00022\u001c\u0010\u000f\u001a\u0018\u0012\u0004\u0012\u00020\u0011\u0012\u0004\u0012\u00020\u00050\u0010¢\u0006\u0002\b\u0012¢\u0006\u0002\b\u0013H\u0007¢\u0006\u0002\u0010\u0014\u001aS\u0010\u0015\u001a\u00020\u00052\b\b\u0002\u0010\b\u001a\u00020\t2\b\b\u0002\u0010\u0016\u001a\u00020\u00172\b\b\u0002\u0010\u0018\u001a\u00020\u00192\b\b\u0002\u0010\u001a\u001a\u00020\u00022\u001c\u0010\u000f\u001a\u0018\u0012\u0004\u0012\u00020\u001b\u0012\u0004\u0012\u00020\u00050\u0010¢\u0006\u0002\b\u0012¢\u0006\u0002\b\u0013H\u0007¢\u0006\u0002\u0010\u001c\u001a)\u0010\u001d\u001a\u00020\u001e2\b\b\u0002\u0010\n\u001a\u00020\u000b2\b\b\u0002\u0010\f\u001a\u00020\r2\u0006\u0010\u001f\u001a\u00020\u0002H\u0003¢\u0006\u0002\u0010 \u001a\u008f\u0001\u0010!\u001a\u00020\u001e2\u0006\u0010\"\u001a\u00020#2*\u0010$\u001a&\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020&\u0012\u0004\u0012\u00020'\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00050%2\u0006\u0010(\u001a\u00020)2\u0006\u0010*\u001a\u00020+2\u0006\u0010,\u001a\u00020-2$\u0010.\u001a \u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00050\u00012\u0006\u0010\u001f\u001a\u00020\u0002H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b/\u00100\u001ax\u00101\u001a\u00020\u00022\f\u00102\u001a\b\u0012\u0004\u0012\u000204032#\u00105\u001a\u001f\u0012\u0004\u0012\u000204\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u000206¢\u0006\u0002\b\u00132#\u0010*\u001a\u001f\u0012\u0004\u0012\u000204\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u000206¢\u0006\u0002\b\u00132\u0006\u00107\u001a\u00020\u00022\u0006\u00108\u001a\u00020\u00022\u0006\u0010\u001f\u001a\u00020\u0002H\u0002\u001a>\u00101\u001a\u00020\u00022\f\u00102\u001a\b\u0012\u0004\u0012\u000204032\u0006\u00109\u001a\u00020\u00032\u0006\u0010:\u001a\u00020\u00032\u0006\u00107\u001a\u00020\u00022\u0006\u00108\u001a\u00020\u00022\u0006\u0010\u001f\u001a\u00020\u0002H\u0002\u001a9\u0010;\u001a&\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020&\u0012\u0004\u0012\u00020'\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00050%2\u0006\u0010\n\u001a\u00020\u000bH\u0003¢\u0006\u0002\u0010<\u001a9\u0010=\u001a&\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020&\u0012\u0004\u0012\u00020'\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00050%2\u0006\u0010\u0016\u001a\u00020\u0017H\u0003¢\u0006\u0002\u0010>\u001aS\u0010?\u001a\u00020\u00022\f\u00102\u001a\b\u0012\u0004\u0012\u000204032#\u00105\u001a\u001f\u0012\u0004\u0012\u000204\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u000206¢\u0006\u0002\b\u00132\u0006\u0010@\u001a\u00020\u00022\u0006\u00108\u001a\u00020\u00022\u0006\u0010\u001f\u001a\u00020\u0002H\u0002\u001ax\u0010A\u001a\u00020\u00022\f\u00102\u001a\b\u0012\u0004\u0012\u000204032#\u00105\u001a\u001f\u0012\u0004\u0012\u000204\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u000206¢\u0006\u0002\b\u00132#\u0010*\u001a\u001f\u0012\u0004\u0012\u000204\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u000206¢\u0006\u0002\b\u00132\u0006\u0010@\u001a\u00020\u00022\u0006\u00108\u001a\u00020\u00022\u0006\u0010\u001f\u001a\u00020\u0002H\u0002\u001a)\u0010B\u001a\u00020\u001e2\b\b\u0002\u0010\u0016\u001a\u00020\u00172\b\b\u0002\u0010\u0018\u001a\u00020\u00192\u0006\u0010\u001f\u001a\u00020\u0002H\u0003¢\u0006\u0002\u0010C\u001a,\u0010D\u001a\u00020E*\u00020\u00042\u0006\u0010F\u001a\u00020G2\u0006\u0010\"\u001a\u00020#2\u0006\u0010H\u001a\u00020I2\u0006\u0010\u001f\u001a\u00020\u0002H\u0000\u001a\u001c\u0010J\u001a\u00020\u0002*\u00020K2\u0006\u0010\"\u001a\u00020#2\u0006\u00105\u001a\u00020\u0002H\u0000\u001a\u0014\u0010*\u001a\u00020\u0002*\u00020L2\u0006\u0010\"\u001a\u00020#H\u0000\u001a\u001c\u0010M\u001a\u00020\u0002*\u00020K2\u0006\u0010\"\u001a\u00020#2\u0006\u0010*\u001a\u00020\u0002H\u0000\u001a\u0014\u00105\u001a\u00020\u0002*\u00020L2\u0006\u0010\"\u001a\u00020#H\u0000\u001a2\u0010N\u001a\u00020\u0002*\u00020K2\u0006\u0010H\u001a\u00020I2\u0006\u0010\"\u001a\u00020#2\u0014\u0010O\u001a\u0010\u0012\u0006\u0012\u0004\u0018\u00010L\u0012\u0004\u0012\u00020\u00050\u0010H\u0002\",\u0010\u0000\u001a \u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00050\u0001X\u0082\u0004¢\u0006\u0002\n\u0000\",\u0010\u0006\u001a \u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00050\u0001X\u0082\u0004¢\u0006\u0002\n\u0000\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006P"}, d2 = {"crossAxisColumnArrangement", "Lkotlin/Function4;", "", "", "Landroidx/compose/ui/layout/MeasureScope;", "", "crossAxisRowArrangement", "FlowColumn", "modifier", "Landroidx/compose/ui/Modifier;", "verticalArrangement", "Landroidx/compose/foundation/layout/Arrangement$Vertical;", "horizontalAlignment", "Landroidx/compose/ui/Alignment$Horizontal;", "maxItemsInEachColumn", "content", "Lkotlin/Function1;", "Landroidx/compose/foundation/layout/ColumnScope;", "Landroidx/compose/runtime/Composable;", "Lkotlin/ExtensionFunctionType;", "(Landroidx/compose/ui/Modifier;Landroidx/compose/foundation/layout/Arrangement$Vertical;Landroidx/compose/ui/Alignment$Horizontal;ILkotlin/jvm/functions/Function3;Landroidx/compose/runtime/Composer;II)V", "FlowRow", "horizontalArrangement", "Landroidx/compose/foundation/layout/Arrangement$Horizontal;", "verticalAlignment", "Landroidx/compose/ui/Alignment$Vertical;", "maxItemsInEachRow", "Landroidx/compose/foundation/layout/RowScope;", "(Landroidx/compose/ui/Modifier;Landroidx/compose/foundation/layout/Arrangement$Horizontal;Landroidx/compose/ui/Alignment$Vertical;ILkotlin/jvm/functions/Function3;Landroidx/compose/runtime/Composer;II)V", "columnMeasurementHelper", "Landroidx/compose/ui/layout/MeasurePolicy;", "maxItemsInMainAxis", "(Landroidx/compose/foundation/layout/Arrangement$Vertical;Landroidx/compose/ui/Alignment$Horizontal;ILandroidx/compose/runtime/Composer;II)Landroidx/compose/ui/layout/MeasurePolicy;", "flowMeasurePolicy", "orientation", "Landroidx/compose/foundation/layout/LayoutOrientation;", "mainAxisArrangement", "Lkotlin/Function5;", "Landroidx/compose/ui/unit/LayoutDirection;", "Landroidx/compose/ui/unit/Density;", "arrangementSpacing", "Landroidx/compose/ui/unit/Dp;", "crossAxisSize", "Landroidx/compose/foundation/layout/SizeMode;", "crossAxisAlignment", "Landroidx/compose/foundation/layout/CrossAxisAlignment;", "crossAxisArrangement", "flowMeasurePolicy-942rkJo", "(Landroidx/compose/foundation/layout/LayoutOrientation;Lkotlin/jvm/functions/Function5;FLandroidx/compose/foundation/layout/SizeMode;Landroidx/compose/foundation/layout/CrossAxisAlignment;Lkotlin/jvm/functions/Function4;I)Landroidx/compose/ui/layout/MeasurePolicy;", "intrinsicCrossAxisSize", "children", "", "Landroidx/compose/ui/layout/IntrinsicMeasurable;", "mainAxisSize", "Lkotlin/Function3;", "mainAxisAvailable", "mainAxisSpacing", "mainAxisSizes", "crossAxisSizes", "mainAxisColumnArrangement", "(Landroidx/compose/foundation/layout/Arrangement$Vertical;Landroidx/compose/runtime/Composer;I)Lkotlin/jvm/functions/Function5;", "mainAxisRowArrangement", "(Landroidx/compose/foundation/layout/Arrangement$Horizontal;Landroidx/compose/runtime/Composer;I)Lkotlin/jvm/functions/Function5;", "maxIntrinsicMainAxisSize", "crossAxisAvailable", "minIntrinsicMainAxisSize", "rowMeasurementHelper", "(Landroidx/compose/foundation/layout/Arrangement$Horizontal;Landroidx/compose/ui/Alignment$Vertical;ILandroidx/compose/runtime/Composer;II)Landroidx/compose/ui/layout/MeasurePolicy;", "breakDownItems", "Landroidx/compose/foundation/layout/FlowResult;", "measureHelper", "Landroidx/compose/foundation/layout/RowColumnMeasurementHelper;", "constraints", "Landroidx/compose/foundation/layout/OrientationIndependentConstraints;", "crossAxisMin", "Landroidx/compose/ui/layout/Measurable;", "Landroidx/compose/ui/layout/Placeable;", "mainAxisMin", "measureAndCache", "storePlaceable", "foundation-layout_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class FlowLayoutKt {
    private static final Function4<Integer, int[], MeasureScope, int[], Unit> crossAxisRowArrangement = new Function4<Integer, int[], MeasureScope, int[], Unit>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$crossAxisRowArrangement$1
        @Override // kotlin.jvm.functions.Function4
        public /* bridge */ /* synthetic */ Unit invoke(Integer num, int[] iArr, MeasureScope measureScope, int[] iArr2) {
            invoke(num.intValue(), iArr, measureScope, iArr2);
            return Unit.INSTANCE;
        }

        public final void invoke(int totalSize, int[] size, MeasureScope measureScope, int[] outPosition) {
            Intrinsics.checkNotNullParameter(size, "size");
            Intrinsics.checkNotNullParameter(measureScope, "measureScope");
            Intrinsics.checkNotNullParameter(outPosition, "outPosition");
            Arrangement.Vertical $this$invoke_u24lambda_u240 = Arrangement.INSTANCE.getTop();
            $this$invoke_u24lambda_u240.arrange(measureScope, totalSize, size, outPosition);
        }
    };
    private static final Function4<Integer, int[], MeasureScope, int[], Unit> crossAxisColumnArrangement = new Function4<Integer, int[], MeasureScope, int[], Unit>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$crossAxisColumnArrangement$1
        @Override // kotlin.jvm.functions.Function4
        public /* bridge */ /* synthetic */ Unit invoke(Integer num, int[] iArr, MeasureScope measureScope, int[] iArr2) {
            invoke(num.intValue(), iArr, measureScope, iArr2);
            return Unit.INSTANCE;
        }

        public final void invoke(int totalSize, int[] size, MeasureScope measureScope, int[] outPosition) {
            Intrinsics.checkNotNullParameter(size, "size");
            Intrinsics.checkNotNullParameter(measureScope, "measureScope");
            Intrinsics.checkNotNullParameter(outPosition, "outPosition");
            Arrangement.Horizontal $this$invoke_u24lambda_u240 = Arrangement.INSTANCE.getStart();
            $this$invoke_u24lambda_u240.arrange(measureScope, totalSize, size, measureScope.getLayoutDirection(), outPosition);
        }
    };

    public static final void FlowRow(Modifier modifier, Arrangement.Horizontal horizontalArrangement, Alignment.Vertical verticalAlignment, int maxItemsInEachRow, final Function3<? super RowScope, ? super Composer, ? super Integer, Unit> content, Composer $composer, final int $changed, final int i) {
        Object obj;
        Object obj2;
        Object verticalAlignment2;
        int maxItemsInEachRow2;
        Modifier modifier2;
        Arrangement.Horizontal horizontalArrangement2;
        Alignment.Vertical verticalAlignment3;
        Intrinsics.checkNotNullParameter(content, "content");
        Composer $composer2 = $composer.startRestartGroup(1098475987);
        ComposerKt.sourceInformation($composer2, "C(FlowRow)P(3,1,4,2)60@2401L111,65@2517L130:FlowLayout.kt#2w3rfo");
        int $dirty = $changed;
        int i2 = i & 1;
        if (i2 != 0) {
            $dirty |= 6;
            obj = modifier;
        } else if (($changed & 14) == 0) {
            obj = modifier;
            $dirty |= $composer2.changed(obj) ? 4 : 2;
        } else {
            obj = modifier;
        }
        int i3 = i & 2;
        if (i3 != 0) {
            $dirty |= 48;
            obj2 = horizontalArrangement;
        } else if (($changed & 112) == 0) {
            obj2 = horizontalArrangement;
            $dirty |= $composer2.changed(obj2) ? 32 : 16;
        } else {
            obj2 = horizontalArrangement;
        }
        int i4 = i & 4;
        if (i4 != 0) {
            $dirty |= 384;
            verticalAlignment2 = verticalAlignment;
        } else if (($changed & 896) == 0) {
            verticalAlignment2 = verticalAlignment;
            $dirty |= $composer2.changed(verticalAlignment2) ? 256 : 128;
        } else {
            verticalAlignment2 = verticalAlignment;
        }
        int i5 = i & 8;
        if (i5 != 0) {
            $dirty |= 3072;
            maxItemsInEachRow2 = maxItemsInEachRow;
        } else if (($changed & 7168) == 0) {
            maxItemsInEachRow2 = maxItemsInEachRow;
            $dirty |= $composer2.changed(maxItemsInEachRow2) ? 2048 : 1024;
        } else {
            maxItemsInEachRow2 = maxItemsInEachRow;
        }
        if ((i & 16) != 0) {
            $dirty |= 24576;
        } else if ((57344 & $changed) == 0) {
            $dirty |= $composer2.changed(content) ? 16384 : 8192;
        }
        int $dirty2 = $dirty;
        if ((46811 & $dirty2) == 9362 && $composer2.getSkipping()) {
            $composer2.skipToGroupEnd();
            modifier2 = obj;
            horizontalArrangement2 = obj2;
            verticalAlignment3 = verticalAlignment2;
        } else {
            modifier2 = i2 != 0 ? Modifier.Companion : obj;
            horizontalArrangement2 = i3 != 0 ? Arrangement.INSTANCE.getStart() : obj2;
            if (i4 != 0) {
                verticalAlignment2 = Alignment.Companion.getTop();
            }
            if (i5 != 0) {
                maxItemsInEachRow2 = Integer.MAX_VALUE;
            }
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(1098475987, $dirty2, -1, "androidx.compose.foundation.layout.FlowRow (FlowLayout.kt:53)");
            }
            MeasurePolicy measurePolicy = rowMeasurementHelper(horizontalArrangement2, verticalAlignment2, maxItemsInEachRow2, $composer2, (($dirty2 >> 3) & 14) | (($dirty2 >> 3) & 112) | (($dirty2 >> 3) & 896), 0);
            int $changed$iv = ($dirty2 << 3) & 112;
            $composer2.startReplaceableGroup(-1323940314);
            ComposerKt.sourceInformation($composer2, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
            ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume = $composer2.consume(CompositionLocalsKt.getLocalDensity());
            ComposerKt.sourceInformationMarkerEnd($composer2);
            Density density$iv = (Density) consume;
            ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume2 = $composer2.consume(CompositionLocalsKt.getLocalLayoutDirection());
            ComposerKt.sourceInformationMarkerEnd($composer2);
            LayoutDirection layoutDirection$iv = (LayoutDirection) consume2;
            ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume3 = $composer2.consume(CompositionLocalsKt.getLocalViewConfiguration());
            ComposerKt.sourceInformationMarkerEnd($composer2);
            ViewConfiguration viewConfiguration$iv = (ViewConfiguration) consume3;
            Function0 factory$iv$iv = ComposeUiNode.Companion.getConstructor();
            Function3 skippableUpdate$iv$iv = LayoutKt.materializerOf(modifier2);
            int $i$f$Layout = $changed$iv << 9;
            int $changed$iv$iv = ($i$f$Layout & 7168) | 6;
            if (!($composer2.getApplier() instanceof Applier)) {
                ComposablesKt.invalidApplier();
            }
            $composer2.startReusableNode();
            if ($composer2.getInserting()) {
                $composer2.createNode(factory$iv$iv);
            } else {
                $composer2.useNode();
            }
            $composer2.disableReusing();
            Composer $this$Layout_u24lambda_u2d0$iv = Updater.m2247constructorimpl($composer2);
            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv, measurePolicy, ComposeUiNode.Companion.getSetMeasurePolicy());
            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv, density$iv, ComposeUiNode.Companion.getSetDensity());
            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv, layoutDirection$iv, ComposeUiNode.Companion.getSetLayoutDirection());
            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv, viewConfiguration$iv, ComposeUiNode.Companion.getSetViewConfiguration());
            $composer2.enableReusing();
            skippableUpdate$iv$iv.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer2)), $composer2, Integer.valueOf(($changed$iv$iv >> 3) & 112));
            $composer2.startReplaceableGroup(2058660585);
            int i6 = ($changed$iv$iv >> 9) & 14;
            ComposerKt.sourceInformationMarkerStart($composer2, 483375088, "C66@2562L9:FlowLayout.kt#2w3rfo");
            content.invoke(RowScopeInstance.INSTANCE, $composer2, Integer.valueOf((($dirty2 >> 9) & 112) | 6));
            ComposerKt.sourceInformationMarkerEnd($composer2);
            $composer2.endReplaceableGroup();
            $composer2.endNode();
            $composer2.endReplaceableGroup();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            verticalAlignment3 = verticalAlignment2;
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Modifier modifier3 = modifier2;
        final Arrangement.Horizontal horizontal = horizontalArrangement2;
        final Alignment.Vertical vertical = verticalAlignment3;
        final int i7 = maxItemsInEachRow2;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$FlowRow$2
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

            public final void invoke(Composer composer, int i8) {
                FlowLayoutKt.FlowRow(Modifier.this, horizontal, vertical, i7, content, composer, $changed | 1, i);
            }
        });
    }

    public static final void FlowColumn(Modifier modifier, Arrangement.Vertical verticalArrangement, Alignment.Horizontal horizontalAlignment, int maxItemsInEachColumn, final Function3<? super ColumnScope, ? super Composer, ? super Integer, Unit> content, Composer $composer, final int $changed, final int i) {
        Object obj;
        Object obj2;
        Object horizontalAlignment2;
        int maxItemsInEachColumn2;
        Modifier modifier2;
        Arrangement.Vertical verticalArrangement2;
        Alignment.Horizontal horizontalAlignment3;
        Intrinsics.checkNotNullParameter(content, "content");
        Composer $composer2 = $composer.startRestartGroup(-310290901);
        ComposerKt.sourceInformation($composer2, "C(FlowColumn)P(3,4,1,2)110@4218L117,115@4340L133:FlowLayout.kt#2w3rfo");
        int $dirty = $changed;
        int i2 = i & 1;
        if (i2 != 0) {
            $dirty |= 6;
            obj = modifier;
        } else if (($changed & 14) == 0) {
            obj = modifier;
            $dirty |= $composer2.changed(obj) ? 4 : 2;
        } else {
            obj = modifier;
        }
        int i3 = i & 2;
        if (i3 != 0) {
            $dirty |= 48;
            obj2 = verticalArrangement;
        } else if (($changed & 112) == 0) {
            obj2 = verticalArrangement;
            $dirty |= $composer2.changed(obj2) ? 32 : 16;
        } else {
            obj2 = verticalArrangement;
        }
        int i4 = i & 4;
        if (i4 != 0) {
            $dirty |= 384;
            horizontalAlignment2 = horizontalAlignment;
        } else if (($changed & 896) == 0) {
            horizontalAlignment2 = horizontalAlignment;
            $dirty |= $composer2.changed(horizontalAlignment2) ? 256 : 128;
        } else {
            horizontalAlignment2 = horizontalAlignment;
        }
        int i5 = i & 8;
        if (i5 != 0) {
            $dirty |= 3072;
            maxItemsInEachColumn2 = maxItemsInEachColumn;
        } else if (($changed & 7168) == 0) {
            maxItemsInEachColumn2 = maxItemsInEachColumn;
            $dirty |= $composer2.changed(maxItemsInEachColumn2) ? 2048 : 1024;
        } else {
            maxItemsInEachColumn2 = maxItemsInEachColumn;
        }
        if ((i & 16) != 0) {
            $dirty |= 24576;
        } else if ((57344 & $changed) == 0) {
            $dirty |= $composer2.changed(content) ? 16384 : 8192;
        }
        int $dirty2 = $dirty;
        if ((46811 & $dirty2) == 9362 && $composer2.getSkipping()) {
            $composer2.skipToGroupEnd();
            modifier2 = obj;
            verticalArrangement2 = obj2;
            horizontalAlignment3 = horizontalAlignment2;
        } else {
            modifier2 = i2 != 0 ? Modifier.Companion : obj;
            verticalArrangement2 = i3 != 0 ? Arrangement.INSTANCE.getTop() : obj2;
            if (i4 != 0) {
                horizontalAlignment2 = Alignment.Companion.getStart();
            }
            if (i5 != 0) {
                maxItemsInEachColumn2 = Integer.MAX_VALUE;
            }
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(-310290901, $dirty2, -1, "androidx.compose.foundation.layout.FlowColumn (FlowLayout.kt:103)");
            }
            MeasurePolicy measurePolicy = columnMeasurementHelper(verticalArrangement2, horizontalAlignment2, maxItemsInEachColumn2, $composer2, (($dirty2 >> 3) & 14) | (($dirty2 >> 3) & 112) | (($dirty2 >> 3) & 896), 0);
            int $changed$iv = ($dirty2 << 3) & 112;
            $composer2.startReplaceableGroup(-1323940314);
            ComposerKt.sourceInformation($composer2, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
            ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume = $composer2.consume(CompositionLocalsKt.getLocalDensity());
            ComposerKt.sourceInformationMarkerEnd($composer2);
            Density density$iv = (Density) consume;
            ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume2 = $composer2.consume(CompositionLocalsKt.getLocalLayoutDirection());
            ComposerKt.sourceInformationMarkerEnd($composer2);
            LayoutDirection layoutDirection$iv = (LayoutDirection) consume2;
            ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume3 = $composer2.consume(CompositionLocalsKt.getLocalViewConfiguration());
            ComposerKt.sourceInformationMarkerEnd($composer2);
            ViewConfiguration viewConfiguration$iv = (ViewConfiguration) consume3;
            Function0 factory$iv$iv = ComposeUiNode.Companion.getConstructor();
            Function3 skippableUpdate$iv$iv = LayoutKt.materializerOf(modifier2);
            int $i$f$Layout = $changed$iv << 9;
            int $changed$iv$iv = ($i$f$Layout & 7168) | 6;
            if (!($composer2.getApplier() instanceof Applier)) {
                ComposablesKt.invalidApplier();
            }
            $composer2.startReusableNode();
            if ($composer2.getInserting()) {
                $composer2.createNode(factory$iv$iv);
            } else {
                $composer2.useNode();
            }
            $composer2.disableReusing();
            Composer $this$Layout_u24lambda_u2d0$iv = Updater.m2247constructorimpl($composer2);
            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv, measurePolicy, ComposeUiNode.Companion.getSetMeasurePolicy());
            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv, density$iv, ComposeUiNode.Companion.getSetDensity());
            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv, layoutDirection$iv, ComposeUiNode.Companion.getSetLayoutDirection());
            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv, viewConfiguration$iv, ComposeUiNode.Companion.getSetViewConfiguration());
            $composer2.enableReusing();
            skippableUpdate$iv$iv.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer2)), $composer2, Integer.valueOf(($changed$iv$iv >> 3) & 112));
            $composer2.startReplaceableGroup(2058660585);
            int i6 = ($changed$iv$iv >> 9) & 14;
            ComposerKt.sourceInformationMarkerStart($composer2, -681937629, "C116@4388L9:FlowLayout.kt#2w3rfo");
            content.invoke(ColumnScopeInstance.INSTANCE, $composer2, Integer.valueOf((($dirty2 >> 9) & 112) | 6));
            ComposerKt.sourceInformationMarkerEnd($composer2);
            $composer2.endReplaceableGroup();
            $composer2.endNode();
            $composer2.endReplaceableGroup();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            horizontalAlignment3 = horizontalAlignment2;
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Modifier modifier3 = modifier2;
        final Arrangement.Vertical vertical = verticalArrangement2;
        final Alignment.Horizontal horizontal = horizontalAlignment3;
        final int i7 = maxItemsInEachColumn2;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$FlowColumn$2
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

            public final void invoke(Composer composer, int i8) {
                FlowLayoutKt.FlowColumn(Modifier.this, vertical, horizontal, i7, content, composer, $changed | 1, i);
            }
        });
    }

    private static final Function5<Integer, int[], LayoutDirection, Density, int[], Unit> mainAxisRowArrangement(final Arrangement.Horizontal horizontalArrangement, Composer $composer, int $changed) {
        Object value$iv$iv;
        $composer.startReplaceableGroup(746410833);
        ComposerKt.sourceInformation($composer, "C(mainAxisRowArrangement)125@4646L252:FlowLayout.kt#2w3rfo");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(746410833, $changed, -1, "androidx.compose.foundation.layout.mainAxisRowArrangement (FlowLayout.kt:123)");
        }
        int i = $changed & 14;
        $composer.startReplaceableGroup(1157296644);
        ComposerKt.sourceInformation($composer, "C(remember)P(1):Composables.kt#9igjgp");
        boolean invalid$iv$iv = $composer.changed(horizontalArrangement);
        Object it$iv$iv = $composer.rememberedValue();
        if (invalid$iv$iv || it$iv$iv == Composer.Companion.getEmpty()) {
            value$iv$iv = (Function5) new Function5<Integer, int[], LayoutDirection, Density, int[], Unit>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$mainAxisRowArrangement$1$1
                /* JADX INFO: Access modifiers changed from: package-private */
                {
                    super(5);
                }

                @Override // kotlin.jvm.functions.Function5
                public /* bridge */ /* synthetic */ Unit invoke(Integer num, int[] iArr, LayoutDirection layoutDirection, Density density, int[] iArr2) {
                    invoke(num.intValue(), iArr, layoutDirection, density, iArr2);
                    return Unit.INSTANCE;
                }

                public final void invoke(int totalSize, int[] size, LayoutDirection layoutDirection, Density density, int[] outPosition) {
                    Intrinsics.checkNotNullParameter(size, "size");
                    Intrinsics.checkNotNullParameter(layoutDirection, "layoutDirection");
                    Intrinsics.checkNotNullParameter(density, "density");
                    Intrinsics.checkNotNullParameter(outPosition, "outPosition");
                    Arrangement.Horizontal $this$invoke_u24lambda_u240 = Arrangement.Horizontal.this;
                    $this$invoke_u24lambda_u240.arrange(density, totalSize, size, layoutDirection, outPosition);
                }
            };
            $composer.updateRememberedValue(value$iv$iv);
        } else {
            value$iv$iv = it$iv$iv;
        }
        $composer.endReplaceableGroup();
        Function5<Integer, int[], LayoutDirection, Density, int[], Unit> function5 = (Function5) value$iv$iv;
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return function5;
    }

    private static final Function5<Integer, int[], LayoutDirection, Density, int[], Unit> mainAxisColumnArrangement(final Arrangement.Vertical verticalArrangement, Composer $composer, int $changed) {
        Object value$iv$iv;
        $composer.startReplaceableGroup(-1642644113);
        ComposerKt.sourceInformation($composer, "C(mainAxisColumnArrangement)136@5068L217:FlowLayout.kt#2w3rfo");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-1642644113, $changed, -1, "androidx.compose.foundation.layout.mainAxisColumnArrangement (FlowLayout.kt:134)");
        }
        int i = $changed & 14;
        $composer.startReplaceableGroup(1157296644);
        ComposerKt.sourceInformation($composer, "C(remember)P(1):Composables.kt#9igjgp");
        boolean invalid$iv$iv = $composer.changed(verticalArrangement);
        Object it$iv$iv = $composer.rememberedValue();
        if (invalid$iv$iv || it$iv$iv == Composer.Companion.getEmpty()) {
            value$iv$iv = (Function5) new Function5<Integer, int[], LayoutDirection, Density, int[], Unit>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$mainAxisColumnArrangement$1$1
                /* JADX INFO: Access modifiers changed from: package-private */
                {
                    super(5);
                }

                @Override // kotlin.jvm.functions.Function5
                public /* bridge */ /* synthetic */ Unit invoke(Integer num, int[] iArr, LayoutDirection layoutDirection, Density density, int[] iArr2) {
                    invoke(num.intValue(), iArr, layoutDirection, density, iArr2);
                    return Unit.INSTANCE;
                }

                public final void invoke(int totalSize, int[] size, LayoutDirection layoutDirection, Density density, int[] outPosition) {
                    Intrinsics.checkNotNullParameter(size, "size");
                    Intrinsics.checkNotNullParameter(layoutDirection, "<anonymous parameter 2>");
                    Intrinsics.checkNotNullParameter(density, "density");
                    Intrinsics.checkNotNullParameter(outPosition, "outPosition");
                    Arrangement.Vertical $this$invoke_u24lambda_u240 = Arrangement.Vertical.this;
                    $this$invoke_u24lambda_u240.arrange(density, totalSize, size, outPosition);
                }
            };
            $composer.updateRememberedValue(value$iv$iv);
        } else {
            value$iv$iv = it$iv$iv;
        }
        $composer.endReplaceableGroup();
        Function5<Integer, int[], LayoutDirection, Density, int[], Unit> function5 = (Function5) value$iv$iv;
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return function5;
    }

    private static final MeasurePolicy rowMeasurementHelper(Arrangement.Horizontal horizontalArrangement, Alignment.Vertical verticalAlignment, int maxItemsInMainAxis, Composer $composer, int $changed, int i) {
        Alignment.Vertical verticalAlignment2;
        Object value$iv$iv;
        $composer.startReplaceableGroup(1479255111);
        ComposerKt.sourceInformation($composer, "C(rowMeasurementHelper)P(!1,2)163@6016L45,164@6091L90,167@6193L499:FlowLayout.kt#2w3rfo");
        Arrangement.Horizontal horizontalArrangement2 = (i & 1) != 0 ? Arrangement.INSTANCE.getEnd() : horizontalArrangement;
        if ((i & 2) == 0) {
            verticalAlignment2 = verticalAlignment;
        } else {
            verticalAlignment2 = Alignment.Companion.getTop();
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(1479255111, $changed, -1, "androidx.compose.foundation.layout.rowMeasurementHelper (FlowLayout.kt:158)");
        }
        Function5 mainAxisArrangement = mainAxisRowArrangement(horizontalArrangement2, $composer, $changed & 14);
        int i2 = ($changed >> 3) & 14;
        $composer.startReplaceableGroup(1157296644);
        ComposerKt.sourceInformation($composer, "C(remember)P(1):Composables.kt#9igjgp");
        boolean invalid$iv$iv = $composer.changed(verticalAlignment2);
        Object it$iv$iv = $composer.rememberedValue();
        if (invalid$iv$iv || it$iv$iv == Composer.Companion.getEmpty()) {
            value$iv$iv = CrossAxisAlignment.Companion.vertical$foundation_layout_release(verticalAlignment2);
            $composer.updateRememberedValue(value$iv$iv);
        } else {
            value$iv$iv = it$iv$iv;
        }
        $composer.endReplaceableGroup();
        CrossAxisAlignment crossAxisAlignment = (CrossAxisAlignment) value$iv$iv;
        Object key3$iv = Integer.valueOf(maxItemsInMainAxis);
        int i3 = ($changed & 14) | ($changed & 112) | ($changed & 896);
        $composer.startReplaceableGroup(1618982084);
        ComposerKt.sourceInformation($composer, "C(remember)P(1,2,3):Composables.kt#9igjgp");
        boolean invalid$iv$iv2 = $composer.changed(horizontalArrangement2) | $composer.changed(verticalAlignment2) | $composer.changed(key3$iv);
        Object value$iv$iv2 = $composer.rememberedValue();
        if (invalid$iv$iv2 || value$iv$iv2 == Composer.Companion.getEmpty()) {
            value$iv$iv2 = m393flowMeasurePolicy942rkJo(LayoutOrientation.Horizontal, mainAxisArrangement, horizontalArrangement2.mo364getSpacingD9Ej5fM(), SizeMode.Wrap, crossAxisAlignment, crossAxisRowArrangement, maxItemsInMainAxis);
            $composer.updateRememberedValue(value$iv$iv2);
        }
        $composer.endReplaceableGroup();
        MeasurePolicy measurePolicy = (MeasurePolicy) value$iv$iv2;
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return measurePolicy;
    }

    private static final MeasurePolicy columnMeasurementHelper(Arrangement.Vertical verticalArrangement, Alignment.Horizontal horizontalAlignment, int maxItemsInMainAxis, Composer $composer, int $changed, int i) {
        Alignment.Horizontal horizontalAlignment2;
        Object value$iv$iv;
        $composer.startReplaceableGroup(-2013098357);
        ComposerKt.sourceInformation($composer, "C(columnMeasurementHelper)P(2)186@6953L46,187@7029L96,190@7137L497:FlowLayout.kt#2w3rfo");
        Arrangement.Vertical verticalArrangement2 = (i & 1) != 0 ? Arrangement.INSTANCE.getTop() : verticalArrangement;
        if ((i & 2) == 0) {
            horizontalAlignment2 = horizontalAlignment;
        } else {
            horizontalAlignment2 = Alignment.Companion.getStart();
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-2013098357, $changed, -1, "androidx.compose.foundation.layout.columnMeasurementHelper (FlowLayout.kt:181)");
        }
        Function5 mainAxisArrangement = mainAxisColumnArrangement(verticalArrangement2, $composer, $changed & 14);
        int i2 = ($changed >> 3) & 14;
        $composer.startReplaceableGroup(1157296644);
        ComposerKt.sourceInformation($composer, "C(remember)P(1):Composables.kt#9igjgp");
        boolean invalid$iv$iv = $composer.changed(horizontalAlignment2);
        Object it$iv$iv = $composer.rememberedValue();
        if (invalid$iv$iv || it$iv$iv == Composer.Companion.getEmpty()) {
            value$iv$iv = CrossAxisAlignment.Companion.horizontal$foundation_layout_release(horizontalAlignment2);
            $composer.updateRememberedValue(value$iv$iv);
        } else {
            value$iv$iv = it$iv$iv;
        }
        $composer.endReplaceableGroup();
        CrossAxisAlignment crossAxisAlignment = (CrossAxisAlignment) value$iv$iv;
        Object key3$iv = Integer.valueOf(maxItemsInMainAxis);
        int i3 = ($changed & 14) | ($changed & 112) | ($changed & 896);
        $composer.startReplaceableGroup(1618982084);
        ComposerKt.sourceInformation($composer, "C(remember)P(1,2,3):Composables.kt#9igjgp");
        boolean invalid$iv$iv2 = $composer.changed(verticalArrangement2) | $composer.changed(horizontalAlignment2) | $composer.changed(key3$iv);
        Object value$iv$iv2 = $composer.rememberedValue();
        if (invalid$iv$iv2 || value$iv$iv2 == Composer.Companion.getEmpty()) {
            value$iv$iv2 = m393flowMeasurePolicy942rkJo(LayoutOrientation.Vertical, mainAxisArrangement, verticalArrangement2.mo364getSpacingD9Ej5fM(), SizeMode.Wrap, crossAxisAlignment, crossAxisColumnArrangement, maxItemsInMainAxis);
            $composer.updateRememberedValue(value$iv$iv2);
        }
        $composer.endReplaceableGroup();
        MeasurePolicy measurePolicy = (MeasurePolicy) value$iv$iv2;
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return measurePolicy;
    }

    /* renamed from: flowMeasurePolicy-942rkJo  reason: not valid java name */
    private static final MeasurePolicy m393flowMeasurePolicy942rkJo(final LayoutOrientation orientation, final Function5<? super Integer, ? super int[], ? super LayoutDirection, ? super Density, ? super int[], Unit> function5, final float arrangementSpacing, final SizeMode crossAxisSize, final CrossAxisAlignment crossAxisAlignment, final Function4<? super Integer, ? super int[], ? super MeasureScope, ? super int[], Unit> function4, final int maxItemsInMainAxis) {
        return new MeasurePolicy(function5, arrangementSpacing, crossAxisSize, crossAxisAlignment, maxItemsInMainAxis, function4) { // from class: androidx.compose.foundation.layout.FlowLayoutKt$flowMeasurePolicy$1
            final /* synthetic */ float $arrangementSpacing;
            final /* synthetic */ CrossAxisAlignment $crossAxisAlignment;
            final /* synthetic */ Function4<Integer, int[], MeasureScope, int[], Unit> $crossAxisArrangement;
            final /* synthetic */ SizeMode $crossAxisSize;
            final /* synthetic */ Function5<Integer, int[], LayoutDirection, Density, int[], Unit> $mainAxisArrangement;
            final /* synthetic */ int $maxItemsInMainAxis;
            private final Function3<IntrinsicMeasurable, Integer, Integer, Integer> maxCrossAxisIntrinsicItemSize;
            private final Function3<IntrinsicMeasurable, Integer, Integer, Integer> maxMainAxisIntrinsicItemSize;
            private final Function3<IntrinsicMeasurable, Integer, Integer, Integer> minCrossAxisIntrinsicItemSize;
            private final Function3<IntrinsicMeasurable, Integer, Integer, Integer> minMainAxisIntrinsicItemSize;

            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: Multi-variable type inference failed */
            {
                this.$mainAxisArrangement = function5;
                this.$arrangementSpacing = arrangementSpacing;
                this.$crossAxisSize = crossAxisSize;
                this.$crossAxisAlignment = crossAxisAlignment;
                this.$maxItemsInMainAxis = maxItemsInMainAxis;
                this.$crossAxisArrangement = function4;
                this.maxMainAxisIntrinsicItemSize = LayoutOrientation.this == LayoutOrientation.Horizontal ? new Function3<IntrinsicMeasurable, Integer, Integer, Integer>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$flowMeasurePolicy$1$maxMainAxisIntrinsicItemSize$1
                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num, Integer num2) {
                        return invoke(intrinsicMeasurable, num.intValue(), num2.intValue());
                    }

                    public final Integer invoke(IntrinsicMeasurable $this$null, int i, int h) {
                        Intrinsics.checkNotNullParameter($this$null, "$this$null");
                        return Integer.valueOf($this$null.maxIntrinsicWidth(h));
                    }
                } : new Function3<IntrinsicMeasurable, Integer, Integer, Integer>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$flowMeasurePolicy$1$maxMainAxisIntrinsicItemSize$2
                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num, Integer num2) {
                        return invoke(intrinsicMeasurable, num.intValue(), num2.intValue());
                    }

                    public final Integer invoke(IntrinsicMeasurable $this$null, int i, int w) {
                        Intrinsics.checkNotNullParameter($this$null, "$this$null");
                        return Integer.valueOf($this$null.maxIntrinsicHeight(w));
                    }
                };
                this.maxCrossAxisIntrinsicItemSize = LayoutOrientation.this == LayoutOrientation.Horizontal ? new Function3<IntrinsicMeasurable, Integer, Integer, Integer>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$flowMeasurePolicy$1$maxCrossAxisIntrinsicItemSize$1
                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num, Integer num2) {
                        return invoke(intrinsicMeasurable, num.intValue(), num2.intValue());
                    }

                    public final Integer invoke(IntrinsicMeasurable $this$null, int i, int w) {
                        Intrinsics.checkNotNullParameter($this$null, "$this$null");
                        return Integer.valueOf($this$null.maxIntrinsicHeight(w));
                    }
                } : new Function3<IntrinsicMeasurable, Integer, Integer, Integer>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$flowMeasurePolicy$1$maxCrossAxisIntrinsicItemSize$2
                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num, Integer num2) {
                        return invoke(intrinsicMeasurable, num.intValue(), num2.intValue());
                    }

                    public final Integer invoke(IntrinsicMeasurable $this$null, int i, int h) {
                        Intrinsics.checkNotNullParameter($this$null, "$this$null");
                        return Integer.valueOf($this$null.maxIntrinsicWidth(h));
                    }
                };
                this.minCrossAxisIntrinsicItemSize = LayoutOrientation.this == LayoutOrientation.Horizontal ? new Function3<IntrinsicMeasurable, Integer, Integer, Integer>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$flowMeasurePolicy$1$minCrossAxisIntrinsicItemSize$1
                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num, Integer num2) {
                        return invoke(intrinsicMeasurable, num.intValue(), num2.intValue());
                    }

                    public final Integer invoke(IntrinsicMeasurable $this$null, int i, int w) {
                        Intrinsics.checkNotNullParameter($this$null, "$this$null");
                        return Integer.valueOf($this$null.minIntrinsicHeight(w));
                    }
                } : new Function3<IntrinsicMeasurable, Integer, Integer, Integer>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$flowMeasurePolicy$1$minCrossAxisIntrinsicItemSize$2
                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num, Integer num2) {
                        return invoke(intrinsicMeasurable, num.intValue(), num2.intValue());
                    }

                    public final Integer invoke(IntrinsicMeasurable $this$null, int i, int h) {
                        Intrinsics.checkNotNullParameter($this$null, "$this$null");
                        return Integer.valueOf($this$null.minIntrinsicWidth(h));
                    }
                };
                this.minMainAxisIntrinsicItemSize = LayoutOrientation.this == LayoutOrientation.Horizontal ? new Function3<IntrinsicMeasurable, Integer, Integer, Integer>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$flowMeasurePolicy$1$minMainAxisIntrinsicItemSize$1
                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num, Integer num2) {
                        return invoke(intrinsicMeasurable, num.intValue(), num2.intValue());
                    }

                    public final Integer invoke(IntrinsicMeasurable $this$null, int i, int h) {
                        Intrinsics.checkNotNullParameter($this$null, "$this$null");
                        return Integer.valueOf($this$null.minIntrinsicWidth(h));
                    }
                } : new Function3<IntrinsicMeasurable, Integer, Integer, Integer>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$flowMeasurePolicy$1$minMainAxisIntrinsicItemSize$2
                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num, Integer num2) {
                        return invoke(intrinsicMeasurable, num.intValue(), num2.intValue());
                    }

                    public final Integer invoke(IntrinsicMeasurable $this$null, int i, int w) {
                        Intrinsics.checkNotNullParameter($this$null, "$this$null");
                        return Integer.valueOf($this$null.minIntrinsicHeight(w));
                    }
                };
            }

            @Override // androidx.compose.ui.layout.MeasurePolicy
            /* renamed from: measure-3p2s80s */
            public MeasureResult mo11measure3p2s80s(final MeasureScope measure, List<? extends Measurable> measurables, long constraints) {
                int layoutWidth;
                int layoutWidth2;
                Intrinsics.checkNotNullParameter(measure, "$this$measure");
                Intrinsics.checkNotNullParameter(measurables, "measurables");
                Placeable[] placeables = new Placeable[measurables.size()];
                final RowColumnMeasurementHelper measureHelper = new RowColumnMeasurementHelper(LayoutOrientation.this, this.$mainAxisArrangement, this.$arrangementSpacing, this.$crossAxisSize, this.$crossAxisAlignment, measurables, placeables, null);
                OrientationIndependentConstraints orientationIndependentConstraints = new OrientationIndependentConstraints(constraints, LayoutOrientation.this, null);
                final FlowResult flowResult = FlowLayoutKt.breakDownItems(measure, measureHelper, LayoutOrientation.this, orientationIndependentConstraints, this.$maxItemsInMainAxis);
                int totalCrossAxisSize = flowResult.getCrossAxisTotalSize();
                MutableVector items = flowResult.getItems();
                int size = items.getSize();
                int[] crossAxisSizes = new int[size];
                for (int i = 0; i < size; i++) {
                    crossAxisSizes[i] = items.getContent()[i].getCrossAxisSize();
                }
                final int[] outPosition = new int[crossAxisSizes.length];
                this.$crossAxisArrangement.invoke(Integer.valueOf(totalCrossAxisSize), crossAxisSizes, measure, outPosition);
                if (LayoutOrientation.this == LayoutOrientation.Horizontal) {
                    layoutWidth = flowResult.getMainAxisTotalSize();
                    layoutWidth2 = flowResult.getCrossAxisTotalSize();
                } else {
                    layoutWidth = flowResult.getCrossAxisTotalSize();
                    layoutWidth2 = flowResult.getMainAxisTotalSize();
                }
                int layoutWidth3 = ConstraintsKt.m5092constrainWidthK40F9xA(constraints, layoutWidth);
                int layoutHeight = ConstraintsKt.m5091constrainHeightK40F9xA(constraints, layoutWidth2);
                return MeasureScope.layout$default(measure, layoutWidth3, layoutHeight, null, new Function1<Placeable.PlacementScope, Unit>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$flowMeasurePolicy$1$measure$1
                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Placeable.PlacementScope placementScope) {
                        invoke2(placementScope);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke  reason: avoid collision after fix types in other method */
                    public final void invoke2(Placeable.PlacementScope layout) {
                        Intrinsics.checkNotNullParameter(layout, "$this$layout");
                        MutableVector this_$iv = FlowResult.this.getItems();
                        RowColumnMeasurementHelper rowColumnMeasurementHelper = measureHelper;
                        int[] iArr = outPosition;
                        MeasureScope measureScope = measure;
                        int size$iv = this_$iv.getSize();
                        if (size$iv <= 0) {
                            return;
                        }
                        int i$iv = 0;
                        Object[] content$iv = this_$iv.getContent();
                        do {
                            RowColumnMeasureHelperResult measureResult = (RowColumnMeasureHelperResult) content$iv[i$iv];
                            int currentRowOrColumnIndex = i$iv;
                            rowColumnMeasurementHelper.placeHelper(layout, measureResult, iArr[currentRowOrColumnIndex], measureScope.getLayoutDirection());
                            i$iv++;
                        } while (i$iv < size$iv);
                    }
                }, 4, null);
            }

            @Override // androidx.compose.ui.layout.MeasurePolicy
            public int minIntrinsicWidth(IntrinsicMeasureScope $this$minIntrinsicWidth, List<? extends IntrinsicMeasurable> measurables, int height) {
                Intrinsics.checkNotNullParameter($this$minIntrinsicWidth, "<this>");
                Intrinsics.checkNotNullParameter(measurables, "measurables");
                if (LayoutOrientation.this == LayoutOrientation.Horizontal) {
                    return minIntrinsicMainAxisSize(measurables, height, $this$minIntrinsicWidth.mo295roundToPx0680j_4(this.$arrangementSpacing));
                }
                return intrinsicCrossAxisSize(measurables, height, $this$minIntrinsicWidth.mo295roundToPx0680j_4(this.$arrangementSpacing));
            }

            @Override // androidx.compose.ui.layout.MeasurePolicy
            public int minIntrinsicHeight(IntrinsicMeasureScope $this$minIntrinsicHeight, List<? extends IntrinsicMeasurable> measurables, int width) {
                Intrinsics.checkNotNullParameter($this$minIntrinsicHeight, "<this>");
                Intrinsics.checkNotNullParameter(measurables, "measurables");
                if (LayoutOrientation.this == LayoutOrientation.Horizontal) {
                    return intrinsicCrossAxisSize(measurables, width, $this$minIntrinsicHeight.mo295roundToPx0680j_4(this.$arrangementSpacing));
                }
                return minIntrinsicMainAxisSize(measurables, width, $this$minIntrinsicHeight.mo295roundToPx0680j_4(this.$arrangementSpacing));
            }

            @Override // androidx.compose.ui.layout.MeasurePolicy
            public int maxIntrinsicHeight(IntrinsicMeasureScope $this$maxIntrinsicHeight, List<? extends IntrinsicMeasurable> measurables, int width) {
                Intrinsics.checkNotNullParameter($this$maxIntrinsicHeight, "<this>");
                Intrinsics.checkNotNullParameter(measurables, "measurables");
                if (LayoutOrientation.this == LayoutOrientation.Horizontal) {
                    return intrinsicCrossAxisSize(measurables, width, $this$maxIntrinsicHeight.mo295roundToPx0680j_4(this.$arrangementSpacing));
                }
                return maxIntrinsicMainAxisSize(measurables, width, $this$maxIntrinsicHeight.mo295roundToPx0680j_4(this.$arrangementSpacing));
            }

            @Override // androidx.compose.ui.layout.MeasurePolicy
            public int maxIntrinsicWidth(IntrinsicMeasureScope $this$maxIntrinsicWidth, List<? extends IntrinsicMeasurable> measurables, int height) {
                Intrinsics.checkNotNullParameter($this$maxIntrinsicWidth, "<this>");
                Intrinsics.checkNotNullParameter(measurables, "measurables");
                if (LayoutOrientation.this == LayoutOrientation.Horizontal) {
                    return maxIntrinsicMainAxisSize(measurables, height, $this$maxIntrinsicWidth.mo295roundToPx0680j_4(this.$arrangementSpacing));
                }
                return intrinsicCrossAxisSize(measurables, height, $this$maxIntrinsicWidth.mo295roundToPx0680j_4(this.$arrangementSpacing));
            }

            public final int minIntrinsicMainAxisSize(List<? extends IntrinsicMeasurable> measurables, int crossAxisAvailable, int arrangementSpacing2) {
                int minIntrinsicMainAxisSize;
                Intrinsics.checkNotNullParameter(measurables, "measurables");
                minIntrinsicMainAxisSize = FlowLayoutKt.minIntrinsicMainAxisSize(measurables, this.minMainAxisIntrinsicItemSize, this.minCrossAxisIntrinsicItemSize, crossAxisAvailable, arrangementSpacing2, this.$maxItemsInMainAxis);
                return minIntrinsicMainAxisSize;
            }

            public final int maxIntrinsicMainAxisSize(List<? extends IntrinsicMeasurable> measurables, int height, int arrangementSpacing2) {
                int maxIntrinsicMainAxisSize;
                Intrinsics.checkNotNullParameter(measurables, "measurables");
                maxIntrinsicMainAxisSize = FlowLayoutKt.maxIntrinsicMainAxisSize(measurables, this.maxMainAxisIntrinsicItemSize, height, arrangementSpacing2, this.$maxItemsInMainAxis);
                return maxIntrinsicMainAxisSize;
            }

            public final int intrinsicCrossAxisSize(List<? extends IntrinsicMeasurable> measurables, int mainAxisAvailable, int arrangementSpacing2) {
                int intrinsicCrossAxisSize;
                Intrinsics.checkNotNullParameter(measurables, "measurables");
                intrinsicCrossAxisSize = FlowLayoutKt.intrinsicCrossAxisSize(measurables, this.minMainAxisIntrinsicItemSize, this.minCrossAxisIntrinsicItemSize, mainAxisAvailable, arrangementSpacing2, this.$maxItemsInMainAxis);
                return intrinsicCrossAxisSize;
            }

            public final Function3<IntrinsicMeasurable, Integer, Integer, Integer> getMaxMainAxisIntrinsicItemSize() {
                return this.maxMainAxisIntrinsicItemSize;
            }

            public final Function3<IntrinsicMeasurable, Integer, Integer, Integer> getMaxCrossAxisIntrinsicItemSize() {
                return this.maxCrossAxisIntrinsicItemSize;
            }

            public final Function3<IntrinsicMeasurable, Integer, Integer, Integer> getMinCrossAxisIntrinsicItemSize() {
                return this.minCrossAxisIntrinsicItemSize;
            }

            public final Function3<IntrinsicMeasurable, Integer, Integer, Integer> getMinMainAxisIntrinsicItemSize() {
                return this.minMainAxisIntrinsicItemSize;
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final int maxIntrinsicMainAxisSize(List<? extends IntrinsicMeasurable> list, Function3<? super IntrinsicMeasurable, ? super Integer, ? super Integer, Integer> function3, int crossAxisAvailable, int mainAxisSpacing, int maxItemsInMainAxis) {
        int fixedSpace = 0;
        int currentFixedSpace = 0;
        int lastBreak = 0;
        int size = list.size();
        for (int index$iv = 0; index$iv < size; index$iv++) {
            Object item$iv = list.get(index$iv);
            IntrinsicMeasurable child = (IntrinsicMeasurable) item$iv;
            int index = index$iv;
            int size2 = function3.invoke(child, Integer.valueOf(index), Integer.valueOf(crossAxisAvailable)).intValue() + mainAxisSpacing;
            if ((index + 1) - lastBreak == maxItemsInMainAxis || index + 1 == list.size()) {
                lastBreak = index;
                fixedSpace = Math.max(fixedSpace, currentFixedSpace + size2);
                currentFixedSpace = 0;
            } else {
                currentFixedSpace += size2;
            }
        }
        return fixedSpace;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Type inference failed for: r7v1, types: [kotlin.collections.IntIterator] */
    /* JADX WARN: Type inference failed for: r8v2, types: [kotlin.collections.IntIterator] */
    public static final int minIntrinsicMainAxisSize(List<? extends IntrinsicMeasurable> list, Function3<? super IntrinsicMeasurable, ? super Integer, ? super Integer, Integer> function3, Function3<? super IntrinsicMeasurable, ? super Integer, ? super Integer, Integer> function32, int crossAxisAvailable, int mainAxisSpacing, int maxItemsInMainAxis) {
        int size = list.size();
        int[] mainAxisSizes = new int[size];
        for (int i = 0; i < size; i++) {
            mainAxisSizes[i] = 0;
        }
        int size2 = list.size();
        int[] crossAxisSizes = new int[size2];
        for (int i2 = 0; i2 < size2; i2++) {
            crossAxisSizes[i2] = 0;
        }
        int size3 = list.size();
        for (int index = 0; index < size3; index++) {
            IntrinsicMeasurable child = list.get(index);
            int mainAxisItemSize = function3.invoke(child, Integer.valueOf(index), Integer.valueOf(crossAxisAvailable)).intValue();
            mainAxisSizes[index] = mainAxisItemSize;
            crossAxisSizes[index] = function32.invoke(child, Integer.valueOf(index), Integer.valueOf(mainAxisItemSize)).intValue();
        }
        int maxMainAxisSize = ArraysKt.sum(mainAxisSizes);
        int mainAxisUsed = maxMainAxisSize;
        if (crossAxisSizes.length == 0) {
            throw new NoSuchElementException();
        }
        int crossAxisUsed = crossAxisSizes[0];
        ?? it = new IntRange(1, ArraysKt.getLastIndex(crossAxisSizes)).iterator();
        while (it.hasNext()) {
            int it2 = crossAxisSizes[it.nextInt()];
            if (crossAxisUsed < it2) {
                crossAxisUsed = it2;
            }
        }
        if (mainAxisSizes.length == 0) {
            throw new NoSuchElementException();
        }
        int minimumItemSize = mainAxisSizes[0];
        ?? it3 = new IntRange(1, ArraysKt.getLastIndex(mainAxisSizes)).iterator();
        while (it3.hasNext()) {
            int it4 = mainAxisSizes[it3.nextInt()];
            if (minimumItemSize < it4) {
                minimumItemSize = it4;
            }
        }
        int low = minimumItemSize;
        int crossAxisUsed2 = crossAxisUsed;
        int low2 = low;
        int high = maxMainAxisSize;
        while (low2 < high) {
            if (crossAxisUsed2 == crossAxisAvailable) {
                return mainAxisUsed;
            }
            int mid = (low2 + high) / 2;
            int high2 = high;
            crossAxisUsed2 = intrinsicCrossAxisSize(list, mainAxisSizes, crossAxisSizes, mid, mainAxisSpacing, maxItemsInMainAxis);
            if (crossAxisUsed2 == crossAxisAvailable) {
                return mid;
            }
            if (crossAxisUsed2 > crossAxisAvailable) {
                low2 = mid + 1;
                mainAxisUsed = mid;
                high = high2;
            } else {
                high = mid - 1;
                mainAxisUsed = mid;
            }
        }
        return mainAxisUsed;
    }

    private static final int intrinsicCrossAxisSize(List<? extends IntrinsicMeasurable> list, final int[] mainAxisSizes, final int[] crossAxisSizes, int mainAxisAvailable, int mainAxisSpacing, int maxItemsInMainAxis) {
        return intrinsicCrossAxisSize(list, new Function3<IntrinsicMeasurable, Integer, Integer, Integer>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$intrinsicCrossAxisSize$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(3);
            }

            @Override // kotlin.jvm.functions.Function3
            public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num, Integer num2) {
                return invoke(intrinsicMeasurable, num.intValue(), num2.intValue());
            }

            public final Integer invoke(IntrinsicMeasurable intrinsicCrossAxisSize, int index, int i) {
                Intrinsics.checkNotNullParameter(intrinsicCrossAxisSize, "$this$intrinsicCrossAxisSize");
                return Integer.valueOf(mainAxisSizes[index]);
            }
        }, new Function3<IntrinsicMeasurable, Integer, Integer, Integer>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$intrinsicCrossAxisSize$2
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(3);
            }

            @Override // kotlin.jvm.functions.Function3
            public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num, Integer num2) {
                return invoke(intrinsicMeasurable, num.intValue(), num2.intValue());
            }

            public final Integer invoke(IntrinsicMeasurable intrinsicCrossAxisSize, int index, int i) {
                Intrinsics.checkNotNullParameter(intrinsicCrossAxisSize, "$this$intrinsicCrossAxisSize");
                return Integer.valueOf(crossAxisSizes[index]);
            }
        }, mainAxisAvailable, mainAxisSpacing, maxItemsInMainAxis);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final int intrinsicCrossAxisSize(List<? extends IntrinsicMeasurable> list, Function3<? super IntrinsicMeasurable, ? super Integer, ? super Integer, Integer> function3, Function3<? super IntrinsicMeasurable, ? super Integer, ? super Integer, Integer> function32, int mainAxisAvailable, int mainAxisSpacing, int maxItemsInMainAxis) {
        List<? extends IntrinsicMeasurable> list2 = list;
        if (list.isEmpty()) {
            return 0;
        }
        Object nextChild = CollectionsKt.getOrNull(list2, 0);
        IntrinsicMeasurable intrinsicMeasurable = (IntrinsicMeasurable) nextChild;
        int nextCrossAxisSize = intrinsicMeasurable != null ? function32.invoke(intrinsicMeasurable, 0, Integer.valueOf(mainAxisAvailable)).intValue() : 0;
        IntrinsicMeasurable intrinsicMeasurable2 = (IntrinsicMeasurable) nextChild;
        int nextMainAxisSize = intrinsicMeasurable2 != null ? function3.invoke(intrinsicMeasurable2, 0, Integer.valueOf(nextCrossAxisSize)).intValue() : 0;
        int remaining = mainAxisAvailable;
        int currentCrossAxisSize = 0;
        int totalCrossAxisSize = 0;
        int lastBreak = 0;
        int index$iv = 0;
        int size = list.size();
        while (index$iv < size) {
            Object item$iv = list.get(index$iv);
            IntrinsicMeasurable intrinsicMeasurable3 = (IntrinsicMeasurable) item$iv;
            int index = index$iv;
            Intrinsics.checkNotNull(nextChild);
            int childCrossAxisSize = nextCrossAxisSize;
            int childMainAxisSize = nextMainAxisSize;
            remaining -= childMainAxisSize;
            currentCrossAxisSize = Math.max(currentCrossAxisSize, childCrossAxisSize);
            nextChild = CollectionsKt.getOrNull(list2, index + 1);
            IntrinsicMeasurable intrinsicMeasurable4 = (IntrinsicMeasurable) nextChild;
            nextCrossAxisSize = intrinsicMeasurable4 != null ? function32.invoke(intrinsicMeasurable4, Integer.valueOf(index + 1), Integer.valueOf(mainAxisAvailable)).intValue() : 0;
            IntrinsicMeasurable intrinsicMeasurable5 = (IntrinsicMeasurable) nextChild;
            int nextMainAxisSize2 = intrinsicMeasurable5 != null ? function3.invoke(intrinsicMeasurable5, Integer.valueOf(index + 1), Integer.valueOf(nextCrossAxisSize)).intValue() + mainAxisSpacing : 0;
            if (remaining >= 0 && index + 1 != list.size()) {
                if ((index + 1) - lastBreak != maxItemsInMainAxis && remaining - nextMainAxisSize2 >= 0) {
                    index$iv++;
                    nextMainAxisSize = nextMainAxisSize2;
                    list2 = list;
                }
            }
            totalCrossAxisSize += currentCrossAxisSize;
            remaining = mainAxisAvailable;
            int lastBreak2 = index + 1;
            nextMainAxisSize2 -= mainAxisSpacing;
            lastBreak = lastBreak2;
            currentCrossAxisSize = 0;
            index$iv++;
            nextMainAxisSize = nextMainAxisSize2;
            list2 = list;
        }
        return totalCrossAxisSize;
    }

    public static final FlowResult breakDownItems(MeasureScope $this$breakDownItems, RowColumnMeasurementHelper measureHelper, LayoutOrientation orientation, OrientationIndependentConstraints constraints, int maxItemsInMainAxis) {
        Integer nextSize;
        Intrinsics.checkNotNullParameter($this$breakDownItems, "<this>");
        Intrinsics.checkNotNullParameter(measureHelper, "measureHelper");
        Intrinsics.checkNotNullParameter(orientation, "orientation");
        Intrinsics.checkNotNullParameter(constraints, "constraints");
        MutableVector items = new MutableVector(new RowColumnMeasureHelperResult[16], 0);
        int mainAxisMax = constraints.getMainAxisMax();
        int mainAxisMin = constraints.getMainAxisMin();
        int crossAxisMax = constraints.getCrossAxisMax();
        List measurables = measureHelper.getMeasurables();
        final Placeable[] placeables = measureHelper.getPlaceables();
        int spacing = (int) Math.ceil($this$breakDownItems.mo301toPx0680j_4(measureHelper.m436getArrangementSpacingD9Ej5fM()));
        OrientationIndependentConstraints subsetConstraints = new OrientationIndependentConstraints(mainAxisMin, mainAxisMax, 0, crossAxisMax);
        Measurable measurable = (Measurable) CollectionsKt.getOrNull(measurables, 0);
        Integer nextSize2 = measurable != null ? Integer.valueOf(measureAndCache(measurable, subsetConstraints, orientation, new Function1<Placeable, Unit>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$breakDownItems$nextSize$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Placeable placeable) {
                invoke2(placeable);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke  reason: avoid collision after fix types in other method */
            public final void invoke2(Placeable placeable) {
                placeables[0] = placeable;
            }
        })) : null;
        Integer[] endBreakLineList = new Integer[measurables.size()];
        int size = measurables.size();
        Integer nextSize3 = nextSize2;
        int startBreakLineIndex = 0;
        int endBreakLineIndex = 0;
        int leftOver = mainAxisMax;
        int startBreakLineIndex2 = mainAxisMin;
        int currentLineMainAxisSize = 0;
        final int index = 0;
        while (index < size) {
            Intrinsics.checkNotNull(nextSize3);
            int itemMainAxisSize = nextSize3.intValue();
            int i = size;
            int currentLineMainAxisSize2 = currentLineMainAxisSize + itemMainAxisSize;
            leftOver -= itemMainAxisSize;
            Measurable measurable2 = (Measurable) CollectionsKt.getOrNull(measurables, index + 1);
            if (measurable2 == null) {
                nextSize = null;
            } else {
                nextSize = Integer.valueOf(measureAndCache(measurable2, subsetConstraints, orientation, new Function1<Placeable, Unit>() { // from class: androidx.compose.foundation.layout.FlowLayoutKt$breakDownItems$1
                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Placeable placeable) {
                        invoke2(placeable);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke  reason: avoid collision after fix types in other method */
                    public final void invoke2(Placeable placeable) {
                        placeables[index + 1] = placeable;
                    }
                }) + spacing);
            }
            int mainAxisMin2 = mainAxisMin;
            if (index + 1 < measurables.size() && (index + 1) - startBreakLineIndex < maxItemsInMainAxis) {
                if (leftOver - (nextSize != null ? nextSize.intValue() : 0) >= 0) {
                    currentLineMainAxisSize = currentLineMainAxisSize2;
                    nextSize3 = nextSize;
                    index++;
                    size = i;
                    mainAxisMin = mainAxisMin2;
                }
            }
            startBreakLineIndex2 = Math.max(startBreakLineIndex2, currentLineMainAxisSize2);
            startBreakLineIndex = index + 1;
            endBreakLineList[endBreakLineIndex] = Integer.valueOf(index + 1);
            endBreakLineIndex++;
            currentLineMainAxisSize = 0;
            nextSize3 = nextSize != null ? Integer.valueOf(nextSize.intValue() - spacing) : null;
            leftOver = mainAxisMax;
            index++;
            size = i;
            mainAxisMin = mainAxisMin2;
        }
        long subsetBoxConstraints = OrientationIndependentConstraints.copy$default(subsetConstraints, startBreakLineIndex2, 0, 0, 0, 14, null).m406toBoxConstraintsOenEA2s(orientation);
        int mainAxisTotalSize = startBreakLineIndex2;
        int crossAxisTotalSize = 0;
        int endBreakLineIndex2 = 0;
        Integer endIndex = (Integer) ArraysKt.getOrNull(endBreakLineList, 0);
        int mainAxisTotalSize2 = mainAxisTotalSize;
        int endBreakLineIndex3 = 0;
        while (endIndex != null) {
            OrientationIndependentConstraints subsetConstraints2 = subsetConstraints;
            int spacing2 = spacing;
            int spacing3 = endBreakLineIndex3;
            int startBreakLineIndex3 = crossAxisTotalSize;
            RowColumnMeasureHelperResult result = measureHelper.m437measureWithoutPlacing_EkL_Y($this$breakDownItems, subsetBoxConstraints, spacing3, endIndex.intValue());
            crossAxisTotalSize = startBreakLineIndex3 + result.getCrossAxisSize();
            mainAxisTotalSize2 = Math.max(mainAxisTotalSize2, result.getMainAxisSize());
            items.add(result);
            endBreakLineIndex3 = endIndex.intValue();
            int endBreakLineIndex4 = endBreakLineIndex2 + 1;
            endIndex = (Integer) ArraysKt.getOrNull(endBreakLineList, endBreakLineIndex4);
            endBreakLineIndex2 = endBreakLineIndex4;
            subsetConstraints = subsetConstraints2;
            spacing = spacing2;
        }
        int startBreakLineIndex4 = crossAxisTotalSize;
        int crossAxisTotalSize2 = Math.max(startBreakLineIndex4, constraints.getCrossAxisMin());
        return new FlowResult(Math.max(mainAxisTotalSize2, constraints.getMainAxisMin()), crossAxisTotalSize2, items);
    }

    public static final int mainAxisMin(Measurable $this$mainAxisMin, LayoutOrientation orientation, int crossAxisSize) {
        Intrinsics.checkNotNullParameter($this$mainAxisMin, "<this>");
        Intrinsics.checkNotNullParameter(orientation, "orientation");
        if (orientation == LayoutOrientation.Horizontal) {
            return $this$mainAxisMin.minIntrinsicWidth(crossAxisSize);
        }
        return $this$mainAxisMin.minIntrinsicHeight(crossAxisSize);
    }

    public static final int crossAxisMin(Measurable $this$crossAxisMin, LayoutOrientation orientation, int mainAxisSize) {
        Intrinsics.checkNotNullParameter($this$crossAxisMin, "<this>");
        Intrinsics.checkNotNullParameter(orientation, "orientation");
        if (orientation == LayoutOrientation.Horizontal) {
            return $this$crossAxisMin.minIntrinsicHeight(mainAxisSize);
        }
        return $this$crossAxisMin.minIntrinsicWidth(mainAxisSize);
    }

    public static final int mainAxisSize(Placeable $this$mainAxisSize, LayoutOrientation orientation) {
        Intrinsics.checkNotNullParameter($this$mainAxisSize, "<this>");
        Intrinsics.checkNotNullParameter(orientation, "orientation");
        return orientation == LayoutOrientation.Horizontal ? $this$mainAxisSize.getWidth() : $this$mainAxisSize.getHeight();
    }

    public static final int crossAxisSize(Placeable $this$crossAxisSize, LayoutOrientation orientation) {
        Intrinsics.checkNotNullParameter($this$crossAxisSize, "<this>");
        Intrinsics.checkNotNullParameter(orientation, "orientation");
        return orientation == LayoutOrientation.Horizontal ? $this$crossAxisSize.getHeight() : $this$crossAxisSize.getWidth();
    }

    private static final int measureAndCache(Measurable $this$measureAndCache, OrientationIndependentConstraints constraints, LayoutOrientation orientation, Function1<? super Placeable, Unit> function1) {
        if (RowColumnImplKt.getWeight(RowColumnImplKt.getRowColumnParentData($this$measureAndCache)) == 0.0f) {
            Placeable placeable = $this$measureAndCache.mo4125measureBRTryo0(OrientationIndependentConstraints.copy$default(constraints, 0, 0, 0, 0, 14, null).m406toBoxConstraintsOenEA2s(orientation));
            function1.invoke(placeable);
            int itemSize = mainAxisSize(placeable, orientation);
            return itemSize;
        }
        int itemSize2 = mainAxisMin($this$measureAndCache, orientation, Integer.MAX_VALUE);
        return itemSize2;
    }
}
