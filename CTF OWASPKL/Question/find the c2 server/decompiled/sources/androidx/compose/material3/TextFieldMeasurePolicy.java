package androidx.compose.material3;

import androidx.compose.foundation.layout.PaddingValues;
import androidx.compose.ui.layout.AlignmentLineKt;
import androidx.compose.ui.layout.IntrinsicMeasurable;
import androidx.compose.ui.layout.IntrinsicMeasureScope;
import androidx.compose.ui.layout.LayoutIdKt;
import androidx.compose.ui.layout.Measurable;
import androidx.compose.ui.layout.MeasurePolicy;
import androidx.compose.ui.layout.MeasureResult;
import androidx.compose.ui.layout.MeasureScope;
import androidx.compose.ui.layout.Placeable;
import androidx.compose.ui.unit.Constraints;
import androidx.compose.ui.unit.ConstraintsKt;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt;
/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: TextField.kt */
@Metadata(d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0002\u0018\u00002\u00020\u0001B\u001d\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007¢\u0006\u0002\u0010\bJ8\u0010\t\u001a\u00020\n2\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\r0\f2\u0006\u0010\u000e\u001a\u00020\n2\u0018\u0010\u000f\u001a\u0014\u0012\u0004\u0012\u00020\r\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\n0\u0010H\u0002J<\u0010\u0011\u001a\u00020\n*\u00020\u00122\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\r0\f2\u0006\u0010\u0013\u001a\u00020\n2\u0018\u0010\u000f\u001a\u0014\u0012\u0004\u0012\u00020\r\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\n0\u0010H\u0002J\"\u0010\u0014\u001a\u00020\n*\u00020\u00122\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\r0\f2\u0006\u0010\u0013\u001a\u00020\nH\u0016J\"\u0010\u0015\u001a\u00020\n*\u00020\u00122\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\r0\f2\u0006\u0010\u000e\u001a\u00020\nH\u0016J/\u0010\u0016\u001a\u00020\u0017*\u00020\u00182\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\u00190\f2\u0006\u0010\u001a\u001a\u00020\u001bH\u0016ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001c\u0010\u001dJ\"\u0010\u001e\u001a\u00020\n*\u00020\u00122\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\r0\f2\u0006\u0010\u0013\u001a\u00020\nH\u0016J\"\u0010\u001f\u001a\u00020\n*\u00020\u00122\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\r0\f2\u0006\u0010\u000e\u001a\u00020\nH\u0016R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006 "}, d2 = {"Landroidx/compose/material3/TextFieldMeasurePolicy;", "Landroidx/compose/ui/layout/MeasurePolicy;", "singleLine", "", "animationProgress", "", "paddingValues", "Landroidx/compose/foundation/layout/PaddingValues;", "(ZFLandroidx/compose/foundation/layout/PaddingValues;)V", "intrinsicWidth", "", "measurables", "", "Landroidx/compose/ui/layout/IntrinsicMeasurable;", "height", "intrinsicMeasurer", "Lkotlin/Function2;", "intrinsicHeight", "Landroidx/compose/ui/layout/IntrinsicMeasureScope;", "width", "maxIntrinsicHeight", "maxIntrinsicWidth", "measure", "Landroidx/compose/ui/layout/MeasureResult;", "Landroidx/compose/ui/layout/MeasureScope;", "Landroidx/compose/ui/layout/Measurable;", "constraints", "Landroidx/compose/ui/unit/Constraints;", "measure-3p2s80s", "(Landroidx/compose/ui/layout/MeasureScope;Ljava/util/List;J)Landroidx/compose/ui/layout/MeasureResult;", "minIntrinsicHeight", "minIntrinsicWidth", "material3_release"}, k = 1, mv = {1, 7, 1}, xi = 48)
/* loaded from: classes.dex */
public final class TextFieldMeasurePolicy implements MeasurePolicy {
    private final float animationProgress;
    private final PaddingValues paddingValues;
    private final boolean singleLine;

    public TextFieldMeasurePolicy(boolean singleLine, float animationProgress, PaddingValues paddingValues) {
        Intrinsics.checkNotNullParameter(paddingValues, "paddingValues");
        this.singleLine = singleLine;
        this.animationProgress = animationProgress;
        this.paddingValues = paddingValues;
    }

    @Override // androidx.compose.ui.layout.MeasurePolicy
    /* renamed from: measure-3p2s80s */
    public MeasureResult mo11measure3p2s80s(final MeasureScope measure, List<? extends Measurable> list, long constraints) {
        long looseConstraints;
        Object obj;
        Object obj2;
        Object obj3;
        int it;
        long m5068copyZbe2FdA;
        long placeholderConstraints;
        int verticalConstraintOffset;
        long textFieldConstraints;
        Object obj4;
        long supportingConstraints;
        int effectiveTopOffset;
        Object obj5;
        long supportingConstraints2;
        final Placeable supportingPlaceable;
        final int width;
        final int totalHeight;
        TextFieldMeasurePolicy textFieldMeasurePolicy = this;
        Iterable measurables = list;
        Intrinsics.checkNotNullParameter(measure, "$this$measure");
        Intrinsics.checkNotNullParameter(measurables, "measurables");
        final int topPaddingValue = measure.mo295roundToPx0680j_4(textFieldMeasurePolicy.paddingValues.mo397calculateTopPaddingD9Ej5fM());
        int bottomPaddingValue = measure.mo295roundToPx0680j_4(textFieldMeasurePolicy.paddingValues.mo394calculateBottomPaddingD9Ej5fM());
        final int topPadding = measure.mo295roundToPx0680j_4(TextFieldKt.getTextFieldTopPadding());
        looseConstraints = Constraints.m5068copyZbe2FdA(constraints, (r12 & 1) != 0 ? Constraints.m5080getMinWidthimpl(constraints) : 0, (r12 & 2) != 0 ? Constraints.m5078getMaxWidthimpl(constraints) : 0, (r12 & 4) != 0 ? Constraints.m5079getMinHeightimpl(constraints) : 0, (r12 & 8) != 0 ? Constraints.m5077getMaxHeightimpl(constraints) : 0);
        Iterator<T> it2 = measurables.iterator();
        while (true) {
            if (!it2.hasNext()) {
                obj = null;
                break;
            }
            obj = it2.next();
            Measurable it3 = (Measurable) obj;
            if (Intrinsics.areEqual(LayoutIdKt.getLayoutId(it3), "Leading")) {
                break;
            }
        }
        Measurable measurable = (Measurable) obj;
        final Placeable leadingPlaceable = measurable != null ? measurable.mo4125measureBRTryo0(looseConstraints) : null;
        int occupiedSpaceHorizontally = 0 + TextFieldImplKt.widthOrZero(leadingPlaceable);
        int occupiedSpaceVertically = Math.max(0, TextFieldImplKt.heightOrZero(leadingPlaceable));
        Iterator<T> it4 = measurables.iterator();
        while (true) {
            if (!it4.hasNext()) {
                obj2 = null;
                break;
            }
            obj2 = it4.next();
            Measurable it5 = (Measurable) obj2;
            if (Intrinsics.areEqual(LayoutIdKt.getLayoutId(it5), "Trailing")) {
                break;
            }
        }
        Measurable measurable2 = (Measurable) obj2;
        final Placeable trailingPlaceable = measurable2 != null ? measurable2.mo4125measureBRTryo0(ConstraintsKt.m5095offsetNN6EwU$default(looseConstraints, -occupiedSpaceHorizontally, 0, 2, null)) : null;
        int occupiedSpaceHorizontally2 = occupiedSpaceHorizontally + TextFieldImplKt.widthOrZero(trailingPlaceable);
        int occupiedSpaceVertically2 = Math.max(occupiedSpaceVertically, TextFieldImplKt.heightOrZero(trailingPlaceable));
        int occupiedSpaceVertically3 = -bottomPaddingValue;
        long labelConstraints = ConstraintsKt.m5094offsetNN6EwU(looseConstraints, -occupiedSpaceHorizontally2, occupiedSpaceVertically3);
        Iterator it6 = measurables.iterator();
        while (true) {
            if (!it6.hasNext()) {
                obj3 = null;
                break;
            }
            Object next = it6.next();
            Measurable it7 = (Measurable) next;
            Iterator it8 = it6;
            if (Intrinsics.areEqual(LayoutIdKt.getLayoutId(it7), "Label")) {
                obj3 = next;
                break;
            }
            it6 = it8;
        }
        Measurable measurable3 = (Measurable) obj3;
        Placeable labelPlaceable = measurable3 != null ? measurable3.mo4125measureBRTryo0(labelConstraints) : null;
        if (labelPlaceable != null) {
            it = labelPlaceable.get(AlignmentLineKt.getLastBaseline());
            if (it == Integer.MIN_VALUE) {
                it = labelPlaceable.getHeight();
            }
        } else {
            it = 0;
        }
        int lastBaseline = it;
        final int effectiveLabelBaseline = Math.max(lastBaseline, topPaddingValue);
        int effectiveTopOffset2 = labelPlaceable != null ? effectiveLabelBaseline + topPadding : topPaddingValue;
        int verticalConstraintOffset2 = (-effectiveTopOffset2) - bottomPaddingValue;
        Placeable labelPlaceable2 = labelPlaceable;
        m5068copyZbe2FdA = Constraints.m5068copyZbe2FdA(constraints, (r12 & 1) != 0 ? Constraints.m5080getMinWidthimpl(constraints) : 0, (r12 & 2) != 0 ? Constraints.m5078getMaxWidthimpl(constraints) : 0, (r12 & 4) != 0 ? Constraints.m5079getMinHeightimpl(constraints) : 0, (r12 & 8) != 0 ? Constraints.m5077getMaxHeightimpl(constraints) : 0);
        long textFieldConstraints2 = ConstraintsKt.m5094offsetNN6EwU(m5068copyZbe2FdA, -occupiedSpaceHorizontally2, verticalConstraintOffset2);
        Iterable $this$first$iv = measurables;
        Iterator<T> it9 = $this$first$iv.iterator();
        while (true) {
            int topPaddingValue2 = lastBaseline;
            if (!it9.hasNext()) {
                throw new NoSuchElementException("Collection contains no element matching the predicate.");
            }
            Object element$iv = it9.next();
            Measurable it10 = (Measurable) element$iv;
            int occupiedSpaceVertically4 = occupiedSpaceHorizontally2;
            Iterable $this$first$iv2 = $this$first$iv;
            if (Intrinsics.areEqual(LayoutIdKt.getLayoutId(it10), "TextField")) {
                final Placeable textFieldPlaceable = ((Measurable) element$iv).mo4125measureBRTryo0(textFieldConstraints2);
                placeholderConstraints = Constraints.m5068copyZbe2FdA(textFieldConstraints2, (r12 & 1) != 0 ? Constraints.m5080getMinWidthimpl(textFieldConstraints2) : 0, (r12 & 2) != 0 ? Constraints.m5078getMaxWidthimpl(textFieldConstraints2) : 0, (r12 & 4) != 0 ? Constraints.m5079getMinHeightimpl(textFieldConstraints2) : 0, (r12 & 8) != 0 ? Constraints.m5077getMaxHeightimpl(textFieldConstraints2) : 0);
                Iterator<T> it11 = measurables.iterator();
                while (true) {
                    if (!it11.hasNext()) {
                        verticalConstraintOffset = verticalConstraintOffset2;
                        textFieldConstraints = textFieldConstraints2;
                        obj4 = null;
                        break;
                    }
                    obj4 = it11.next();
                    Measurable it12 = (Measurable) obj4;
                    verticalConstraintOffset = verticalConstraintOffset2;
                    textFieldConstraints = textFieldConstraints2;
                    if (Intrinsics.areEqual(LayoutIdKt.getLayoutId(it12), "Hint")) {
                        break;
                    }
                    verticalConstraintOffset2 = verticalConstraintOffset;
                    textFieldConstraints2 = textFieldConstraints;
                }
                Measurable measurable4 = (Measurable) obj4;
                final Placeable placeholderPlaceable = measurable4 != null ? measurable4.mo4125measureBRTryo0(placeholderConstraints) : null;
                supportingConstraints = Constraints.m5068copyZbe2FdA(r44, (r12 & 1) != 0 ? Constraints.m5080getMinWidthimpl(r44) : 0, (r12 & 2) != 0 ? Constraints.m5078getMaxWidthimpl(r44) : 0, (r12 & 4) != 0 ? Constraints.m5079getMinHeightimpl(r44) : 0, (r12 & 8) != 0 ? Constraints.m5077getMaxHeightimpl(ConstraintsKt.m5095offsetNN6EwU$default(looseConstraints, 0, -Math.max(occupiedSpaceVertically2, Math.max(TextFieldImplKt.heightOrZero(textFieldPlaceable), TextFieldImplKt.heightOrZero(placeholderPlaceable)) + effectiveTopOffset2 + bottomPaddingValue), 1, null)) : 0);
                Iterator it13 = measurables.iterator();
                while (true) {
                    if (!it13.hasNext()) {
                        effectiveTopOffset = effectiveTopOffset2;
                        obj5 = null;
                        break;
                    }
                    obj5 = it13.next();
                    Measurable it14 = (Measurable) obj5;
                    Iterator it15 = it13;
                    effectiveTopOffset = effectiveTopOffset2;
                    if (Intrinsics.areEqual(LayoutIdKt.getLayoutId(it14), TextFieldImplKt.SupportingId)) {
                        break;
                    }
                    it13 = it15;
                    effectiveTopOffset2 = effectiveTopOffset;
                }
                Measurable measurable5 = (Measurable) obj5;
                if (measurable5 != null) {
                    supportingConstraints2 = supportingConstraints;
                    supportingPlaceable = measurable5.mo4125measureBRTryo0(supportingConstraints2);
                } else {
                    supportingConstraints2 = supportingConstraints;
                    supportingPlaceable = null;
                }
                final Placeable labelPlaceable3 = labelPlaceable2;
                int supportingHeight = TextFieldImplKt.heightOrZero(supportingPlaceable);
                width = TextFieldKt.m1633calculateWidthVsPV1Ek(TextFieldImplKt.widthOrZero(leadingPlaceable), TextFieldImplKt.widthOrZero(trailingPlaceable), textFieldPlaceable.getWidth(), TextFieldImplKt.widthOrZero(labelPlaceable3), TextFieldImplKt.widthOrZero(placeholderPlaceable), constraints);
                totalHeight = TextFieldKt.m1632calculateHeightjCXOeKk(textFieldPlaceable.getHeight(), labelPlaceable3 != null, effectiveLabelBaseline, TextFieldImplKt.heightOrZero(leadingPlaceable), TextFieldImplKt.heightOrZero(trailingPlaceable), TextFieldImplKt.heightOrZero(placeholderPlaceable), TextFieldImplKt.heightOrZero(supportingPlaceable), constraints, measure.getDensity(), textFieldMeasurePolicy.paddingValues);
                int height = totalHeight - supportingHeight;
                Iterable $this$first$iv3 = measurables;
                for (Object element$iv2 : $this$first$iv3) {
                    Measurable it16 = (Measurable) element$iv2;
                    Iterable $this$first$iv4 = $this$first$iv3;
                    long placeholderConstraints2 = placeholderConstraints;
                    if (Intrinsics.areEqual(LayoutIdKt.getLayoutId(it16), TextFieldImplKt.ContainerId)) {
                        final Placeable containerPlaceable = ((Measurable) element$iv2).mo4125measureBRTryo0(ConstraintsKt.Constraints(width != Integer.MAX_VALUE ? width : 0, width, height != Integer.MAX_VALUE ? height : 0, height));
                        final int lastBaseline2 = topPaddingValue2;
                        return MeasureScope.layout$default(measure, width, totalHeight, null, new Function1<Placeable.PlacementScope, Unit>() { // from class: androidx.compose.material3.TextFieldMeasurePolicy$measure$1
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
                                boolean z;
                                PaddingValues paddingValues;
                                boolean z2;
                                float f;
                                Intrinsics.checkNotNullParameter(layout, "$this$layout");
                                if (Placeable.this != null) {
                                    int labelEndPosition = RangesKt.coerceAtLeast(topPaddingValue - lastBaseline2, 0);
                                    int i = width;
                                    int i2 = totalHeight;
                                    Placeable placeable = textFieldPlaceable;
                                    Placeable placeable2 = Placeable.this;
                                    Placeable placeable3 = placeholderPlaceable;
                                    Placeable placeable4 = leadingPlaceable;
                                    Placeable placeable5 = trailingPlaceable;
                                    Placeable placeable6 = containerPlaceable;
                                    Placeable placeable7 = supportingPlaceable;
                                    z2 = this.singleLine;
                                    int i3 = effectiveLabelBaseline + topPadding;
                                    f = this.animationProgress;
                                    TextFieldKt.placeWithLabel(layout, i, i2, placeable, placeable2, placeable3, placeable4, placeable5, placeable6, placeable7, z2, labelEndPosition, i3, f, measure.getDensity());
                                    return;
                                }
                                int i4 = width;
                                int i5 = totalHeight;
                                Placeable placeable8 = textFieldPlaceable;
                                Placeable placeable9 = placeholderPlaceable;
                                Placeable placeable10 = leadingPlaceable;
                                Placeable placeable11 = trailingPlaceable;
                                Placeable placeable12 = containerPlaceable;
                                Placeable placeable13 = supportingPlaceable;
                                z = this.singleLine;
                                float density = measure.getDensity();
                                paddingValues = this.paddingValues;
                                TextFieldKt.placeWithoutLabel(layout, i4, i5, placeable8, placeable9, placeable10, placeable11, placeable12, placeable13, z, density, paddingValues);
                            }
                        }, 4, null);
                    }
                    $this$first$iv3 = $this$first$iv4;
                    placeholderConstraints = placeholderConstraints2;
                    effectiveTopOffset = effectiveTopOffset;
                    topPaddingValue2 = topPaddingValue2;
                    occupiedSpaceVertically4 = occupiedSpaceVertically4;
                }
                throw new NoSuchElementException("Collection contains no element matching the predicate.");
            }
            textFieldMeasurePolicy = this;
            measurables = list;
            $this$first$iv = $this$first$iv2;
            lastBaseline = topPaddingValue2;
            occupiedSpaceHorizontally2 = occupiedSpaceVertically4;
            labelPlaceable2 = labelPlaceable2;
        }
    }

    @Override // androidx.compose.ui.layout.MeasurePolicy
    public int maxIntrinsicHeight(IntrinsicMeasureScope $this$maxIntrinsicHeight, List<? extends IntrinsicMeasurable> measurables, int width) {
        Intrinsics.checkNotNullParameter($this$maxIntrinsicHeight, "<this>");
        Intrinsics.checkNotNullParameter(measurables, "measurables");
        return intrinsicHeight($this$maxIntrinsicHeight, measurables, width, new Function2<IntrinsicMeasurable, Integer, Integer>() { // from class: androidx.compose.material3.TextFieldMeasurePolicy$maxIntrinsicHeight$1
            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num) {
                return invoke(intrinsicMeasurable, num.intValue());
            }

            public final Integer invoke(IntrinsicMeasurable intrinsicMeasurable, int w) {
                Intrinsics.checkNotNullParameter(intrinsicMeasurable, "intrinsicMeasurable");
                return Integer.valueOf(intrinsicMeasurable.maxIntrinsicHeight(w));
            }
        });
    }

    @Override // androidx.compose.ui.layout.MeasurePolicy
    public int minIntrinsicHeight(IntrinsicMeasureScope $this$minIntrinsicHeight, List<? extends IntrinsicMeasurable> measurables, int width) {
        Intrinsics.checkNotNullParameter($this$minIntrinsicHeight, "<this>");
        Intrinsics.checkNotNullParameter(measurables, "measurables");
        return intrinsicHeight($this$minIntrinsicHeight, measurables, width, new Function2<IntrinsicMeasurable, Integer, Integer>() { // from class: androidx.compose.material3.TextFieldMeasurePolicy$minIntrinsicHeight$1
            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num) {
                return invoke(intrinsicMeasurable, num.intValue());
            }

            public final Integer invoke(IntrinsicMeasurable intrinsicMeasurable, int w) {
                Intrinsics.checkNotNullParameter(intrinsicMeasurable, "intrinsicMeasurable");
                return Integer.valueOf(intrinsicMeasurable.minIntrinsicHeight(w));
            }
        });
    }

    @Override // androidx.compose.ui.layout.MeasurePolicy
    public int maxIntrinsicWidth(IntrinsicMeasureScope $this$maxIntrinsicWidth, List<? extends IntrinsicMeasurable> measurables, int height) {
        Intrinsics.checkNotNullParameter($this$maxIntrinsicWidth, "<this>");
        Intrinsics.checkNotNullParameter(measurables, "measurables");
        return intrinsicWidth(measurables, height, new Function2<IntrinsicMeasurable, Integer, Integer>() { // from class: androidx.compose.material3.TextFieldMeasurePolicy$maxIntrinsicWidth$1
            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num) {
                return invoke(intrinsicMeasurable, num.intValue());
            }

            public final Integer invoke(IntrinsicMeasurable intrinsicMeasurable, int h) {
                Intrinsics.checkNotNullParameter(intrinsicMeasurable, "intrinsicMeasurable");
                return Integer.valueOf(intrinsicMeasurable.maxIntrinsicWidth(h));
            }
        });
    }

    @Override // androidx.compose.ui.layout.MeasurePolicy
    public int minIntrinsicWidth(IntrinsicMeasureScope $this$minIntrinsicWidth, List<? extends IntrinsicMeasurable> measurables, int height) {
        Intrinsics.checkNotNullParameter($this$minIntrinsicWidth, "<this>");
        Intrinsics.checkNotNullParameter(measurables, "measurables");
        return intrinsicWidth(measurables, height, new Function2<IntrinsicMeasurable, Integer, Integer>() { // from class: androidx.compose.material3.TextFieldMeasurePolicy$minIntrinsicWidth$1
            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Integer invoke(IntrinsicMeasurable intrinsicMeasurable, Integer num) {
                return invoke(intrinsicMeasurable, num.intValue());
            }

            public final Integer invoke(IntrinsicMeasurable intrinsicMeasurable, int h) {
                Intrinsics.checkNotNullParameter(intrinsicMeasurable, "intrinsicMeasurable");
                return Integer.valueOf(intrinsicMeasurable.minIntrinsicWidth(h));
            }
        });
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final int intrinsicWidth(List<? extends IntrinsicMeasurable> list, int height, Function2<? super IntrinsicMeasurable, ? super Integer, Integer> function2) {
        Object obj;
        Object obj2;
        Object obj3;
        Object obj4;
        int m1633calculateWidthVsPV1Ek;
        List<? extends IntrinsicMeasurable> $this$first$iv = list;
        for (Object element$iv : $this$first$iv) {
            if (Intrinsics.areEqual(TextFieldImplKt.getLayoutId((IntrinsicMeasurable) element$iv), "TextField")) {
                int textFieldWidth = function2.invoke(element$iv, Integer.valueOf(height)).intValue();
                Iterator<T> it = list.iterator();
                while (true) {
                    obj = null;
                    if (!it.hasNext()) {
                        obj2 = null;
                        break;
                    }
                    obj2 = it.next();
                    if (Intrinsics.areEqual(TextFieldImplKt.getLayoutId((IntrinsicMeasurable) obj2), "Label")) {
                        break;
                    }
                }
                IntrinsicMeasurable it2 = (IntrinsicMeasurable) obj2;
                int labelWidth = it2 != null ? function2.invoke(it2, Integer.valueOf(height)).intValue() : 0;
                Iterator<T> it3 = list.iterator();
                while (true) {
                    if (!it3.hasNext()) {
                        obj3 = null;
                        break;
                    }
                    obj3 = it3.next();
                    if (Intrinsics.areEqual(TextFieldImplKt.getLayoutId((IntrinsicMeasurable) obj3), "Trailing")) {
                        break;
                    }
                }
                IntrinsicMeasurable it4 = (IntrinsicMeasurable) obj3;
                int trailingWidth = it4 != null ? function2.invoke(it4, Integer.valueOf(height)).intValue() : 0;
                Iterator<T> it5 = list.iterator();
                while (true) {
                    if (!it5.hasNext()) {
                        obj4 = null;
                        break;
                    }
                    obj4 = it5.next();
                    if (Intrinsics.areEqual(TextFieldImplKt.getLayoutId((IntrinsicMeasurable) obj4), "Leading")) {
                        break;
                    }
                }
                IntrinsicMeasurable it6 = (IntrinsicMeasurable) obj4;
                int leadingWidth = it6 != null ? function2.invoke(it6, Integer.valueOf(height)).intValue() : 0;
                Iterator<T> it7 = list.iterator();
                while (true) {
                    if (!it7.hasNext()) {
                        break;
                    }
                    Object next = it7.next();
                    if (Intrinsics.areEqual(TextFieldImplKt.getLayoutId((IntrinsicMeasurable) next), "Hint")) {
                        obj = next;
                        break;
                    }
                }
                IntrinsicMeasurable it8 = (IntrinsicMeasurable) obj;
                int placeholderWidth = it8 != null ? function2.invoke(it8, Integer.valueOf(height)).intValue() : 0;
                m1633calculateWidthVsPV1Ek = TextFieldKt.m1633calculateWidthVsPV1Ek(leadingWidth, trailingWidth, textFieldWidth, labelWidth, placeholderWidth, TextFieldImplKt.getZeroConstraints());
                return m1633calculateWidthVsPV1Ek;
            }
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final int intrinsicHeight(IntrinsicMeasureScope $this$intrinsicHeight, List<? extends IntrinsicMeasurable> list, int width, Function2<? super IntrinsicMeasurable, ? super Integer, Integer> function2) {
        Object obj;
        Object obj2;
        Object obj3;
        Object obj4;
        Object obj5;
        int m1632calculateHeightjCXOeKk;
        List<? extends IntrinsicMeasurable> $this$first$iv = list;
        for (Object element$iv : $this$first$iv) {
            if (Intrinsics.areEqual(TextFieldImplKt.getLayoutId((IntrinsicMeasurable) element$iv), "TextField")) {
                int textFieldHeight = function2.invoke(element$iv, Integer.valueOf(width)).intValue();
                Iterator<T> it = list.iterator();
                while (true) {
                    obj = null;
                    if (!it.hasNext()) {
                        obj2 = null;
                        break;
                    }
                    obj2 = it.next();
                    if (Intrinsics.areEqual(TextFieldImplKt.getLayoutId((IntrinsicMeasurable) obj2), "Label")) {
                        break;
                    }
                }
                IntrinsicMeasurable it2 = (IntrinsicMeasurable) obj2;
                int labelHeight = it2 != null ? function2.invoke(it2, Integer.valueOf(width)).intValue() : 0;
                Iterator<T> it3 = list.iterator();
                while (true) {
                    if (!it3.hasNext()) {
                        obj3 = null;
                        break;
                    }
                    obj3 = it3.next();
                    if (Intrinsics.areEqual(TextFieldImplKt.getLayoutId((IntrinsicMeasurable) obj3), "Trailing")) {
                        break;
                    }
                }
                IntrinsicMeasurable it4 = (IntrinsicMeasurable) obj3;
                int trailingHeight = it4 != null ? function2.invoke(it4, Integer.valueOf(width)).intValue() : 0;
                Iterator<T> it5 = list.iterator();
                while (true) {
                    if (!it5.hasNext()) {
                        obj4 = null;
                        break;
                    }
                    obj4 = it5.next();
                    if (Intrinsics.areEqual(TextFieldImplKt.getLayoutId((IntrinsicMeasurable) obj4), "Leading")) {
                        break;
                    }
                }
                IntrinsicMeasurable it6 = (IntrinsicMeasurable) obj4;
                int leadingHeight = it6 != null ? function2.invoke(it6, Integer.valueOf(width)).intValue() : 0;
                Iterator<T> it7 = list.iterator();
                while (true) {
                    if (!it7.hasNext()) {
                        obj5 = null;
                        break;
                    }
                    obj5 = it7.next();
                    if (Intrinsics.areEqual(TextFieldImplKt.getLayoutId((IntrinsicMeasurable) obj5), "Hint")) {
                        break;
                    }
                }
                IntrinsicMeasurable it8 = (IntrinsicMeasurable) obj5;
                int placeholderHeight = it8 != null ? function2.invoke(it8, Integer.valueOf(width)).intValue() : 0;
                Iterator<T> it9 = list.iterator();
                while (true) {
                    if (!it9.hasNext()) {
                        break;
                    }
                    Object next = it9.next();
                    if (Intrinsics.areEqual(TextFieldImplKt.getLayoutId((IntrinsicMeasurable) next), TextFieldImplKt.SupportingId)) {
                        obj = next;
                        break;
                    }
                }
                IntrinsicMeasurable it10 = (IntrinsicMeasurable) obj;
                int supportingHeight = it10 != null ? function2.invoke(it10, Integer.valueOf(width)).intValue() : 0;
                m1632calculateHeightjCXOeKk = TextFieldKt.m1632calculateHeightjCXOeKk(textFieldHeight, labelHeight > 0, labelHeight, leadingHeight, trailingHeight, placeholderHeight, supportingHeight, TextFieldImplKt.getZeroConstraints(), $this$intrinsicHeight.getDensity(), this.paddingValues);
                return m1632calculateHeightjCXOeKk;
            }
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }
}
