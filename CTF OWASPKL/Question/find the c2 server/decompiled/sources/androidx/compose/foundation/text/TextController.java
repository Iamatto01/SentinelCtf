package androidx.compose.foundation.text;

import androidx.compose.foundation.text.selection.MouseSelectionObserver;
import androidx.compose.foundation.text.selection.MultiWidgetSelectionDelegate;
import androidx.compose.foundation.text.selection.Selectable;
import androidx.compose.foundation.text.selection.Selection;
import androidx.compose.foundation.text.selection.SelectionAdjustment;
import androidx.compose.foundation.text.selection.SelectionRegistrar;
import androidx.compose.foundation.text.selection.SelectionRegistrarKt;
import androidx.compose.runtime.RememberObserver;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.draw.DrawModifierKt;
import androidx.compose.ui.geometry.Offset;
import androidx.compose.ui.geometry.Size;
import androidx.compose.ui.graphics.Canvas;
import androidx.compose.ui.graphics.ClipOp;
import androidx.compose.ui.graphics.GraphicsLayerModifierKt;
import androidx.compose.ui.graphics.Path;
import androidx.compose.ui.graphics.drawscope.DrawContext;
import androidx.compose.ui.graphics.drawscope.DrawScope;
import androidx.compose.ui.graphics.drawscope.DrawTransform;
import androidx.compose.ui.input.pointer.PointerIconKt;
import androidx.compose.ui.input.pointer.SuspendingPointerInputFilterKt;
import androidx.compose.ui.layout.IntrinsicMeasurable;
import androidx.compose.ui.layout.IntrinsicMeasureScope;
import androidx.compose.ui.layout.LayoutCoordinates;
import androidx.compose.ui.layout.MeasurePolicy;
import androidx.compose.ui.layout.OnGloballyPositionedModifierKt;
import androidx.compose.ui.semantics.SemanticsModifierKt;
import androidx.compose.ui.semantics.SemanticsPropertiesKt;
import androidx.compose.ui.semantics.SemanticsPropertyReceiver;
import androidx.compose.ui.text.AnnotatedString;
import androidx.compose.ui.text.TextLayoutResult;
import androidx.compose.ui.text.style.TextOverflow;
import androidx.compose.ui.unit.ConstraintsKt;
import androidx.compose.ui.unit.IntSize;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt;
/* compiled from: CoreText.kt */
@Metadata(d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\b\u0000\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0010\u0010\u001c\u001a\u00020\u00062\u0006\u0010\u001d\u001a\u00020\u001eH\u0002J\b\u0010\u001f\u001a\u00020 H\u0016J\b\u0010!\u001a\u00020 H\u0016J\b\u0010\"\u001a\u00020 H\u0016J%\u0010#\u001a\u00020$2\u0006\u0010%\u001a\u00020&2\u0006\u0010'\u001a\u00020&H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b(\u0010)J\u000e\u0010*\u001a\u00020 2\u0006\u0010+\u001a\u00020,J\u0010\u0010-\u001a\u00020 2\b\u0010\u0015\u001a\u0004\u0018\u00010\u0016J\f\u0010.\u001a\u00020\u0006*\u00020\u0006H\u0003R\u000e\u0010\u0005\u001a\u00020\u0006X\u0082\u0004¢\u0006\u0002\n\u0000R\u001a\u0010\u0007\u001a\u00020\bX\u0086.¢\u0006\u000e\n\u0000\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\fR\u0011\u0010\r\u001a\u00020\u000e¢\u0006\b\n\u0000\u001a\u0004\b\u000f\u0010\u0010R\u0011\u0010\u0011\u001a\u00020\u00068F¢\u0006\u0006\u001a\u0004\b\u0012\u0010\u0013R\u000e\u0010\u0014\u001a\u00020\u0006X\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\u0015\u001a\u0004\u0018\u00010\u0016X\u0082\u000e¢\u0006\u0002\n\u0000R\u001e\u0010\u0018\u001a\u00020\u00062\u0006\u0010\u0017\u001a\u00020\u0006@BX\u0080\u000e¢\u0006\b\n\u0000\u001a\u0004\b\u0019\u0010\u0013R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u001a\u0010\u001b\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006/"}, d2 = {"Landroidx/compose/foundation/text/TextController;", "Landroidx/compose/runtime/RememberObserver;", "state", "Landroidx/compose/foundation/text/TextState;", "(Landroidx/compose/foundation/text/TextState;)V", "coreModifiers", "Landroidx/compose/ui/Modifier;", "longPressDragObserver", "Landroidx/compose/foundation/text/TextDragObserver;", "getLongPressDragObserver", "()Landroidx/compose/foundation/text/TextDragObserver;", "setLongPressDragObserver", "(Landroidx/compose/foundation/text/TextDragObserver;)V", "measurePolicy", "Landroidx/compose/ui/layout/MeasurePolicy;", "getMeasurePolicy", "()Landroidx/compose/ui/layout/MeasurePolicy;", "modifiers", "getModifiers", "()Landroidx/compose/ui/Modifier;", "selectionModifiers", "selectionRegistrar", "Landroidx/compose/foundation/text/selection/SelectionRegistrar;", "<set-?>", "semanticsModifier", "getSemanticsModifier$foundation_release", "getState", "()Landroidx/compose/foundation/text/TextState;", "createSemanticsModifierFor", "text", "Landroidx/compose/ui/text/AnnotatedString;", "onAbandoned", "", "onForgotten", "onRemembered", "outOfBoundary", "", "start", "Landroidx/compose/ui/geometry/Offset;", "end", "outOfBoundary-0a9Yr6o", "(JJ)Z", "setTextDelegate", "textDelegate", "Landroidx/compose/foundation/text/TextDelegate;", "update", "drawTextAndSelectionBehind", "foundation_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class TextController implements RememberObserver {
    private final Modifier coreModifiers;
    public TextDragObserver longPressDragObserver;
    private final MeasurePolicy measurePolicy;
    private Modifier selectionModifiers;
    private SelectionRegistrar selectionRegistrar;
    private Modifier semanticsModifier;
    private final TextState state;

    public TextController(TextState state) {
        Intrinsics.checkNotNullParameter(state, "state");
        this.state = state;
        this.measurePolicy = new MeasurePolicy() { // from class: androidx.compose.foundation.text.TextController$measurePolicy$1
            /* JADX WARN: Code restructure failed: missing block: B:8:0x0069, code lost:
                r10 = r5.selectionRegistrar;
             */
            @Override // androidx.compose.ui.layout.MeasurePolicy
            /* renamed from: measure-3p2s80s */
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public androidx.compose.ui.layout.MeasureResult mo11measure3p2s80s(androidx.compose.ui.layout.MeasureScope r32, java.util.List<? extends androidx.compose.ui.layout.Measurable> r33, long r34) {
                /*
                    Method dump skipped, instructions count: 422
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.TextController$measurePolicy$1.mo11measure3p2s80s(androidx.compose.ui.layout.MeasureScope, java.util.List, long):androidx.compose.ui.layout.MeasureResult");
            }

            @Override // androidx.compose.ui.layout.MeasurePolicy
            public int minIntrinsicWidth(IntrinsicMeasureScope $this$minIntrinsicWidth, List<? extends IntrinsicMeasurable> measurables, int height) {
                Intrinsics.checkNotNullParameter($this$minIntrinsicWidth, "<this>");
                Intrinsics.checkNotNullParameter(measurables, "measurables");
                TextController.this.getState().getTextDelegate().layoutIntrinsics($this$minIntrinsicWidth.getLayoutDirection());
                return TextController.this.getState().getTextDelegate().getMinIntrinsicWidth();
            }

            @Override // androidx.compose.ui.layout.MeasurePolicy
            public int minIntrinsicHeight(IntrinsicMeasureScope $this$minIntrinsicHeight, List<? extends IntrinsicMeasurable> measurables, int width) {
                Intrinsics.checkNotNullParameter($this$minIntrinsicHeight, "<this>");
                Intrinsics.checkNotNullParameter(measurables, "measurables");
                return IntSize.m5281getHeightimpl(TextDelegate.m761layoutNN6EwU$default(TextController.this.getState().getTextDelegate(), ConstraintsKt.Constraints(0, width, 0, Integer.MAX_VALUE), $this$minIntrinsicHeight.getLayoutDirection(), null, 4, null).m4610getSizeYbymL2g());
            }

            @Override // androidx.compose.ui.layout.MeasurePolicy
            public int maxIntrinsicWidth(IntrinsicMeasureScope $this$maxIntrinsicWidth, List<? extends IntrinsicMeasurable> measurables, int height) {
                Intrinsics.checkNotNullParameter($this$maxIntrinsicWidth, "<this>");
                Intrinsics.checkNotNullParameter(measurables, "measurables");
                TextController.this.getState().getTextDelegate().layoutIntrinsics($this$maxIntrinsicWidth.getLayoutDirection());
                return TextController.this.getState().getTextDelegate().getMaxIntrinsicWidth();
            }

            @Override // androidx.compose.ui.layout.MeasurePolicy
            public int maxIntrinsicHeight(IntrinsicMeasureScope $this$maxIntrinsicHeight, List<? extends IntrinsicMeasurable> measurables, int width) {
                Intrinsics.checkNotNullParameter($this$maxIntrinsicHeight, "<this>");
                Intrinsics.checkNotNullParameter(measurables, "measurables");
                return IntSize.m5281getHeightimpl(TextDelegate.m761layoutNN6EwU$default(TextController.this.getState().getTextDelegate(), ConstraintsKt.Constraints(0, width, 0, Integer.MAX_VALUE), $this$maxIntrinsicHeight.getLayoutDirection(), null, 4, null).m4610getSizeYbymL2g());
            }
        };
        this.coreModifiers = OnGloballyPositionedModifierKt.onGloballyPositioned(drawTextAndSelectionBehind(Modifier.Companion), new Function1<LayoutCoordinates, Unit>() { // from class: androidx.compose.foundation.text.TextController$coreModifiers$1
            /* JADX INFO: Access modifiers changed from: package-private */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LayoutCoordinates layoutCoordinates) {
                invoke2(layoutCoordinates);
                return Unit.INSTANCE;
            }

            /* JADX WARN: Code restructure failed: missing block: B:6:0x0039, code lost:
                r2 = r5.this$0.selectionRegistrar;
             */
            /* renamed from: invoke  reason: avoid collision after fix types in other method */
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public final void invoke2(androidx.compose.ui.layout.LayoutCoordinates r6) {
                /*
                    r5 = this;
                    java.lang.String r0 = "it"
                    kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
                    androidx.compose.foundation.text.TextController r0 = androidx.compose.foundation.text.TextController.this
                    androidx.compose.foundation.text.TextState r0 = r0.getState()
                    r0.setLayoutCoordinates(r6)
                    androidx.compose.foundation.text.TextController r0 = androidx.compose.foundation.text.TextController.this
                    androidx.compose.foundation.text.selection.SelectionRegistrar r0 = androidx.compose.foundation.text.TextController.access$getSelectionRegistrar$p(r0)
                    androidx.compose.foundation.text.TextController r1 = androidx.compose.foundation.text.TextController.this
                    androidx.compose.foundation.text.TextState r1 = r1.getState()
                    long r1 = r1.getSelectableId()
                    boolean r0 = androidx.compose.foundation.text.selection.SelectionRegistrarKt.hasSelection(r0, r1)
                    if (r0 == 0) goto L57
                    long r0 = androidx.compose.ui.layout.LayoutCoordinatesKt.positionInWindow(r6)
                    androidx.compose.foundation.text.TextController r2 = androidx.compose.foundation.text.TextController.this
                    androidx.compose.foundation.text.TextState r2 = r2.getState()
                    long r2 = r2.m796getPreviousGlobalPositionF1C5BW0()
                    boolean r2 = androidx.compose.ui.geometry.Offset.m2365equalsimpl0(r0, r2)
                    if (r2 != 0) goto L4e
                    androidx.compose.foundation.text.TextController r2 = androidx.compose.foundation.text.TextController.this
                    androidx.compose.foundation.text.selection.SelectionRegistrar r2 = androidx.compose.foundation.text.TextController.access$getSelectionRegistrar$p(r2)
                    if (r2 == 0) goto L4e
                    androidx.compose.foundation.text.TextController r3 = androidx.compose.foundation.text.TextController.this
                    androidx.compose.foundation.text.TextState r3 = r3.getState()
                    long r3 = r3.getSelectableId()
                    r2.notifyPositionChange(r3)
                L4e:
                    androidx.compose.foundation.text.TextController r2 = androidx.compose.foundation.text.TextController.this
                    androidx.compose.foundation.text.TextState r2 = r2.getState()
                    r2.m798setPreviousGlobalPositionk4lQ0M(r0)
                L57:
                    return
                */
                throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.TextController$coreModifiers$1.invoke2(androidx.compose.ui.layout.LayoutCoordinates):void");
            }
        });
        this.semanticsModifier = createSemanticsModifierFor(state.getTextDelegate().getText());
        this.selectionModifiers = Modifier.Companion;
    }

    public final TextState getState() {
        return this.state;
    }

    public final TextDragObserver getLongPressDragObserver() {
        TextDragObserver textDragObserver = this.longPressDragObserver;
        if (textDragObserver != null) {
            return textDragObserver;
        }
        Intrinsics.throwUninitializedPropertyAccessException("longPressDragObserver");
        return null;
    }

    public final void setLongPressDragObserver(TextDragObserver textDragObserver) {
        Intrinsics.checkNotNullParameter(textDragObserver, "<set-?>");
        this.longPressDragObserver = textDragObserver;
    }

    /* JADX WARN: Type inference failed for: r0v4, types: [androidx.compose.foundation.text.TextController$update$mouseSelectionObserver$1, java.lang.Object] */
    public final void update(final SelectionRegistrar selectionRegistrar) {
        Modifier.Companion companion;
        this.selectionRegistrar = selectionRegistrar;
        if (selectionRegistrar != null) {
            if (TouchMode_androidKt.isInTouchMode()) {
                setLongPressDragObserver(new TextDragObserver() { // from class: androidx.compose.foundation.text.TextController$update$1
                    private long lastPosition = Offset.Companion.m2384getZeroF1C5BW0();
                    private long dragTotalDistance = Offset.Companion.m2384getZeroF1C5BW0();

                    public final long getLastPosition() {
                        return this.lastPosition;
                    }

                    public final void setLastPosition(long j) {
                        this.lastPosition = j;
                    }

                    public final long getDragTotalDistance() {
                        return this.dragTotalDistance;
                    }

                    public final void setDragTotalDistance(long j) {
                        this.dragTotalDistance = j;
                    }

                    @Override // androidx.compose.foundation.text.TextDragObserver
                    /* renamed from: onDown-k-4lQ0M  reason: not valid java name */
                    public void mo754onDownk4lQ0M(long point) {
                    }

                    @Override // androidx.compose.foundation.text.TextDragObserver
                    public void onUp() {
                    }

                    @Override // androidx.compose.foundation.text.TextDragObserver
                    /* renamed from: onStart-k-4lQ0M  reason: not valid java name */
                    public void mo756onStartk4lQ0M(long startPoint) {
                        boolean m753outOfBoundary0a9Yr6o;
                        LayoutCoordinates it = TextController.this.getState().getLayoutCoordinates();
                        if (it != null) {
                            TextController textController = TextController.this;
                            SelectionRegistrar selectionRegistrar2 = selectionRegistrar;
                            if (!it.isAttached()) {
                                return;
                            }
                            m753outOfBoundary0a9Yr6o = textController.m753outOfBoundary0a9Yr6o(startPoint, startPoint);
                            if (m753outOfBoundary0a9Yr6o) {
                                selectionRegistrar2.notifySelectionUpdateSelectAll(textController.getState().getSelectableId());
                            } else {
                                selectionRegistrar2.mo866notifySelectionUpdateStartd4ec7I(it, startPoint, SelectionAdjustment.Companion.getWord());
                            }
                            this.lastPosition = startPoint;
                        }
                        if (SelectionRegistrarKt.hasSelection(selectionRegistrar, TextController.this.getState().getSelectableId())) {
                            this.dragTotalDistance = Offset.Companion.m2384getZeroF1C5BW0();
                        }
                    }

                    @Override // androidx.compose.foundation.text.TextDragObserver
                    /* renamed from: onDrag-k-4lQ0M  reason: not valid java name */
                    public void mo755onDragk4lQ0M(long delta) {
                        boolean m753outOfBoundary0a9Yr6o;
                        LayoutCoordinates it = TextController.this.getState().getLayoutCoordinates();
                        if (it != null) {
                            SelectionRegistrar selectionRegistrar2 = selectionRegistrar;
                            TextController textController = TextController.this;
                            if (it.isAttached() && SelectionRegistrarKt.hasSelection(selectionRegistrar2, textController.getState().getSelectableId())) {
                                long m2373plusMKHz9U = Offset.m2373plusMKHz9U(this.dragTotalDistance, delta);
                                this.dragTotalDistance = m2373plusMKHz9U;
                                long newPosition = Offset.m2373plusMKHz9U(this.lastPosition, m2373plusMKHz9U);
                                m753outOfBoundary0a9Yr6o = textController.m753outOfBoundary0a9Yr6o(this.lastPosition, newPosition);
                                if (!m753outOfBoundary0a9Yr6o) {
                                    boolean consumed = selectionRegistrar2.mo865notifySelectionUpdate5iVPX68(it, newPosition, this.lastPosition, false, SelectionAdjustment.Companion.getCharacterWithWordAccelerate());
                                    if (consumed) {
                                        this.lastPosition = newPosition;
                                        this.dragTotalDistance = Offset.Companion.m2384getZeroF1C5BW0();
                                    }
                                }
                            }
                        }
                    }

                    @Override // androidx.compose.foundation.text.TextDragObserver
                    public void onStop() {
                        if (SelectionRegistrarKt.hasSelection(selectionRegistrar, TextController.this.getState().getSelectableId())) {
                            selectionRegistrar.notifySelectionUpdateEnd();
                        }
                    }

                    @Override // androidx.compose.foundation.text.TextDragObserver
                    public void onCancel() {
                        if (SelectionRegistrarKt.hasSelection(selectionRegistrar, TextController.this.getState().getSelectableId())) {
                            selectionRegistrar.notifySelectionUpdateEnd();
                        }
                    }
                });
                companion = SuspendingPointerInputFilterKt.pointerInput(Modifier.Companion, getLongPressDragObserver(), new TextController$update$2(this, null));
            } else {
                ?? r0 = new MouseSelectionObserver() { // from class: androidx.compose.foundation.text.TextController$update$mouseSelectionObserver$1
                    private long lastPosition = Offset.Companion.m2384getZeroF1C5BW0();

                    public final long getLastPosition() {
                        return this.lastPosition;
                    }

                    public final void setLastPosition(long j) {
                        this.lastPosition = j;
                    }

                    @Override // androidx.compose.foundation.text.selection.MouseSelectionObserver
                    /* renamed from: onExtend-k-4lQ0M  reason: not valid java name */
                    public boolean mo758onExtendk4lQ0M(long downPosition) {
                        LayoutCoordinates layoutCoordinates = TextController.this.getState().getLayoutCoordinates();
                        if (layoutCoordinates != null) {
                            SelectionRegistrar it = selectionRegistrar;
                            TextController textController = TextController.this;
                            if (layoutCoordinates.isAttached()) {
                                boolean consumed = it.mo865notifySelectionUpdate5iVPX68(layoutCoordinates, downPosition, this.lastPosition, false, SelectionAdjustment.Companion.getNone());
                                if (consumed) {
                                    this.lastPosition = downPosition;
                                }
                                return SelectionRegistrarKt.hasSelection(it, textController.getState().getSelectableId());
                            }
                            return false;
                        }
                        return false;
                    }

                    @Override // androidx.compose.foundation.text.selection.MouseSelectionObserver
                    /* renamed from: onExtendDrag-k-4lQ0M  reason: not valid java name */
                    public boolean mo759onExtendDragk4lQ0M(long dragPosition) {
                        LayoutCoordinates layoutCoordinates = TextController.this.getState().getLayoutCoordinates();
                        if (layoutCoordinates != null) {
                            SelectionRegistrar selectionRegistrar2 = selectionRegistrar;
                            TextController textController = TextController.this;
                            if (layoutCoordinates.isAttached() && SelectionRegistrarKt.hasSelection(selectionRegistrar2, textController.getState().getSelectableId())) {
                                boolean consumed = selectionRegistrar2.mo865notifySelectionUpdate5iVPX68(layoutCoordinates, dragPosition, this.lastPosition, false, SelectionAdjustment.Companion.getNone());
                                if (consumed) {
                                    this.lastPosition = dragPosition;
                                    return true;
                                }
                                return true;
                            }
                            return false;
                        }
                        return true;
                    }

                    @Override // androidx.compose.foundation.text.selection.MouseSelectionObserver
                    /* renamed from: onStart-3MmeM6k  reason: not valid java name */
                    public boolean mo760onStart3MmeM6k(long downPosition, SelectionAdjustment adjustment) {
                        Intrinsics.checkNotNullParameter(adjustment, "adjustment");
                        LayoutCoordinates it = TextController.this.getState().getLayoutCoordinates();
                        if (it != null) {
                            SelectionRegistrar selectionRegistrar2 = selectionRegistrar;
                            TextController textController = TextController.this;
                            if (it.isAttached()) {
                                selectionRegistrar2.mo866notifySelectionUpdateStartd4ec7I(it, downPosition, adjustment);
                                this.lastPosition = downPosition;
                                return SelectionRegistrarKt.hasSelection(selectionRegistrar2, textController.getState().getSelectableId());
                            }
                            return false;
                        }
                        return false;
                    }

                    @Override // androidx.compose.foundation.text.selection.MouseSelectionObserver
                    /* renamed from: onDrag-3MmeM6k  reason: not valid java name */
                    public boolean mo757onDrag3MmeM6k(long dragPosition, SelectionAdjustment adjustment) {
                        Intrinsics.checkNotNullParameter(adjustment, "adjustment");
                        LayoutCoordinates it = TextController.this.getState().getLayoutCoordinates();
                        if (it != null) {
                            SelectionRegistrar selectionRegistrar2 = selectionRegistrar;
                            TextController textController = TextController.this;
                            if (!it.isAttached() || !SelectionRegistrarKt.hasSelection(selectionRegistrar2, textController.getState().getSelectableId())) {
                                return false;
                            }
                            boolean consumed = selectionRegistrar2.mo865notifySelectionUpdate5iVPX68(it, dragPosition, this.lastPosition, false, adjustment);
                            if (consumed) {
                                this.lastPosition = dragPosition;
                            }
                        }
                        return true;
                    }
                };
                companion = PointerIconKt.pointerHoverIcon$default(SuspendingPointerInputFilterKt.pointerInput(Modifier.Companion, (Object) r0, new TextController$update$3(r0, null)), TextPointerIcon_androidKt.getTextPointerIcon(), false, 2, null);
            }
        } else {
            companion = Modifier.Companion;
        }
        this.selectionModifiers = companion;
    }

    public final void setTextDelegate(TextDelegate textDelegate) {
        Intrinsics.checkNotNullParameter(textDelegate, "textDelegate");
        if (this.state.getTextDelegate() == textDelegate) {
            return;
        }
        this.state.setTextDelegate(textDelegate);
        this.semanticsModifier = createSemanticsModifierFor(this.state.getTextDelegate().getText());
    }

    public final MeasurePolicy getMeasurePolicy() {
        return this.measurePolicy;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: outOfBoundary-0a9Yr6o  reason: not valid java name */
    public final boolean m753outOfBoundary0a9Yr6o(long start, long end) {
        TextLayoutResult it = this.state.getLayoutResult();
        if (it != null) {
            int lastOffset = it.getLayoutInput().getText().getText().length();
            int rawStartOffset = it.m4609getOffsetForPositionk4lQ0M(start);
            int rawEndOffset = it.m4609getOffsetForPositionk4lQ0M(end);
            return (rawStartOffset >= lastOffset + (-1) && rawEndOffset >= lastOffset + (-1)) || (rawStartOffset < 0 && rawEndOffset < 0);
        }
        return false;
    }

    private final Modifier drawTextAndSelectionBehind(Modifier $this$drawTextAndSelectionBehind) {
        return DrawModifierKt.drawBehind(GraphicsLayerModifierKt.m2752graphicsLayerAp8cVGQ$default($this$drawTextAndSelectionBehind, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0L, null, false, null, 0L, 0L, 0, 131071, null), new Function1<DrawScope, Unit>() { // from class: androidx.compose.foundation.text.TextController$drawTextAndSelectionBehind$1
            /* JADX INFO: Access modifiers changed from: package-private */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(DrawScope drawScope) {
                invoke2(drawScope);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke  reason: avoid collision after fix types in other method */
            public final void invoke2(DrawScope drawBehind) {
                SelectionRegistrar selectionRegistrar;
                int offset;
                int offset2;
                Map<Long, Selection> subselections;
                Intrinsics.checkNotNullParameter(drawBehind, "$this$drawBehind");
                TextLayoutResult it = TextController.this.getState().getLayoutResult();
                if (it != null) {
                    TextController textController = TextController.this;
                    textController.getState().getDrawScopeInvalidation();
                    selectionRegistrar = textController.selectionRegistrar;
                    Selection selection = (selectionRegistrar == null || (subselections = selectionRegistrar.getSubselections()) == null) ? null : subselections.get(Long.valueOf(textController.getState().getSelectableId()));
                    Selectable selectable = textController.getState().getSelectable();
                    int lastVisibleOffset = selectable != null ? selectable.getLastVisibleOffset() : 0;
                    if (selection != null) {
                        if (!selection.getHandlesCrossed()) {
                            offset = selection.getStart().getOffset();
                        } else {
                            offset = selection.getEnd().getOffset();
                        }
                        int start = RangesKt.coerceIn(offset, 0, lastVisibleOffset);
                        if (!selection.getHandlesCrossed()) {
                            offset2 = selection.getEnd().getOffset();
                        } else {
                            offset2 = selection.getStart().getOffset();
                        }
                        int end = RangesKt.coerceIn(offset2, 0, lastVisibleOffset);
                        if (start != end) {
                            Path selectionPath = it.getMultiParagraph().getPathForRange(start, end);
                            if (TextOverflow.m5034equalsimpl0(it.getLayoutInput().m4606getOverflowgIe3tQ8(), TextOverflow.Companion.m5043getVisiblegIe3tQ8())) {
                                DrawScope.m3137drawPathLG529CI$default(drawBehind, selectionPath, textController.getState().m797getSelectionBackgroundColor0d7_KjU(), 0.0f, null, null, 0, 60, null);
                            } else {
                                float right$iv = Size.m2437getWidthimpl(drawBehind.mo3146getSizeNHjbRc());
                                float bottom$iv = Size.m2434getHeightimpl(drawBehind.mo3146getSizeNHjbRc());
                                int clipOp$iv = ClipOp.Companion.m2595getIntersectrtfAjoo();
                                DrawContext $this$withTransform_u24lambda_u246$iv$iv = drawBehind.getDrawContext();
                                long previousSize$iv$iv = $this$withTransform_u24lambda_u246$iv$iv.mo3071getSizeNHjbRc();
                                $this$withTransform_u24lambda_u246$iv$iv.getCanvas().save();
                                DrawTransform $this$clipRect_rOu3jXo_u24lambda_u244$iv = $this$withTransform_u24lambda_u246$iv$iv.getTransform();
                                $this$clipRect_rOu3jXo_u24lambda_u244$iv.mo3074clipRectN_I0leg(0.0f, 0.0f, right$iv, bottom$iv, clipOp$iv);
                                DrawScope.m3137drawPathLG529CI$default(drawBehind, selectionPath, textController.getState().m797getSelectionBackgroundColor0d7_KjU(), 0.0f, null, null, 0, 60, null);
                                $this$withTransform_u24lambda_u246$iv$iv.getCanvas().restore();
                                $this$withTransform_u24lambda_u246$iv$iv.mo3072setSizeuvyYCjk(previousSize$iv$iv);
                            }
                        }
                    }
                    Canvas canvas = drawBehind.getDrawContext().getCanvas();
                    TextDelegate.Companion.paint(canvas, it);
                }
            }
        });
    }

    public final Modifier getSemanticsModifier$foundation_release() {
        return this.semanticsModifier;
    }

    private final Modifier createSemanticsModifierFor(final AnnotatedString text) {
        return SemanticsModifierKt.semantics$default(Modifier.Companion, false, new Function1<SemanticsPropertyReceiver, Unit>() { // from class: androidx.compose.foundation.text.TextController$createSemanticsModifierFor$1
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
                SemanticsPropertiesKt.setText(semantics, AnnotatedString.this);
                final TextController textController = this;
                SemanticsPropertiesKt.getTextLayoutResult$default(semantics, null, new Function1<List<TextLayoutResult>, Boolean>() { // from class: androidx.compose.foundation.text.TextController$createSemanticsModifierFor$1.1
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public final Boolean invoke(List<TextLayoutResult> it) {
                        boolean z;
                        Intrinsics.checkNotNullParameter(it, "it");
                        if (TextController.this.getState().getLayoutResult() != null) {
                            TextLayoutResult layoutResult = TextController.this.getState().getLayoutResult();
                            Intrinsics.checkNotNull(layoutResult);
                            it.add(layoutResult);
                            z = true;
                        } else {
                            z = false;
                        }
                        return Boolean.valueOf(z);
                    }
                }, 1, null);
            }
        }, 1, null);
    }

    public final Modifier getModifiers() {
        return HeightInLinesModifierKt.heightInLines$default(this.coreModifiers, this.state.getTextDelegate().getStyle(), this.state.getTextDelegate().getMinLines(), 0, 4, null).then(this.semanticsModifier).then(this.selectionModifiers);
    }

    @Override // androidx.compose.runtime.RememberObserver
    public void onRemembered() {
        SelectionRegistrar selectionRegistrar = this.selectionRegistrar;
        if (selectionRegistrar != null) {
            this.state.setSelectable(selectionRegistrar.subscribe(new MultiWidgetSelectionDelegate(this.state.getSelectableId(), new Function0<LayoutCoordinates>() { // from class: androidx.compose.foundation.text.TextController$onRemembered$1$1
                /* JADX INFO: Access modifiers changed from: package-private */
                {
                    super(0);
                }

                /* JADX WARN: Can't rename method to resolve collision */
                @Override // kotlin.jvm.functions.Function0
                public final LayoutCoordinates invoke() {
                    return TextController.this.getState().getLayoutCoordinates();
                }
            }, new Function0<TextLayoutResult>() { // from class: androidx.compose.foundation.text.TextController$onRemembered$1$2
                /* JADX INFO: Access modifiers changed from: package-private */
                {
                    super(0);
                }

                /* JADX WARN: Can't rename method to resolve collision */
                @Override // kotlin.jvm.functions.Function0
                public final TextLayoutResult invoke() {
                    return TextController.this.getState().getLayoutResult();
                }
            })));
        }
    }

    @Override // androidx.compose.runtime.RememberObserver
    public void onForgotten() {
        SelectionRegistrar selectionRegistrar;
        Selectable it = this.state.getSelectable();
        if (it == null || (selectionRegistrar = this.selectionRegistrar) == null) {
            return;
        }
        selectionRegistrar.unsubscribe(it);
    }

    @Override // androidx.compose.runtime.RememberObserver
    public void onAbandoned() {
        SelectionRegistrar selectionRegistrar;
        Selectable it = this.state.getSelectable();
        if (it == null || (selectionRegistrar = this.selectionRegistrar) == null) {
            return;
        }
        selectionRegistrar.unsubscribe(it);
    }
}
