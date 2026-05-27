package androidx.compose.material3;

import androidx.compose.foundation.BackgroundKt;
import androidx.compose.foundation.BorderKt;
import androidx.compose.foundation.BorderStroke;
import androidx.compose.foundation.interaction.InteractionSource;
import androidx.compose.foundation.layout.BoxKt;
import androidx.compose.foundation.layout.PaddingKt;
import androidx.compose.foundation.layout.PaddingValues;
import androidx.compose.foundation.text.selection.TextSelectionColors;
import androidx.compose.foundation.text.selection.TextSelectionColorsKt;
import androidx.compose.material3.tokens.FilledTextFieldTokens;
import androidx.compose.material3.tokens.OutlinedTextFieldTokens;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.ScopeUpdateScope;
import androidx.compose.runtime.State;
import androidx.compose.ui.ComposedModifierKt;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.graphics.Color;
import androidx.compose.ui.graphics.Shape;
import androidx.compose.ui.platform.InspectableValueKt;
import androidx.compose.ui.platform.InspectorInfo;
import androidx.compose.ui.unit.Dp;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: TextFieldDefaults.kt */
@ExperimentalMaterial3Api
@Metadata(d1 = {"\u0000r\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b,\n\u0002\u0018\u0002\n\u0002\b\u0005\bÇ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J7\u0010\u0014\u001a\u00020\u00152\u0006\u0010\u0016\u001a\u00020\u00172\u0006\u0010\u0018\u001a\u00020\u00172\u0006\u0010\u0019\u001a\u00020\u001a2\u0006\u0010\u001b\u001a\u00020\u001c2\b\b\u0002\u0010\u001d\u001a\u00020\u000fH\u0007¢\u0006\u0002\u0010\u001eJS\u0010\u001f\u001a\u00020\u00152\u0006\u0010\u0016\u001a\u00020\u00172\u0006\u0010\u0018\u001a\u00020\u00172\u0006\u0010\u0019\u001a\u00020\u001a2\u0006\u0010\u001b\u001a\u00020\u001c2\b\b\u0002\u0010\u001d\u001a\u00020\u000f2\b\b\u0002\u0010 \u001a\u00020\u00042\b\b\u0002\u0010!\u001a\u00020\u0004H\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\"\u0010#Jî\u0001\u0010$\u001a\u00020\u00152\u0006\u0010%\u001a\u00020&2\u0011\u0010'\u001a\r\u0012\u0004\u0012\u00020\u00150(¢\u0006\u0002\b)2\u0006\u0010\u0016\u001a\u00020\u00172\u0006\u0010*\u001a\u00020\u00172\u0006\u0010+\u001a\u00020,2\u0006\u0010\u0019\u001a\u00020\u001a2\b\b\u0002\u0010\u0018\u001a\u00020\u00172\u0015\b\u0002\u0010-\u001a\u000f\u0012\u0004\u0012\u00020\u0015\u0018\u00010(¢\u0006\u0002\b)2\u0015\b\u0002\u0010.\u001a\u000f\u0012\u0004\u0012\u00020\u0015\u0018\u00010(¢\u0006\u0002\b)2\u0015\b\u0002\u0010/\u001a\u000f\u0012\u0004\u0012\u00020\u0015\u0018\u00010(¢\u0006\u0002\b)2\u0015\b\u0002\u00100\u001a\u000f\u0012\u0004\u0012\u00020\u0015\u0018\u00010(¢\u0006\u0002\b)2\u0015\b\u0002\u00101\u001a\u000f\u0012\u0004\u0012\u00020\u0015\u0018\u00010(¢\u0006\u0002\b)2\b\b\u0002\u0010\u001b\u001a\u00020\u001c2\b\b\u0002\u00102\u001a\u0002032\u0013\b\u0002\u00104\u001a\r\u0012\u0004\u0012\u00020\u00150(¢\u0006\u0002\b)H\u0007¢\u0006\u0002\u00105Jø\u0001\u00106\u001a\u00020\u00152\u0006\u0010%\u001a\u00020&2\u0011\u0010'\u001a\r\u0012\u0004\u0012\u00020\u00150(¢\u0006\u0002\b)2\u0006\u0010\u0016\u001a\u00020\u00172\u0006\u0010*\u001a\u00020\u00172\u0006\u0010+\u001a\u00020,2\u0006\u0010\u0019\u001a\u00020\u001a2\b\b\u0002\u0010\u0018\u001a\u00020\u00172\u0015\b\u0002\u0010-\u001a\u000f\u0012\u0004\u0012\u00020\u0015\u0018\u00010(¢\u0006\u0002\b)2\u0015\b\u0002\u0010.\u001a\u000f\u0012\u0004\u0012\u00020\u0015\u0018\u00010(¢\u0006\u0002\b)2\u0015\b\u0002\u0010/\u001a\u000f\u0012\u0004\u0012\u00020\u0015\u0018\u00010(¢\u0006\u0002\b)2\u0015\b\u0002\u00100\u001a\u000f\u0012\u0004\u0012\u00020\u0015\u0018\u00010(¢\u0006\u0002\b)2\u0015\b\u0002\u00101\u001a\u000f\u0012\u0004\u0012\u00020\u0015\u0018\u00010(¢\u0006\u0002\b)2\b\b\u0002\u0010\u001d\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u001c2\b\b\u0002\u00102\u001a\u0002032\u0013\b\u0002\u00104\u001a\r\u0012\u0004\u0012\u00020\u00150(¢\u0006\u0002\b)H\u0007¢\u0006\u0002\u00107J\u00ad\u0002\u00108\u001a\u00020\u001c2\b\b\u0002\u00109\u001a\u00020:2\b\b\u0002\u0010;\u001a\u00020:2\b\b\u0002\u0010<\u001a\u00020:2\b\b\u0002\u0010=\u001a\u00020:2\b\b\u0002\u0010>\u001a\u00020:2\b\b\u0002\u0010?\u001a\u00020@2\b\b\u0002\u0010A\u001a\u00020:2\b\b\u0002\u0010B\u001a\u00020:2\b\b\u0002\u0010C\u001a\u00020:2\b\b\u0002\u0010D\u001a\u00020:2\b\b\u0002\u0010E\u001a\u00020:2\b\b\u0002\u0010F\u001a\u00020:2\b\b\u0002\u0010G\u001a\u00020:2\b\b\u0002\u0010H\u001a\u00020:2\b\b\u0002\u0010I\u001a\u00020:2\b\b\u0002\u0010J\u001a\u00020:2\b\b\u0002\u0010K\u001a\u00020:2\b\b\u0002\u0010L\u001a\u00020:2\b\b\u0002\u0010M\u001a\u00020:2\b\b\u0002\u0010N\u001a\u00020:2\b\b\u0002\u0010O\u001a\u00020:2\b\b\u0002\u0010P\u001a\u00020:2\b\b\u0002\u0010Q\u001a\u00020:2\b\b\u0002\u0010R\u001a\u00020:2\b\b\u0002\u0010S\u001a\u00020:2\b\b\u0002\u0010T\u001a\u00020:2\b\b\u0002\u0010U\u001a\u00020:2\b\b\u0002\u0010V\u001a\u00020:H\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\bW\u0010XJ=\u0010Y\u001a\u0002032\b\b\u0002\u0010Z\u001a\u00020\u00042\b\b\u0002\u0010[\u001a\u00020\u00042\b\b\u0002\u0010\\\u001a\u00020\u00042\b\b\u0002\u0010]\u001a\u00020\u0004H\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b^\u0010_J=\u0010`\u001a\u0002032\b\b\u0002\u0010Z\u001a\u00020\u00042\b\b\u0002\u0010[\u001a\u00020\u00042\b\b\u0002\u0010\\\u001a\u00020\u00042\b\b\u0002\u0010]\u001a\u00020\u0004H\u0001ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\ba\u0010_J\u00ad\u0002\u0010b\u001a\u00020\u001c2\b\b\u0002\u00109\u001a\u00020:2\b\b\u0002\u0010;\u001a\u00020:2\b\b\u0002\u0010<\u001a\u00020:2\b\b\u0002\u0010=\u001a\u00020:2\b\b\u0002\u0010>\u001a\u00020:2\b\b\u0002\u0010?\u001a\u00020@2\b\b\u0002\u0010c\u001a\u00020:2\b\b\u0002\u0010d\u001a\u00020:2\b\b\u0002\u0010e\u001a\u00020:2\b\b\u0002\u0010f\u001a\u00020:2\b\b\u0002\u0010E\u001a\u00020:2\b\b\u0002\u0010F\u001a\u00020:2\b\b\u0002\u0010G\u001a\u00020:2\b\b\u0002\u0010H\u001a\u00020:2\b\b\u0002\u0010I\u001a\u00020:2\b\b\u0002\u0010J\u001a\u00020:2\b\b\u0002\u0010K\u001a\u00020:2\b\b\u0002\u0010L\u001a\u00020:2\b\b\u0002\u0010M\u001a\u00020:2\b\b\u0002\u0010N\u001a\u00020:2\b\b\u0002\u0010O\u001a\u00020:2\b\b\u0002\u0010P\u001a\u00020:2\b\b\u0002\u0010Q\u001a\u00020:2\b\b\u0002\u0010R\u001a\u00020:2\b\b\u0002\u0010S\u001a\u00020:2\b\b\u0002\u0010T\u001a\u00020:2\b\b\u0002\u0010U\u001a\u00020:2\b\b\u0002\u0010V\u001a\u00020:H\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\bg\u0010XJ=\u0010h\u001a\u0002032\b\b\u0002\u0010Z\u001a\u00020\u00042\b\b\u0002\u0010\\\u001a\u00020\u00042\b\b\u0002\u0010[\u001a\u00020\u00042\b\b\u0002\u0010]\u001a\u00020\u0004H\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\bi\u0010_J=\u0010j\u001a\u0002032\b\b\u0002\u0010Z\u001a\u00020\u00042\b\b\u0002\u0010[\u001a\u00020\u00042\b\b\u0002\u0010\\\u001a\u00020\u00042\b\b\u0002\u0010]\u001a\u00020\u0004H\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\bk\u0010_JM\u0010l\u001a\u00020m*\u00020m2\u0006\u0010\u0016\u001a\u00020\u00172\u0006\u0010\u0018\u001a\u00020\u00172\u0006\u0010\u0019\u001a\u00020\u001a2\u0006\u0010\u001b\u001a\u00020\u001c2\b\b\u0002\u0010n\u001a\u00020\u00042\b\b\u0002\u0010o\u001a\u00020\u0004H\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\bp\u0010qR\u001c\u0010\u0003\u001a\u00020\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010\u0007\u001a\u0004\b\u0005\u0010\u0006R\u001c\u0010\b\u001a\u00020\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010\u0007\u001a\u0004\b\t\u0010\u0006R\u001c\u0010\n\u001a\u00020\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010\u0007\u001a\u0004\b\u000b\u0010\u0006R\u001c\u0010\f\u001a\u00020\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010\u0007\u001a\u0004\b\r\u0010\u0006R\u0011\u0010\u000e\u001a\u00020\u000f8G¢\u0006\u0006\u001a\u0004\b\u0010\u0010\u0011R\u0011\u0010\u0012\u001a\u00020\u000f8G¢\u0006\u0006\u001a\u0004\b\u0013\u0010\u0011\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u0006r"}, d2 = {"Landroidx/compose/material3/TextFieldDefaults;", "", "()V", "FocusedBorderThickness", "Landroidx/compose/ui/unit/Dp;", "getFocusedBorderThickness-D9Ej5fM", "()F", "F", "MinHeight", "getMinHeight-D9Ej5fM", "MinWidth", "getMinWidth-D9Ej5fM", "UnfocusedBorderThickness", "getUnfocusedBorderThickness-D9Ej5fM", "filledShape", "Landroidx/compose/ui/graphics/Shape;", "getFilledShape", "(Landroidx/compose/runtime/Composer;I)Landroidx/compose/ui/graphics/Shape;", "outlinedShape", "getOutlinedShape", "FilledContainerBox", "", "enabled", "", "isError", "interactionSource", "Landroidx/compose/foundation/interaction/InteractionSource;", "colors", "Landroidx/compose/material3/TextFieldColors;", "shape", "(ZZLandroidx/compose/foundation/interaction/InteractionSource;Landroidx/compose/material3/TextFieldColors;Landroidx/compose/ui/graphics/Shape;Landroidx/compose/runtime/Composer;II)V", "OutlinedBorderContainerBox", "focusedBorderThickness", "unfocusedBorderThickness", "OutlinedBorderContainerBox-nbWgWpA", "(ZZLandroidx/compose/foundation/interaction/InteractionSource;Landroidx/compose/material3/TextFieldColors;Landroidx/compose/ui/graphics/Shape;FFLandroidx/compose/runtime/Composer;II)V", "OutlinedTextFieldDecorationBox", "value", "", "innerTextField", "Lkotlin/Function0;", "Landroidx/compose/runtime/Composable;", "singleLine", "visualTransformation", "Landroidx/compose/ui/text/input/VisualTransformation;", "label", "placeholder", "leadingIcon", "trailingIcon", "supportingText", "contentPadding", "Landroidx/compose/foundation/layout/PaddingValues;", "container", "(Ljava/lang/String;Lkotlin/jvm/functions/Function2;ZZLandroidx/compose/ui/text/input/VisualTransformation;Landroidx/compose/foundation/interaction/InteractionSource;ZLkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Landroidx/compose/material3/TextFieldColors;Landroidx/compose/foundation/layout/PaddingValues;Lkotlin/jvm/functions/Function2;Landroidx/compose/runtime/Composer;III)V", "TextFieldDecorationBox", "(Ljava/lang/String;Lkotlin/jvm/functions/Function2;ZZLandroidx/compose/ui/text/input/VisualTransformation;Landroidx/compose/foundation/interaction/InteractionSource;ZLkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Landroidx/compose/ui/graphics/Shape;Landroidx/compose/material3/TextFieldColors;Landroidx/compose/foundation/layout/PaddingValues;Lkotlin/jvm/functions/Function2;Landroidx/compose/runtime/Composer;III)V", "outlinedTextFieldColors", "textColor", "Landroidx/compose/ui/graphics/Color;", "disabledTextColor", "containerColor", "cursorColor", "errorCursorColor", "selectionColors", "Landroidx/compose/foundation/text/selection/TextSelectionColors;", "focusedBorderColor", "unfocusedBorderColor", "disabledBorderColor", "errorBorderColor", "focusedLeadingIconColor", "unfocusedLeadingIconColor", "disabledLeadingIconColor", "errorLeadingIconColor", "focusedTrailingIconColor", "unfocusedTrailingIconColor", "disabledTrailingIconColor", "errorTrailingIconColor", "focusedLabelColor", "unfocusedLabelColor", "disabledLabelColor", "errorLabelColor", "placeholderColor", "disabledPlaceholderColor", "focusedSupportingTextColor", "unfocusedSupportingTextColor", "disabledSupportingTextColor", "errorSupportingTextColor", "outlinedTextFieldColors-l59Burw", "(JJJJJLandroidx/compose/foundation/text/selection/TextSelectionColors;JJJJJJJJJJJJJJJJJJJJJJLandroidx/compose/runtime/Composer;IIII)Landroidx/compose/material3/TextFieldColors;", "outlinedTextFieldPadding", "start", "top", "end", "bottom", "outlinedTextFieldPadding-a9UjIt4", "(FFFF)Landroidx/compose/foundation/layout/PaddingValues;", "supportingTextPadding", "supportingTextPadding-a9UjIt4$material3_release", "textFieldColors", "focusedIndicatorColor", "unfocusedIndicatorColor", "disabledIndicatorColor", "errorIndicatorColor", "textFieldColors-l59Burw", "textFieldWithLabelPadding", "textFieldWithLabelPadding-a9UjIt4", "textFieldWithoutLabelPadding", "textFieldWithoutLabelPadding-a9UjIt4", "indicatorLine", "Landroidx/compose/ui/Modifier;", "focusedIndicatorLineThickness", "unfocusedIndicatorLineThickness", "indicatorLine-gv0btCI", "(Landroidx/compose/ui/Modifier;ZZLandroidx/compose/foundation/interaction/InteractionSource;Landroidx/compose/material3/TextFieldColors;FF)Landroidx/compose/ui/Modifier;", "material3_release"}, k = 1, mv = {1, 7, 1}, xi = 48)
/* loaded from: classes.dex */
public final class TextFieldDefaults {
    public static final TextFieldDefaults INSTANCE = new TextFieldDefaults();
    private static final float MinHeight = Dp.m5122constructorimpl(56);
    private static final float MinWidth = Dp.m5122constructorimpl(280);
    private static final float UnfocusedBorderThickness = Dp.m5122constructorimpl(1);
    private static final float FocusedBorderThickness = Dp.m5122constructorimpl(2);

    private TextFieldDefaults() {
    }

    public final Shape getOutlinedShape(Composer $composer, int $changed) {
        $composer.startReplaceableGroup(-584749279);
        ComposerKt.sourceInformation($composer, "C59@2665L9:TextFieldDefaults.kt#uh7d8r");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-584749279, $changed, -1, "androidx.compose.material3.TextFieldDefaults.<get-outlinedShape> (TextFieldDefaults.kt:59)");
        }
        Shape shape = ShapesKt.toShape(OutlinedTextFieldTokens.INSTANCE.getContainerShape(), $composer, 6);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return shape;
    }

    public final Shape getFilledShape(Composer $composer, int $changed) {
        $composer.startReplaceableGroup(611926497);
        ComposerKt.sourceInformation($composer, "C62@2810L9:TextFieldDefaults.kt#uh7d8r");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(611926497, $changed, -1, "androidx.compose.material3.TextFieldDefaults.<get-filledShape> (TextFieldDefaults.kt:62)");
        }
        Shape shape = ShapesKt.toShape(FilledTextFieldTokens.INSTANCE.getContainerShape(), $composer, 6);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return shape;
    }

    /* renamed from: getMinHeight-D9Ej5fM  reason: not valid java name */
    public final float m1613getMinHeightD9Ej5fM() {
        return MinHeight;
    }

    /* renamed from: getMinWidth-D9Ej5fM  reason: not valid java name */
    public final float m1614getMinWidthD9Ej5fM() {
        return MinWidth;
    }

    /* renamed from: getUnfocusedBorderThickness-D9Ej5fM  reason: not valid java name */
    public final float m1615getUnfocusedBorderThicknessD9Ej5fM() {
        return UnfocusedBorderThickness;
    }

    /* renamed from: getFocusedBorderThickness-D9Ej5fM  reason: not valid java name */
    public final float m1612getFocusedBorderThicknessD9Ej5fM() {
        return FocusedBorderThickness;
    }

    /* JADX WARN: Removed duplicated region for block: B:81:0x00fa  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0111  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x015b  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0165  */
    /* JADX WARN: Removed duplicated region for block: B:94:? A[RETURN, SYNTHETIC] */
    @androidx.compose.material3.ExperimentalMaterial3Api
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void FilledContainerBox(final boolean r21, final boolean r22, final androidx.compose.foundation.interaction.InteractionSource r23, final androidx.compose.material3.TextFieldColors r24, androidx.compose.ui.graphics.Shape r25, androidx.compose.runtime.Composer r26, final int r27, final int r28) {
        /*
            Method dump skipped, instructions count: 388
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.TextFieldDefaults.FilledContainerBox(boolean, boolean, androidx.compose.foundation.interaction.InteractionSource, androidx.compose.material3.TextFieldColors, androidx.compose.ui.graphics.Shape, androidx.compose.runtime.Composer, int, int):void");
    }

    /* renamed from: indicatorLine-gv0btCI$default  reason: not valid java name */
    public static /* synthetic */ Modifier m1606indicatorLinegv0btCI$default(TextFieldDefaults textFieldDefaults, Modifier modifier, boolean z, boolean z2, InteractionSource interactionSource, TextFieldColors textFieldColors, float f, float f2, int i, Object obj) {
        float f3;
        float f4;
        if ((i & 16) == 0) {
            f3 = f;
        } else {
            f3 = FocusedBorderThickness;
        }
        if ((i & 32) == 0) {
            f4 = f2;
        } else {
            f4 = UnfocusedBorderThickness;
        }
        return textFieldDefaults.m1616indicatorLinegv0btCI(modifier, z, z2, interactionSource, textFieldColors, f3, f4);
    }

    @ExperimentalMaterial3Api
    /* renamed from: indicatorLine-gv0btCI  reason: not valid java name */
    public final Modifier m1616indicatorLinegv0btCI(Modifier indicatorLine, final boolean enabled, final boolean isError, final InteractionSource interactionSource, final TextFieldColors colors, final float focusedIndicatorLineThickness, final float unfocusedIndicatorLineThickness) {
        Intrinsics.checkNotNullParameter(indicatorLine, "$this$indicatorLine");
        Intrinsics.checkNotNullParameter(interactionSource, "interactionSource");
        Intrinsics.checkNotNullParameter(colors, "colors");
        return ComposedModifierKt.composed(indicatorLine, InspectableValueKt.isDebugInspectorInfoEnabled() ? new Function1<InspectorInfo, Unit>() { // from class: androidx.compose.material3.TextFieldDefaults$indicatorLine-gv0btCI$$inlined$debugInspectorInfo$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(InspectorInfo inspectorInfo) {
                invoke2(inspectorInfo);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke  reason: avoid collision after fix types in other method */
            public final void invoke2(InspectorInfo $this$null) {
                Intrinsics.checkNotNullParameter($this$null, "$this$null");
                $this$null.setName("indicatorLine");
                $this$null.getProperties().set("enabled", Boolean.valueOf(enabled));
                $this$null.getProperties().set("isError", Boolean.valueOf(isError));
                $this$null.getProperties().set("interactionSource", interactionSource);
                $this$null.getProperties().set("colors", colors);
                $this$null.getProperties().set("focusedIndicatorLineThickness", Dp.m5120boximpl(focusedIndicatorLineThickness));
                $this$null.getProperties().set("unfocusedIndicatorLineThickness", Dp.m5120boximpl(unfocusedIndicatorLineThickness));
            }
        } : InspectableValueKt.getNoInspectorInfo(), new Function3<Modifier, Composer, Integer, Modifier>() { // from class: androidx.compose.material3.TextFieldDefaults$indicatorLine$2
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(3);
            }

            @Override // kotlin.jvm.functions.Function3
            public /* bridge */ /* synthetic */ Modifier invoke(Modifier modifier, Composer composer, Integer num) {
                return invoke(modifier, composer, num.intValue());
            }

            public final Modifier invoke(Modifier composed, Composer $composer, int $changed) {
                State stroke;
                Intrinsics.checkNotNullParameter(composed, "$this$composed");
                $composer.startReplaceableGroup(-891038934);
                ComposerKt.sourceInformation($composer, "C147@6353L217:TextFieldDefaults.kt#uh7d8r");
                if (ComposerKt.isTraceInProgress()) {
                    ComposerKt.traceEventStart(-891038934, $changed, -1, "androidx.compose.material3.TextFieldDefaults.indicatorLine.<anonymous> (TextFieldDefaults.kt:146)");
                }
                stroke = TextFieldDefaultsKt.m1624animateBorderStrokeAsStateNuRrP5Q(enabled, isError, interactionSource, colors, focusedIndicatorLineThickness, unfocusedIndicatorLineThickness, $composer, 0);
                Modifier drawIndicatorLine = TextFieldKt.drawIndicatorLine(Modifier.Companion, (BorderStroke) stroke.getValue());
                if (ComposerKt.isTraceInProgress()) {
                    ComposerKt.traceEventEnd();
                }
                $composer.endReplaceableGroup();
                return drawIndicatorLine;
            }
        });
    }

    @ExperimentalMaterial3Api
    /* renamed from: OutlinedBorderContainerBox-nbWgWpA  reason: not valid java name */
    public final void m1611OutlinedBorderContainerBoxnbWgWpA(final boolean enabled, final boolean isError, final InteractionSource interactionSource, final TextFieldColors colors, Shape shape, float focusedBorderThickness, float unfocusedBorderThickness, Composer $composer, final int $changed, final int i) {
        Object obj;
        float focusedBorderThickness2;
        float f;
        Shape shape2;
        Shape shape3;
        float focusedBorderThickness3;
        float unfocusedBorderThickness2;
        int $dirty;
        State borderStroke;
        float unfocusedBorderThickness3;
        float unfocusedBorderThickness4;
        Object shape4;
        int i2;
        int i3;
        int i4;
        Intrinsics.checkNotNullParameter(interactionSource, "interactionSource");
        Intrinsics.checkNotNullParameter(colors, "colors");
        Composer $composer2 = $composer.startRestartGroup(-1998946250);
        ComposerKt.sourceInformation($composer2, "C(OutlinedBorderContainerBox)P(1,4,3!1,5,2:c#ui.unit.Dp,6:c#ui.unit.Dp)180@7782L9,184@7953L203,195@8277L16,192@8165L143:TextFieldDefaults.kt#uh7d8r");
        int $dirty2 = $changed;
        if ((i & 1) != 0) {
            $dirty2 |= 6;
        } else if (($changed & 14) == 0) {
            $dirty2 |= $composer2.changed(enabled) ? 4 : 2;
        }
        if ((i & 2) != 0) {
            $dirty2 |= 48;
        } else if (($changed & 112) == 0) {
            $dirty2 |= $composer2.changed(isError) ? 32 : 16;
        }
        if ((i & 4) != 0) {
            $dirty2 |= 384;
        } else if (($changed & 896) == 0) {
            $dirty2 |= $composer2.changed(interactionSource) ? 256 : 128;
        }
        if ((i & 8) != 0) {
            $dirty2 |= 3072;
        } else if (($changed & 7168) == 0) {
            $dirty2 |= $composer2.changed(colors) ? 2048 : 1024;
        }
        if (($changed & 57344) == 0) {
            if ((i & 16) == 0) {
                obj = shape;
                if ($composer2.changed(obj)) {
                    i4 = 16384;
                    $dirty2 |= i4;
                }
            } else {
                obj = shape;
            }
            i4 = 8192;
            $dirty2 |= i4;
        } else {
            obj = shape;
        }
        if (($changed & 458752) == 0) {
            if ((i & 32) == 0) {
                focusedBorderThickness2 = focusedBorderThickness;
                if ($composer2.changed(focusedBorderThickness2)) {
                    i3 = 131072;
                    $dirty2 |= i3;
                }
            } else {
                focusedBorderThickness2 = focusedBorderThickness;
            }
            i3 = 65536;
            $dirty2 |= i3;
        } else {
            focusedBorderThickness2 = focusedBorderThickness;
        }
        if ((3670016 & $changed) == 0) {
            if ((i & 64) == 0) {
                f = unfocusedBorderThickness;
                if ($composer2.changed(f)) {
                    i2 = 1048576;
                    $dirty2 |= i2;
                }
            } else {
                f = unfocusedBorderThickness;
            }
            i2 = 524288;
            $dirty2 |= i2;
        } else {
            f = unfocusedBorderThickness;
        }
        if ((i & 128) != 0) {
            $dirty2 |= 12582912;
        } else if ((29360128 & $changed) == 0) {
            $dirty2 |= $composer2.changed(this) ? 8388608 : 4194304;
        }
        if ((23967451 & $dirty2) == 4793490 && $composer2.getSkipping()) {
            $composer2.skipToGroupEnd();
            shape4 = obj;
            unfocusedBorderThickness4 = focusedBorderThickness2;
            unfocusedBorderThickness3 = f;
        } else {
            $composer2.startDefaults();
            if (($changed & 1) == 0 || $composer2.getDefaultsInvalid()) {
                if ((i & 16) != 0) {
                    shape2 = ShapesKt.toShape(OutlinedTextFieldTokens.INSTANCE.getContainerShape(), $composer2, 6);
                    $dirty2 &= -57345;
                } else {
                    shape2 = obj;
                }
                if ((i & 32) != 0) {
                    $dirty2 &= -458753;
                    focusedBorderThickness2 = FocusedBorderThickness;
                }
                if ((i & 64) != 0) {
                    $dirty = $dirty2 & (-3670017);
                    shape3 = shape2;
                    unfocusedBorderThickness2 = UnfocusedBorderThickness;
                    focusedBorderThickness3 = focusedBorderThickness2;
                } else {
                    shape3 = shape2;
                    focusedBorderThickness3 = focusedBorderThickness2;
                    unfocusedBorderThickness2 = f;
                    $dirty = $dirty2;
                }
            } else {
                $composer2.skipToGroupEnd();
                if ((i & 16) != 0) {
                    $dirty2 &= -57345;
                }
                if ((i & 32) != 0) {
                    $dirty2 &= -458753;
                }
                if ((i & 64) != 0) {
                    $dirty2 &= -3670017;
                }
                shape3 = obj;
                focusedBorderThickness3 = focusedBorderThickness2;
                unfocusedBorderThickness2 = f;
                $dirty = $dirty2;
            }
            $composer2.endDefaults();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(-1998946250, $dirty, -1, "androidx.compose.material3.TextFieldDefaults.OutlinedBorderContainerBox (TextFieldDefaults.kt:175)");
            }
            Shape shape5 = shape3;
            borderStroke = TextFieldDefaultsKt.m1624animateBorderStrokeAsStateNuRrP5Q(enabled, isError, interactionSource, colors, focusedBorderThickness3, unfocusedBorderThickness2, $composer2, ($dirty & 14) | ($dirty & 112) | ($dirty & 896) | ($dirty & 7168) | (($dirty >> 3) & 57344) | (($dirty >> 3) & 458752));
            BoxKt.Box(BackgroundKt.m150backgroundbw27NRU(BorderKt.border(Modifier.Companion, (BorderStroke) borderStroke.getValue(), shape5), colors.containerColor$material3_release($composer2, ($dirty >> 9) & 14).getValue().m2616unboximpl(), shape5), $composer2, 0);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            unfocusedBorderThickness3 = unfocusedBorderThickness2;
            unfocusedBorderThickness4 = focusedBorderThickness3;
            shape4 = shape5;
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Shape shape6 = shape4;
        final float f2 = unfocusedBorderThickness4;
        final float f3 = unfocusedBorderThickness3;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material3.TextFieldDefaults$OutlinedBorderContainerBox$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
                invoke(composer, num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(Composer composer, int i5) {
                TextFieldDefaults.this.m1611OutlinedBorderContainerBoxnbWgWpA(enabled, isError, interactionSource, colors, shape6, f2, f3, composer, $changed | 1, i);
            }
        });
    }

    /* renamed from: textFieldWithLabelPadding-a9UjIt4$default  reason: not valid java name */
    public static /* synthetic */ PaddingValues m1609textFieldWithLabelPaddinga9UjIt4$default(TextFieldDefaults textFieldDefaults, float f, float f2, float f3, float f4, int i, Object obj) {
        if ((i & 1) != 0) {
            f = TextFieldImplKt.getTextFieldPadding();
        }
        if ((i & 2) != 0) {
            f2 = TextFieldImplKt.getTextFieldPadding();
        }
        if ((i & 4) != 0) {
            f3 = TextFieldKt.getFirstBaselineOffset();
        }
        if ((i & 8) != 0) {
            f4 = TextFieldKt.getTextFieldBottomPadding();
        }
        return textFieldDefaults.m1621textFieldWithLabelPaddinga9UjIt4(f, f2, f3, f4);
    }

    @ExperimentalMaterial3Api
    /* renamed from: textFieldWithLabelPadding-a9UjIt4  reason: not valid java name */
    public final PaddingValues m1621textFieldWithLabelPaddinga9UjIt4(float start, float end, float top, float bottom) {
        return PaddingKt.m410PaddingValuesa9UjIt4(start, top, end, bottom);
    }

    /* renamed from: textFieldWithoutLabelPadding-a9UjIt4$default  reason: not valid java name */
    public static /* synthetic */ PaddingValues m1610textFieldWithoutLabelPaddinga9UjIt4$default(TextFieldDefaults textFieldDefaults, float f, float f2, float f3, float f4, int i, Object obj) {
        if ((i & 1) != 0) {
            f = TextFieldImplKt.getTextFieldPadding();
        }
        if ((i & 2) != 0) {
            f2 = TextFieldImplKt.getTextFieldPadding();
        }
        if ((i & 4) != 0) {
            f3 = TextFieldImplKt.getTextFieldPadding();
        }
        if ((i & 8) != 0) {
            f4 = TextFieldImplKt.getTextFieldPadding();
        }
        return textFieldDefaults.m1622textFieldWithoutLabelPaddinga9UjIt4(f, f2, f3, f4);
    }

    @ExperimentalMaterial3Api
    /* renamed from: textFieldWithoutLabelPadding-a9UjIt4  reason: not valid java name */
    public final PaddingValues m1622textFieldWithoutLabelPaddinga9UjIt4(float start, float top, float end, float bottom) {
        return PaddingKt.m410PaddingValuesa9UjIt4(start, top, end, bottom);
    }

    /* renamed from: outlinedTextFieldPadding-a9UjIt4$default  reason: not valid java name */
    public static /* synthetic */ PaddingValues m1607outlinedTextFieldPaddinga9UjIt4$default(TextFieldDefaults textFieldDefaults, float f, float f2, float f3, float f4, int i, Object obj) {
        if ((i & 1) != 0) {
            f = TextFieldImplKt.getTextFieldPadding();
        }
        if ((i & 2) != 0) {
            f2 = TextFieldImplKt.getTextFieldPadding();
        }
        if ((i & 4) != 0) {
            f3 = TextFieldImplKt.getTextFieldPadding();
        }
        if ((i & 8) != 0) {
            f4 = TextFieldImplKt.getTextFieldPadding();
        }
        return textFieldDefaults.m1618outlinedTextFieldPaddinga9UjIt4(f, f2, f3, f4);
    }

    @ExperimentalMaterial3Api
    /* renamed from: outlinedTextFieldPadding-a9UjIt4  reason: not valid java name */
    public final PaddingValues m1618outlinedTextFieldPaddinga9UjIt4(float start, float top, float end, float bottom) {
        return PaddingKt.m410PaddingValuesa9UjIt4(start, top, end, bottom);
    }

    /* renamed from: supportingTextPadding-a9UjIt4$material3_release$default  reason: not valid java name */
    public static /* synthetic */ PaddingValues m1608supportingTextPaddinga9UjIt4$material3_release$default(TextFieldDefaults textFieldDefaults, float f, float f2, float f3, float f4, int i, Object obj) {
        if ((i & 1) != 0) {
            f = TextFieldImplKt.getTextFieldPadding();
        }
        if ((i & 2) != 0) {
            f2 = TextFieldImplKt.getSupportingTopPadding();
        }
        if ((i & 4) != 0) {
            f3 = TextFieldImplKt.getTextFieldPadding();
        }
        if ((i & 8) != 0) {
            f4 = Dp.m5122constructorimpl(0);
        }
        return textFieldDefaults.m1619supportingTextPaddinga9UjIt4$material3_release(f, f2, f3, f4);
    }

    @ExperimentalMaterial3Api
    /* renamed from: supportingTextPadding-a9UjIt4$material3_release  reason: not valid java name */
    public final PaddingValues m1619supportingTextPaddinga9UjIt4$material3_release(float start, float top, float end, float bottom) {
        return PaddingKt.m410PaddingValuesa9UjIt4(start, top, end, bottom);
    }

    @ExperimentalMaterial3Api
    /* renamed from: textFieldColors-l59Burw  reason: not valid java name */
    public final TextFieldColors m1620textFieldColorsl59Burw(long textColor, long disabledTextColor, long containerColor, long cursorColor, long errorCursorColor, TextSelectionColors selectionColors, long focusedIndicatorColor, long unfocusedIndicatorColor, long disabledIndicatorColor, long errorIndicatorColor, long focusedLeadingIconColor, long unfocusedLeadingIconColor, long disabledLeadingIconColor, long errorLeadingIconColor, long focusedTrailingIconColor, long unfocusedTrailingIconColor, long disabledTrailingIconColor, long errorTrailingIconColor, long focusedLabelColor, long unfocusedLabelColor, long disabledLabelColor, long errorLabelColor, long placeholderColor, long disabledPlaceholderColor, long focusedSupportingTextColor, long unfocusedSupportingTextColor, long disabledSupportingTextColor, long errorSupportingTextColor, Composer $composer, int $changed, int $changed1, int $changed2, int i) {
        long disabledTextColor2;
        long containerColor2;
        long cursorColor2;
        long errorCursorColor2;
        TextSelectionColors selectionColors2;
        long focusedIndicatorColor2;
        long unfocusedIndicatorColor2;
        long disabledIndicatorColor2;
        long errorIndicatorColor2;
        long focusedLeadingIconColor2;
        long unfocusedLeadingIconColor2;
        long disabledLeadingIconColor2;
        long errorLeadingIconColor2;
        long focusedTrailingIconColor2;
        long unfocusedTrailingIconColor2;
        long disabledTrailingIconColor2;
        long errorTrailingIconColor2;
        long focusedLabelColor2;
        long unfocusedLabelColor2;
        long disabledLabelColor2;
        long errorLabelColor2;
        long placeholderColor2;
        long disabledPlaceholderColor2;
        long focusedSupportingTextColor2;
        long unfocusedSupportingTextColor2;
        long disabledSupportingTextColor2;
        long errorSupportingTextColor2;
        long m2604copywmQWz5c;
        long m2604copywmQWz5c2;
        long m2604copywmQWz5c3;
        long m2604copywmQWz5c4;
        long m2604copywmQWz5c5;
        long m2604copywmQWz5c6;
        long m2604copywmQWz5c7;
        $composer.startReplaceableGroup(-128842621);
        ComposerKt.sourceInformation($composer, "C(textFieldColors)P(22:c#ui.graphics.Color,7:c#ui.graphics.Color,0:c#ui.graphics.Color,1:c#ui.graphics.Color,9:c#ui.graphics.Color,21,15:c#ui.graphics.Color,23:c#ui.graphics.Color,2:c#ui.graphics.Color,10:c#ui.graphics.Color,17:c#ui.graphics.Color,25:c#ui.graphics.Color,4:c#ui.graphics.Color,12:c#ui.graphics.Color,19:c#ui.graphics.Color,27:c#ui.graphics.Color,8:c#ui.graphics.Color,14:c#ui.graphics.Color,16:c#ui.graphics.Color,24:c#ui.graphics.Color,3:c#ui.graphics.Color,11:c#ui.graphics.Color,20:c#ui.graphics.Color,5:c#ui.graphics.Color,18:c#ui.graphics.Color,26:c#ui.graphics.Color,6:c#ui.graphics.Color,13:c#ui.graphics.Color)293@13317L9,294@13404L9,296@13554L9,297@13627L9,298@13715L9,299@13798L7,300@13894L9,301@13989L9,302@14091L9,304@14267L9,305@14363L9,306@14456L9,307@14556L9,309@14726L9,310@14824L9,311@14919L9,312@15021L9,314@15194L9,315@15278L9,316@15359L9,317@15447L9,319@15599L9,320@15688L9,321@15782L9,323@15950L9,324@16045L9,325@16147L9,327@16318L9:TextFieldDefaults.kt#uh7d8r");
        long textColor2 = (i & 1) != 0 ? ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getInputColor(), $composer, 6) : textColor;
        if ((i & 2) != 0) {
            m2604copywmQWz5c7 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getDisabledInputColor(), $composer, 6)) : 0.0f);
            disabledTextColor2 = m2604copywmQWz5c7;
        } else {
            disabledTextColor2 = disabledTextColor;
        }
        if ((i & 4) == 0) {
            containerColor2 = containerColor;
        } else {
            containerColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getContainerColor(), $composer, 6);
        }
        if ((i & 8) == 0) {
            cursorColor2 = cursorColor;
        } else {
            cursorColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getCaretColor(), $composer, 6);
        }
        if ((i & 16) == 0) {
            errorCursorColor2 = errorCursorColor;
        } else {
            errorCursorColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getErrorFocusCaretColor(), $composer, 6);
        }
        if ((i & 32) == 0) {
            selectionColors2 = selectionColors;
        } else {
            ComposerKt.sourceInformationMarkerStart($composer, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume = $composer.consume(TextSelectionColorsKt.getLocalTextSelectionColors());
            ComposerKt.sourceInformationMarkerEnd($composer);
            selectionColors2 = (TextSelectionColors) consume;
        }
        if ((i & 64) != 0) {
            focusedIndicatorColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getFocusActiveIndicatorColor(), $composer, 6);
        } else {
            focusedIndicatorColor2 = focusedIndicatorColor;
        }
        if ((i & 128) == 0) {
            unfocusedIndicatorColor2 = unfocusedIndicatorColor;
        } else {
            unfocusedIndicatorColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getActiveIndicatorColor(), $composer, 6);
        }
        if ((i & 256) != 0) {
            m2604copywmQWz5c6 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getDisabledActiveIndicatorColor(), $composer, 6)) : 0.0f);
            disabledIndicatorColor2 = m2604copywmQWz5c6;
        } else {
            disabledIndicatorColor2 = disabledIndicatorColor;
        }
        if ((i & 512) == 0) {
            errorIndicatorColor2 = errorIndicatorColor;
        } else {
            errorIndicatorColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getErrorActiveIndicatorColor(), $composer, 6);
        }
        if ((i & 1024) == 0) {
            focusedLeadingIconColor2 = focusedLeadingIconColor;
        } else {
            focusedLeadingIconColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getFocusLeadingIconColor(), $composer, 6);
        }
        if ((i & 2048) == 0) {
            unfocusedLeadingIconColor2 = unfocusedLeadingIconColor;
        } else {
            unfocusedLeadingIconColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getLeadingIconColor(), $composer, 6);
        }
        if ((i & 4096) != 0) {
            m2604copywmQWz5c5 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getDisabledLeadingIconColor(), $composer, 6)) : 0.0f);
            disabledLeadingIconColor2 = m2604copywmQWz5c5;
        } else {
            disabledLeadingIconColor2 = disabledLeadingIconColor;
        }
        if ((i & 8192) == 0) {
            errorLeadingIconColor2 = errorLeadingIconColor;
        } else {
            errorLeadingIconColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getErrorLeadingIconColor(), $composer, 6);
        }
        if ((i & 16384) == 0) {
            focusedTrailingIconColor2 = focusedTrailingIconColor;
        } else {
            focusedTrailingIconColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getFocusTrailingIconColor(), $composer, 6);
        }
        if ((32768 & i) == 0) {
            unfocusedTrailingIconColor2 = unfocusedTrailingIconColor;
        } else {
            unfocusedTrailingIconColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getTrailingIconColor(), $composer, 6);
        }
        if ((65536 & i) != 0) {
            m2604copywmQWz5c4 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getDisabledTrailingIconColor(), $composer, 6)) : 0.0f);
            disabledTrailingIconColor2 = m2604copywmQWz5c4;
        } else {
            disabledTrailingIconColor2 = disabledTrailingIconColor;
        }
        if ((131072 & i) == 0) {
            errorTrailingIconColor2 = errorTrailingIconColor;
        } else {
            errorTrailingIconColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getErrorTrailingIconColor(), $composer, 6);
        }
        if ((262144 & i) == 0) {
            focusedLabelColor2 = focusedLabelColor;
        } else {
            focusedLabelColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getFocusLabelColor(), $composer, 6);
        }
        if ((524288 & i) == 0) {
            unfocusedLabelColor2 = unfocusedLabelColor;
        } else {
            unfocusedLabelColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getLabelColor(), $composer, 6);
        }
        if ((1048576 & i) != 0) {
            m2604copywmQWz5c3 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getDisabledLabelColor(), $composer, 6)) : 0.0f);
            disabledLabelColor2 = m2604copywmQWz5c3;
        } else {
            disabledLabelColor2 = disabledLabelColor;
        }
        if ((2097152 & i) == 0) {
            errorLabelColor2 = errorLabelColor;
        } else {
            errorLabelColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getErrorLabelColor(), $composer, 6);
        }
        if ((4194304 & i) == 0) {
            placeholderColor2 = placeholderColor;
        } else {
            placeholderColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getInputPlaceholderColor(), $composer, 6);
        }
        if ((8388608 & i) != 0) {
            m2604copywmQWz5c2 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getDisabledInputColor(), $composer, 6)) : 0.0f);
            disabledPlaceholderColor2 = m2604copywmQWz5c2;
        } else {
            disabledPlaceholderColor2 = disabledPlaceholderColor;
        }
        if ((16777216 & i) == 0) {
            focusedSupportingTextColor2 = focusedSupportingTextColor;
        } else {
            focusedSupportingTextColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getFocusSupportingColor(), $composer, 6);
        }
        if ((33554432 & i) == 0) {
            unfocusedSupportingTextColor2 = unfocusedSupportingTextColor;
        } else {
            unfocusedSupportingTextColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getSupportingColor(), $composer, 6);
        }
        if ((67108864 & i) != 0) {
            m2604copywmQWz5c = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getDisabledSupportingColor(), $composer, 6)) : 0.0f);
            disabledSupportingTextColor2 = m2604copywmQWz5c;
        } else {
            disabledSupportingTextColor2 = disabledSupportingTextColor;
        }
        if ((i & 134217728) == 0) {
            errorSupportingTextColor2 = errorSupportingTextColor;
        } else {
            errorSupportingTextColor2 = ColorSchemeKt.toColor(FilledTextFieldTokens.INSTANCE.getErrorSupportingColor(), $composer, 6);
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-128842621, $changed, $changed1, "androidx.compose.material3.TextFieldDefaults.textFieldColors (TextFieldDefaults.kt:292)");
        }
        TextFieldColors textFieldColors = new TextFieldColors(textColor2, disabledTextColor2, containerColor2, cursorColor2, errorCursorColor2, selectionColors2, focusedIndicatorColor2, unfocusedIndicatorColor2, errorIndicatorColor2, disabledIndicatorColor2, focusedLeadingIconColor2, unfocusedLeadingIconColor2, disabledLeadingIconColor2, errorLeadingIconColor2, focusedTrailingIconColor2, unfocusedTrailingIconColor2, disabledTrailingIconColor2, errorTrailingIconColor2, focusedLabelColor2, unfocusedLabelColor2, disabledLabelColor2, errorLabelColor2, placeholderColor2, disabledPlaceholderColor2, focusedSupportingTextColor2, unfocusedSupportingTextColor2, disabledSupportingTextColor2, errorSupportingTextColor2, null);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return textFieldColors;
    }

    @ExperimentalMaterial3Api
    /* renamed from: outlinedTextFieldColors-l59Burw  reason: not valid java name */
    public final TextFieldColors m1617outlinedTextFieldColorsl59Burw(long textColor, long disabledTextColor, long containerColor, long cursorColor, long errorCursorColor, TextSelectionColors selectionColors, long focusedBorderColor, long unfocusedBorderColor, long disabledBorderColor, long errorBorderColor, long focusedLeadingIconColor, long unfocusedLeadingIconColor, long disabledLeadingIconColor, long errorLeadingIconColor, long focusedTrailingIconColor, long unfocusedTrailingIconColor, long disabledTrailingIconColor, long errorTrailingIconColor, long focusedLabelColor, long unfocusedLabelColor, long disabledLabelColor, long errorLabelColor, long placeholderColor, long disabledPlaceholderColor, long focusedSupportingTextColor, long unfocusedSupportingTextColor, long disabledSupportingTextColor, long errorSupportingTextColor, Composer $composer, int $changed, int $changed1, int $changed2, int i) {
        long disabledTextColor2;
        long containerColor2;
        long cursorColor2;
        long errorCursorColor2;
        TextSelectionColors selectionColors2;
        long focusedBorderColor2;
        long unfocusedBorderColor2;
        long disabledBorderColor2;
        long errorBorderColor2;
        long focusedLeadingIconColor2;
        long unfocusedLeadingIconColor2;
        long disabledLeadingIconColor2;
        long errorLeadingIconColor2;
        long focusedTrailingIconColor2;
        long unfocusedTrailingIconColor2;
        long disabledTrailingIconColor2;
        long errorTrailingIconColor2;
        long focusedLabelColor2;
        long unfocusedLabelColor2;
        long disabledLabelColor2;
        long errorLabelColor2;
        long placeholderColor2;
        long disabledPlaceholderColor2;
        long focusedSupportingTextColor2;
        long unfocusedSupportingTextColor2;
        long disabledSupportingTextColor2;
        long errorSupportingTextColor2;
        long m2604copywmQWz5c;
        long m2604copywmQWz5c2;
        long m2604copywmQWz5c3;
        long m2604copywmQWz5c4;
        long m2604copywmQWz5c5;
        long m2604copywmQWz5c6;
        long m2604copywmQWz5c7;
        $composer.startReplaceableGroup(-1654658683);
        ComposerKt.sourceInformation($composer, "C(outlinedTextFieldColors)P(22:c#ui.graphics.Color,7:c#ui.graphics.Color,0:c#ui.graphics.Color,1:c#ui.graphics.Color,10:c#ui.graphics.Color,21,15:c#ui.graphics.Color,23:c#ui.graphics.Color,2:c#ui.graphics.Color,9:c#ui.graphics.Color,17:c#ui.graphics.Color,25:c#ui.graphics.Color,4:c#ui.graphics.Color,12:c#ui.graphics.Color,19:c#ui.graphics.Color,27:c#ui.graphics.Color,8:c#ui.graphics.Color,14:c#ui.graphics.Color,16:c#ui.graphics.Color,24:c#ui.graphics.Color,3:c#ui.graphics.Color,11:c#ui.graphics.Color,20:c#ui.graphics.Color,5:c#ui.graphics.Color,18:c#ui.graphics.Color,26:c#ui.graphics.Color,6:c#ui.graphics.Color,13:c#ui.graphics.Color)400@20949L9,401@21038L9,404@21236L9,405@21326L9,406@21409L7,407@21496L9,408@21582L9,409@21675L9,411@21836L9,412@21934L9,413@22029L9,414@22131L9,416@22305L9,417@22405L9,418@22502L9,420@22619L9,421@22783L9,422@22869L9,423@22952L9,424@23042L9,426@23198L9,427@23289L9,428@23385L9,430@23557L9,431@23654L9,433@23771L9,434@23933L9:TextFieldDefaults.kt#uh7d8r");
        long textColor2 = (i & 1) != 0 ? ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getInputColor(), $composer, 6) : textColor;
        if ((i & 2) != 0) {
            m2604copywmQWz5c7 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getDisabledInputColor(), $composer, 6)) : 0.0f);
            disabledTextColor2 = m2604copywmQWz5c7;
        } else {
            disabledTextColor2 = disabledTextColor;
        }
        if ((i & 4) == 0) {
            containerColor2 = containerColor;
        } else {
            containerColor2 = Color.Companion.m2641getTransparent0d7_KjU();
        }
        if ((i & 8) == 0) {
            cursorColor2 = cursorColor;
        } else {
            cursorColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getCaretColor(), $composer, 6);
        }
        if ((i & 16) == 0) {
            errorCursorColor2 = errorCursorColor;
        } else {
            errorCursorColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getErrorFocusCaretColor(), $composer, 6);
        }
        if ((i & 32) == 0) {
            selectionColors2 = selectionColors;
        } else {
            ComposerKt.sourceInformationMarkerStart($composer, 2023513938, "C:CompositionLocal.kt#9igjgp");
            Object consume = $composer.consume(TextSelectionColorsKt.getLocalTextSelectionColors());
            ComposerKt.sourceInformationMarkerEnd($composer);
            selectionColors2 = (TextSelectionColors) consume;
        }
        if ((i & 64) != 0) {
            focusedBorderColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getFocusOutlineColor(), $composer, 6);
        } else {
            focusedBorderColor2 = focusedBorderColor;
        }
        if ((i & 128) == 0) {
            unfocusedBorderColor2 = unfocusedBorderColor;
        } else {
            unfocusedBorderColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getOutlineColor(), $composer, 6);
        }
        if ((i & 256) != 0) {
            m2604copywmQWz5c6 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.12f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getDisabledOutlineColor(), $composer, 6)) : 0.0f);
            disabledBorderColor2 = m2604copywmQWz5c6;
        } else {
            disabledBorderColor2 = disabledBorderColor;
        }
        if ((i & 512) == 0) {
            errorBorderColor2 = errorBorderColor;
        } else {
            errorBorderColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getErrorOutlineColor(), $composer, 6);
        }
        if ((i & 1024) == 0) {
            focusedLeadingIconColor2 = focusedLeadingIconColor;
        } else {
            focusedLeadingIconColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getFocusLeadingIconColor(), $composer, 6);
        }
        if ((i & 2048) == 0) {
            unfocusedLeadingIconColor2 = unfocusedLeadingIconColor;
        } else {
            unfocusedLeadingIconColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getLeadingIconColor(), $composer, 6);
        }
        if ((i & 4096) != 0) {
            m2604copywmQWz5c5 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getDisabledLeadingIconColor(), $composer, 6)) : 0.0f);
            disabledLeadingIconColor2 = m2604copywmQWz5c5;
        } else {
            disabledLeadingIconColor2 = disabledLeadingIconColor;
        }
        if ((i & 8192) == 0) {
            errorLeadingIconColor2 = errorLeadingIconColor;
        } else {
            errorLeadingIconColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getErrorLeadingIconColor(), $composer, 6);
        }
        if ((i & 16384) == 0) {
            focusedTrailingIconColor2 = focusedTrailingIconColor;
        } else {
            focusedTrailingIconColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getFocusTrailingIconColor(), $composer, 6);
        }
        if ((32768 & i) == 0) {
            unfocusedTrailingIconColor2 = unfocusedTrailingIconColor;
        } else {
            unfocusedTrailingIconColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getTrailingIconColor(), $composer, 6);
        }
        if ((65536 & i) != 0) {
            m2604copywmQWz5c4 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getDisabledTrailingIconColor(), $composer, 6)) : 0.0f);
            disabledTrailingIconColor2 = m2604copywmQWz5c4;
        } else {
            disabledTrailingIconColor2 = disabledTrailingIconColor;
        }
        if ((131072 & i) == 0) {
            errorTrailingIconColor2 = errorTrailingIconColor;
        } else {
            errorTrailingIconColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getErrorTrailingIconColor(), $composer, 6);
        }
        if ((262144 & i) == 0) {
            focusedLabelColor2 = focusedLabelColor;
        } else {
            focusedLabelColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getFocusLabelColor(), $composer, 6);
        }
        if ((524288 & i) == 0) {
            unfocusedLabelColor2 = unfocusedLabelColor;
        } else {
            unfocusedLabelColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getLabelColor(), $composer, 6);
        }
        if ((1048576 & i) != 0) {
            m2604copywmQWz5c3 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getDisabledLabelColor(), $composer, 6)) : 0.0f);
            disabledLabelColor2 = m2604copywmQWz5c3;
        } else {
            disabledLabelColor2 = disabledLabelColor;
        }
        if ((2097152 & i) == 0) {
            errorLabelColor2 = errorLabelColor;
        } else {
            errorLabelColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getErrorLabelColor(), $composer, 6);
        }
        if ((4194304 & i) == 0) {
            placeholderColor2 = placeholderColor;
        } else {
            placeholderColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getInputPlaceholderColor(), $composer, 6);
        }
        if ((8388608 & i) != 0) {
            m2604copywmQWz5c2 = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getDisabledInputColor(), $composer, 6)) : 0.0f);
            disabledPlaceholderColor2 = m2604copywmQWz5c2;
        } else {
            disabledPlaceholderColor2 = disabledPlaceholderColor;
        }
        if ((16777216 & i) == 0) {
            focusedSupportingTextColor2 = focusedSupportingTextColor;
        } else {
            focusedSupportingTextColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getFocusSupportingColor(), $composer, 6);
        }
        if ((33554432 & i) == 0) {
            unfocusedSupportingTextColor2 = unfocusedSupportingTextColor;
        } else {
            unfocusedSupportingTextColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getSupportingColor(), $composer, 6);
        }
        if ((67108864 & i) != 0) {
            m2604copywmQWz5c = Color.m2604copywmQWz5c(r7, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r7) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r7) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r7) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getDisabledSupportingColor(), $composer, 6)) : 0.0f);
            disabledSupportingTextColor2 = m2604copywmQWz5c;
        } else {
            disabledSupportingTextColor2 = disabledSupportingTextColor;
        }
        if ((i & 134217728) == 0) {
            errorSupportingTextColor2 = errorSupportingTextColor;
        } else {
            errorSupportingTextColor2 = ColorSchemeKt.toColor(OutlinedTextFieldTokens.INSTANCE.getErrorSupportingColor(), $composer, 6);
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-1654658683, $changed, $changed1, "androidx.compose.material3.TextFieldDefaults.outlinedTextFieldColors (TextFieldDefaults.kt:399)");
        }
        TextFieldColors textFieldColors = new TextFieldColors(textColor2, disabledTextColor2, containerColor2, cursorColor2, errorCursorColor2, selectionColors2, focusedBorderColor2, unfocusedBorderColor2, errorBorderColor2, disabledBorderColor2, focusedLeadingIconColor2, unfocusedLeadingIconColor2, disabledLeadingIconColor2, errorLeadingIconColor2, focusedTrailingIconColor2, unfocusedTrailingIconColor2, disabledTrailingIconColor2, errorTrailingIconColor2, focusedLabelColor2, unfocusedLabelColor2, disabledLabelColor2, errorLabelColor2, placeholderColor2, disabledPlaceholderColor2, focusedSupportingTextColor2, unfocusedSupportingTextColor2, disabledSupportingTextColor2, errorSupportingTextColor2, null);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return textFieldColors;
    }

    /* JADX WARN: Code restructure failed: missing block: B:135:0x01c0, code lost:
        if (r7.changed(r88) == false) goto L44;
     */
    /* JADX WARN: Code restructure failed: missing block: B:146:0x01da, code lost:
        if (r7.changed(r89) == false) goto L52;
     */
    /* JADX WARN: Code restructure failed: missing block: B:157:0x01f4, code lost:
        if (r7.changed(r12) != false) goto L61;
     */
    /* JADX WARN: Removed duplicated region for block: B:100:0x015c  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0178  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x017d  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x0197  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x019c  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:140:0x01ca  */
    /* JADX WARN: Removed duplicated region for block: B:143:0x01d0  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x01e4  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x01ea  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x01fe  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x0207  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x020e  */
    /* JADX WARN: Removed duplicated region for block: B:176:0x0228  */
    /* JADX WARN: Removed duplicated region for block: B:178:0x022d  */
    /* JADX WARN: Removed duplicated region for block: B:186:0x0249  */
    /* JADX WARN: Removed duplicated region for block: B:194:0x027f  */
    /* JADX WARN: Removed duplicated region for block: B:208:0x02d5  */
    /* JADX WARN: Removed duplicated region for block: B:209:0x02d9  */
    /* JADX WARN: Removed duplicated region for block: B:211:0x02dd  */
    /* JADX WARN: Removed duplicated region for block: B:212:0x02e1  */
    /* JADX WARN: Removed duplicated region for block: B:214:0x02e5  */
    /* JADX WARN: Removed duplicated region for block: B:215:0x02e9  */
    /* JADX WARN: Removed duplicated region for block: B:217:0x02ed  */
    /* JADX WARN: Removed duplicated region for block: B:218:0x02f1  */
    /* JADX WARN: Removed duplicated region for block: B:220:0x02f5  */
    /* JADX WARN: Removed duplicated region for block: B:221:0x02f9  */
    /* JADX WARN: Removed duplicated region for block: B:223:0x02fd  */
    /* JADX WARN: Removed duplicated region for block: B:224:0x0301  */
    /* JADX WARN: Removed duplicated region for block: B:227:0x0307  */
    /* JADX WARN: Removed duplicated region for block: B:228:0x0315  */
    /* JADX WARN: Removed duplicated region for block: B:231:0x031c  */
    /* JADX WARN: Removed duplicated region for block: B:232:0x037e  */
    /* JADX WARN: Removed duplicated region for block: B:235:0x038b  */
    /* JADX WARN: Removed duplicated region for block: B:239:0x03c6  */
    /* JADX WARN: Removed duplicated region for block: B:241:0x03ca  */
    /* JADX WARN: Removed duplicated region for block: B:242:0x03f3  */
    /* JADX WARN: Removed duplicated region for block: B:245:0x0405  */
    /* JADX WARN: Removed duplicated region for block: B:246:0x0410  */
    /* JADX WARN: Removed duplicated region for block: B:249:0x04a1  */
    /* JADX WARN: Removed duplicated region for block: B:254:0x04b3  */
    /* JADX WARN: Removed duplicated region for block: B:256:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00f5  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x010f  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0116  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0132  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x0139  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0155  */
    @androidx.compose.material3.ExperimentalMaterial3Api
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void TextFieldDecorationBox(final java.lang.String r76, final kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r77, final boolean r78, final boolean r79, final androidx.compose.ui.text.input.VisualTransformation r80, final androidx.compose.foundation.interaction.InteractionSource r81, boolean r82, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r83, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r84, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r85, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r86, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r87, androidx.compose.ui.graphics.Shape r88, androidx.compose.material3.TextFieldColors r89, androidx.compose.foundation.layout.PaddingValues r90, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r91, androidx.compose.runtime.Composer r92, final int r93, final int r94, final int r95) {
        /*
            Method dump skipped, instructions count: 1262
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.TextFieldDefaults.TextFieldDecorationBox(java.lang.String, kotlin.jvm.functions.Function2, boolean, boolean, androidx.compose.ui.text.input.VisualTransformation, androidx.compose.foundation.interaction.InteractionSource, boolean, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function2, androidx.compose.ui.graphics.Shape, androidx.compose.material3.TextFieldColors, androidx.compose.foundation.layout.PaddingValues, kotlin.jvm.functions.Function2, androidx.compose.runtime.Composer, int, int, int):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:145:0x01d4, code lost:
        if (r8.changed(r95) == false) goto L52;
     */
    /* JADX WARN: Removed duplicated region for block: B:100:0x0156  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0172  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0177  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x0191  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x0196  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x01b0  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x01c4  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01ca  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x01de  */
    /* JADX WARN: Removed duplicated region for block: B:153:0x01e4  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x01e9  */
    /* JADX WARN: Removed duplicated region for block: B:164:0x0204  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x020b  */
    /* JADX WARN: Removed duplicated region for block: B:194:0x028c  */
    /* JADX WARN: Removed duplicated region for block: B:195:0x028e  */
    /* JADX WARN: Removed duplicated region for block: B:197:0x0292  */
    /* JADX WARN: Removed duplicated region for block: B:198:0x0294  */
    /* JADX WARN: Removed duplicated region for block: B:200:0x0298  */
    /* JADX WARN: Removed duplicated region for block: B:201:0x029a  */
    /* JADX WARN: Removed duplicated region for block: B:203:0x029e  */
    /* JADX WARN: Removed duplicated region for block: B:204:0x02a0  */
    /* JADX WARN: Removed duplicated region for block: B:206:0x02a4  */
    /* JADX WARN: Removed duplicated region for block: B:207:0x02a6  */
    /* JADX WARN: Removed duplicated region for block: B:209:0x02aa  */
    /* JADX WARN: Removed duplicated region for block: B:210:0x02ac  */
    /* JADX WARN: Removed duplicated region for block: B:213:0x02b2  */
    /* JADX WARN: Removed duplicated region for block: B:214:0x0300  */
    /* JADX WARN: Removed duplicated region for block: B:217:0x0308  */
    /* JADX WARN: Removed duplicated region for block: B:218:0x0328  */
    /* JADX WARN: Removed duplicated region for block: B:220:0x032c  */
    /* JADX WARN: Removed duplicated region for block: B:221:0x0362  */
    /* JADX WARN: Removed duplicated region for block: B:224:0x0383  */
    /* JADX WARN: Removed duplicated region for block: B:227:0x041b  */
    /* JADX WARN: Removed duplicated region for block: B:231:0x0425  */
    /* JADX WARN: Removed duplicated region for block: B:233:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00ed  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0109  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0110  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x012e  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x0135  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x014f  */
    @androidx.compose.material3.ExperimentalMaterial3Api
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void OutlinedTextFieldDecorationBox(final java.lang.String r82, final kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r83, final boolean r84, final boolean r85, final androidx.compose.ui.text.input.VisualTransformation r86, final androidx.compose.foundation.interaction.InteractionSource r87, boolean r88, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r89, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r90, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r91, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r92, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r93, androidx.compose.material3.TextFieldColors r94, androidx.compose.foundation.layout.PaddingValues r95, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r96, androidx.compose.runtime.Composer r97, final int r98, final int r99, final int r100) {
        /*
            Method dump skipped, instructions count: 1118
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.TextFieldDefaults.OutlinedTextFieldDecorationBox(java.lang.String, kotlin.jvm.functions.Function2, boolean, boolean, androidx.compose.ui.text.input.VisualTransformation, androidx.compose.foundation.interaction.InteractionSource, boolean, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function2, androidx.compose.material3.TextFieldColors, androidx.compose.foundation.layout.PaddingValues, kotlin.jvm.functions.Function2, androidx.compose.runtime.Composer, int, int, int):void");
    }
}
