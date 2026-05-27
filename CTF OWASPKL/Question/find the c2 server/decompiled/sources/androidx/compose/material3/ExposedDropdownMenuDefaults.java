package androidx.compose.material3;

import androidx.compose.foundation.layout.PaddingKt;
import androidx.compose.foundation.layout.PaddingValues;
import androidx.compose.foundation.text.selection.TextSelectionColors;
import androidx.compose.foundation.text.selection.TextSelectionColorsKt;
import androidx.compose.material.icons.Icons;
import androidx.compose.material.icons.filled.ArrowDropDownKt;
import androidx.compose.material3.tokens.FilledAutocompleteTokens;
import androidx.compose.material3.tokens.OutlinedAutocompleteTokens;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.ScopeUpdateScope;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.draw.RotateKt;
import androidx.compose.ui.graphics.Color;
import androidx.compose.ui.unit.Dp;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
/* compiled from: ExposedDropdownMenu.kt */
@ExperimentalMaterial3Api
@Metadata(d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u001b\bÇ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J\u0015\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\nH\u0007¢\u0006\u0002\u0010\u000bJ\u0085\u0002\u0010\f\u001a\u00020\r2\b\b\u0002\u0010\u000e\u001a\u00020\u000f2\b\b\u0002\u0010\u0010\u001a\u00020\u000f2\b\b\u0002\u0010\u0011\u001a\u00020\u000f2\b\b\u0002\u0010\u0012\u001a\u00020\u000f2\b\b\u0002\u0010\u0013\u001a\u00020\u000f2\b\b\u0002\u0010\u0014\u001a\u00020\u00152\b\b\u0002\u0010\u0016\u001a\u00020\u000f2\b\b\u0002\u0010\u0017\u001a\u00020\u000f2\b\b\u0002\u0010\u0018\u001a\u00020\u000f2\b\b\u0002\u0010\u0019\u001a\u00020\u000f2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f2\b\b\u0002\u0010\u001c\u001a\u00020\u000f2\b\b\u0002\u0010\u001d\u001a\u00020\u000f2\b\b\u0002\u0010\u001e\u001a\u00020\u000f2\b\b\u0002\u0010\u001f\u001a\u00020\u000f2\b\b\u0002\u0010 \u001a\u00020\u000f2\b\b\u0002\u0010!\u001a\u00020\u000f2\b\b\u0002\u0010\"\u001a\u00020\u000f2\b\b\u0002\u0010#\u001a\u00020\u000f2\b\b\u0002\u0010$\u001a\u00020\u000f2\b\b\u0002\u0010%\u001a\u00020\u000f2\b\b\u0002\u0010&\u001a\u00020\u000f2\b\b\u0002\u0010'\u001a\u00020\u000fH\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b(\u0010)J\u0085\u0002\u0010*\u001a\u00020\r2\b\b\u0002\u0010\u000e\u001a\u00020\u000f2\b\b\u0002\u0010\u0010\u001a\u00020\u000f2\b\b\u0002\u0010\u0011\u001a\u00020\u000f2\b\b\u0002\u0010\u0012\u001a\u00020\u000f2\b\b\u0002\u0010\u0013\u001a\u00020\u000f2\b\b\u0002\u0010\u0014\u001a\u00020\u00152\b\b\u0002\u0010+\u001a\u00020\u000f2\b\b\u0002\u0010,\u001a\u00020\u000f2\b\b\u0002\u0010-\u001a\u00020\u000f2\b\b\u0002\u0010.\u001a\u00020\u000f2\b\b\u0002\u0010\u001a\u001a\u00020\u000f2\b\b\u0002\u0010\u001b\u001a\u00020\u000f2\b\b\u0002\u0010\u001c\u001a\u00020\u000f2\b\b\u0002\u0010\u001d\u001a\u00020\u000f2\b\b\u0002\u0010\u001e\u001a\u00020\u000f2\b\b\u0002\u0010\u001f\u001a\u00020\u000f2\b\b\u0002\u0010 \u001a\u00020\u000f2\b\b\u0002\u0010!\u001a\u00020\u000f2\b\b\u0002\u0010\"\u001a\u00020\u000f2\b\b\u0002\u0010#\u001a\u00020\u000f2\b\b\u0002\u0010$\u001a\u00020\u000f2\b\b\u0002\u0010%\u001a\u00020\u000f2\b\b\u0002\u0010&\u001a\u00020\u000f2\b\b\u0002\u0010'\u001a\u00020\u000fH\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b/\u0010)R\u0011\u0010\u0003\u001a\u00020\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0005\u0010\u0006\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u00060"}, d2 = {"Landroidx/compose/material3/ExposedDropdownMenuDefaults;", "", "()V", "ItemContentPadding", "Landroidx/compose/foundation/layout/PaddingValues;", "getItemContentPadding", "()Landroidx/compose/foundation/layout/PaddingValues;", "TrailingIcon", "", "expanded", "", "(ZLandroidx/compose/runtime/Composer;I)V", "outlinedTextFieldColors", "Landroidx/compose/material3/TextFieldColors;", "textColor", "Landroidx/compose/ui/graphics/Color;", "disabledTextColor", "containerColor", "cursorColor", "errorCursorColor", "selectionColors", "Landroidx/compose/foundation/text/selection/TextSelectionColors;", "focusedBorderColor", "unfocusedBorderColor", "disabledBorderColor", "errorBorderColor", "focusedLeadingIconColor", "unfocusedLeadingIconColor", "disabledLeadingIconColor", "errorLeadingIconColor", "focusedTrailingIconColor", "unfocusedTrailingIconColor", "disabledTrailingIconColor", "errorTrailingIconColor", "focusedLabelColor", "unfocusedLabelColor", "disabledLabelColor", "errorLabelColor", "placeholderColor", "disabledPlaceholderColor", "outlinedTextFieldColors-St-qZLY", "(JJJJJLandroidx/compose/foundation/text/selection/TextSelectionColors;JJJJJJJJJJJJJJJJJJLandroidx/compose/runtime/Composer;IIII)Landroidx/compose/material3/TextFieldColors;", "textFieldColors", "focusedIndicatorColor", "unfocusedIndicatorColor", "disabledIndicatorColor", "errorIndicatorColor", "textFieldColors-St-qZLY", "material3_release"}, k = 1, mv = {1, 7, 1}, xi = 48)
/* loaded from: classes.dex */
public final class ExposedDropdownMenuDefaults {
    public static final int $stable = 0;
    public static final ExposedDropdownMenuDefaults INSTANCE = new ExposedDropdownMenuDefaults();
    private static final PaddingValues ItemContentPadding;

    private ExposedDropdownMenuDefaults() {
    }

    @ExperimentalMaterial3Api
    public final void TrailingIcon(final boolean expanded, Composer $composer, final int $changed) {
        Composer $composer2 = $composer.startRestartGroup(-1803742020);
        ComposerKt.sourceInformation($composer2, "C(TrailingIcon)299@12322L129:ExposedDropdownMenu.kt#uh7d8r");
        int $dirty = $changed;
        if (($changed & 14) == 0) {
            $dirty |= $composer2.changed(expanded) ? 4 : 2;
        }
        if (($dirty & 11) != 2 || !$composer2.getSkipping()) {
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(-1803742020, $changed, -1, "androidx.compose.material3.ExposedDropdownMenuDefaults.TrailingIcon (ExposedDropdownMenu.kt:298)");
            }
            IconKt.m1438Iconww6aTOc(ArrowDropDownKt.getArrowDropDown(Icons.Filled.INSTANCE), (String) null, RotateKt.rotate(Modifier.Companion, expanded ? 180.0f : 0.0f), 0L, $composer2, 48, 8);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
        } else {
            $composer2.skipToGroupEnd();
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material3.ExposedDropdownMenuDefaults$TrailingIcon$1
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

            public final void invoke(Composer composer, int i) {
                ExposedDropdownMenuDefaults.this.TrailingIcon(expanded, composer, $changed | 1);
            }
        });
    }

    /* renamed from: textFieldColors-St-qZLY  reason: not valid java name */
    public final TextFieldColors m1390textFieldColorsStqZLY(long textColor, long disabledTextColor, long containerColor, long cursorColor, long errorCursorColor, TextSelectionColors selectionColors, long focusedIndicatorColor, long unfocusedIndicatorColor, long disabledIndicatorColor, long errorIndicatorColor, long focusedLeadingIconColor, long unfocusedLeadingIconColor, long disabledLeadingIconColor, long errorLeadingIconColor, long focusedTrailingIconColor, long unfocusedTrailingIconColor, long disabledTrailingIconColor, long errorTrailingIconColor, long focusedLabelColor, long unfocusedLabelColor, long disabledLabelColor, long errorLabelColor, long placeholderColor, long disabledPlaceholderColor, Composer $composer, int $changed, int $changed1, int $changed2, int i) {
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
        long m2604copywmQWz5c;
        long m2604copywmQWz5c2;
        long m2604copywmQWz5c3;
        long m2604copywmQWz5c4;
        long m2604copywmQWz5c5;
        $composer.startReplaceableGroup(-2013303349);
        ComposerKt.sourceInformation($composer, "C(textFieldColors)P(19:c#ui.graphics.Color,6:c#ui.graphics.Color,0:c#ui.graphics.Color,1:c#ui.graphics.Color,8:c#ui.graphics.Color,18,13:c#ui.graphics.Color,20:c#ui.graphics.Color,2:c#ui.graphics.Color,9:c#ui.graphics.Color,15:c#ui.graphics.Color,22:c#ui.graphics.Color,4:c#ui.graphics.Color,11:c#ui.graphics.Color,16:c#ui.graphics.Color,23:c#ui.graphics.Color,7:c#ui.graphics.Color,12:c#ui.graphics.Color,14:c#ui.graphics.Color,21:c#ui.graphics.Color,3:c#ui.graphics.Color,10:c#ui.graphics.Color,17:c#ui.graphics.Color,5:c#ui.graphics.Color)339@14991L9,340@15090L9,342@15264L9,343@15349L9,344@15449L9,345@15532L7,347@15652L9,349@15771L9,351@15897L9,354@16113L9,356@16233L9,358@16350L9,360@16474L9,363@16684L9,365@16806L9,367@16925L9,369@17051L9,372@17264L9,373@17360L9,374@17453L9,375@17553L9,376@17647L9,377@17742L9,379@17860L9,382@18007L1365:ExposedDropdownMenu.kt#uh7d8r");
        long textColor2 = (i & 1) != 0 ? ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getFieldInputTextColor(), $composer, 6) : textColor;
        if ((i & 2) != 0) {
            m2604copywmQWz5c5 = Color.m2604copywmQWz5c(r4, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r4) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r4) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r4) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getFieldDisabledInputTextColor(), $composer, 6)) : 0.0f);
            disabledTextColor2 = m2604copywmQWz5c5;
        } else {
            disabledTextColor2 = disabledTextColor;
        }
        if ((i & 4) == 0) {
            containerColor2 = containerColor;
        } else {
            containerColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldContainerColor(), $composer, 6);
        }
        if ((i & 8) == 0) {
            cursorColor2 = cursorColor;
        } else {
            cursorColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldCaretColor(), $composer, 6);
        }
        if ((i & 16) == 0) {
            errorCursorColor2 = errorCursorColor;
        } else {
            errorCursorColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldErrorFocusCaretColor(), $composer, 6);
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
            focusedIndicatorColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldFocusActiveIndicatorColor(), $composer, 6);
        } else {
            focusedIndicatorColor2 = focusedIndicatorColor;
        }
        if ((i & 128) == 0) {
            unfocusedIndicatorColor2 = unfocusedIndicatorColor;
        } else {
            unfocusedIndicatorColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldActiveIndicatorColor(), $composer, 6);
        }
        if ((i & 256) != 0) {
            m2604copywmQWz5c4 = Color.m2604copywmQWz5c(r4, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r4) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r4) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r4) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldDisabledActiveIndicatorColor(), $composer, 6)) : 0.0f);
            disabledIndicatorColor2 = m2604copywmQWz5c4;
        } else {
            disabledIndicatorColor2 = disabledIndicatorColor;
        }
        if ((i & 512) == 0) {
            errorIndicatorColor2 = errorIndicatorColor;
        } else {
            errorIndicatorColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldErrorActiveIndicatorColor(), $composer, 6);
        }
        if ((i & 1024) == 0) {
            focusedLeadingIconColor2 = focusedLeadingIconColor;
        } else {
            focusedLeadingIconColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldFocusLeadingIconColor(), $composer, 6);
        }
        if ((i & 2048) == 0) {
            unfocusedLeadingIconColor2 = unfocusedLeadingIconColor;
        } else {
            unfocusedLeadingIconColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldLeadingIconColor(), $composer, 6);
        }
        if ((i & 4096) != 0) {
            m2604copywmQWz5c3 = Color.m2604copywmQWz5c(r4, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r4) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r4) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r4) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldDisabledLeadingIconColor(), $composer, 6)) : 0.0f);
            disabledLeadingIconColor2 = m2604copywmQWz5c3;
        } else {
            disabledLeadingIconColor2 = disabledLeadingIconColor;
        }
        if ((i & 8192) == 0) {
            errorLeadingIconColor2 = errorLeadingIconColor;
        } else {
            errorLeadingIconColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldErrorLeadingIconColor(), $composer, 6);
        }
        if ((i & 16384) == 0) {
            focusedTrailingIconColor2 = focusedTrailingIconColor;
        } else {
            focusedTrailingIconColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldFocusTrailingIconColor(), $composer, 6);
        }
        if ((32768 & i) == 0) {
            unfocusedTrailingIconColor2 = unfocusedTrailingIconColor;
        } else {
            unfocusedTrailingIconColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldTrailingIconColor(), $composer, 6);
        }
        if ((65536 & i) != 0) {
            m2604copywmQWz5c2 = Color.m2604copywmQWz5c(r4, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r4) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r4) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r4) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldDisabledTrailingIconColor(), $composer, 6)) : 0.0f);
            disabledTrailingIconColor2 = m2604copywmQWz5c2;
        } else {
            disabledTrailingIconColor2 = disabledTrailingIconColor;
        }
        if ((131072 & i) == 0) {
            errorTrailingIconColor2 = errorTrailingIconColor;
        } else {
            errorTrailingIconColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getTextFieldErrorTrailingIconColor(), $composer, 6);
        }
        if ((262144 & i) == 0) {
            focusedLabelColor2 = focusedLabelColor;
        } else {
            focusedLabelColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getFieldFocusLabelTextColor(), $composer, 6);
        }
        if ((524288 & i) == 0) {
            unfocusedLabelColor2 = unfocusedLabelColor;
        } else {
            unfocusedLabelColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getFieldLabelTextColor(), $composer, 6);
        }
        if ((1048576 & i) == 0) {
            disabledLabelColor2 = disabledLabelColor;
        } else {
            disabledLabelColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getFieldDisabledLabelTextColor(), $composer, 6);
        }
        if ((2097152 & i) == 0) {
            errorLabelColor2 = errorLabelColor;
        } else {
            errorLabelColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getFieldErrorLabelTextColor(), $composer, 6);
        }
        if ((4194304 & i) == 0) {
            placeholderColor2 = placeholderColor;
        } else {
            placeholderColor2 = ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getFieldSupportingTextColor(), $composer, 6);
        }
        if ((i & 8388608) != 0) {
            m2604copywmQWz5c = Color.m2604copywmQWz5c(r2, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r2) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r2) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r2) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(FilledAutocompleteTokens.INSTANCE.getFieldDisabledInputTextColor(), $composer, 6)) : 0.0f);
            disabledPlaceholderColor2 = m2604copywmQWz5c;
        } else {
            disabledPlaceholderColor2 = disabledPlaceholderColor;
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-2013303349, $changed, $changed1, "androidx.compose.material3.ExposedDropdownMenuDefaults.textFieldColors (ExposedDropdownMenu.kt:338)");
        }
        TextFieldColors m1620textFieldColorsl59Burw = TextFieldDefaults.INSTANCE.m1620textFieldColorsl59Burw(textColor2, disabledTextColor2, containerColor2, cursorColor2, errorCursorColor2, selectionColors2, focusedIndicatorColor2, unfocusedIndicatorColor2, disabledIndicatorColor2, errorIndicatorColor2, focusedLeadingIconColor2, unfocusedLeadingIconColor2, disabledLeadingIconColor2, errorLeadingIconColor2, focusedTrailingIconColor2, unfocusedTrailingIconColor2, disabledTrailingIconColor2, errorTrailingIconColor2, focusedLabelColor2, unfocusedLabelColor2, disabledLabelColor2, errorLabelColor2, placeholderColor2, disabledPlaceholderColor2, 0L, 0L, 0L, 0L, $composer, ($changed & 14) | ($changed & 112) | ($changed & 896) | ($changed & 7168) | ($changed & 57344) | ($changed & 458752) | ($changed & 3670016) | ($changed & 29360128) | ($changed & 234881024) | ($changed & 1879048192), ($changed1 & 14) | ($changed1 & 112) | ($changed1 & 896) | ($changed1 & 7168) | (57344 & $changed1) | ($changed1 & 458752) | ($changed1 & 3670016) | ($changed1 & 29360128) | ($changed1 & 234881024) | ($changed1 & 1879048192), 100663296 | ($changed2 & 14) | ($changed2 & 112) | ($changed2 & 896) | ($changed2 & 7168), 251658240);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return m1620textFieldColorsl59Burw;
    }

    /* renamed from: outlinedTextFieldColors-St-qZLY  reason: not valid java name */
    public final TextFieldColors m1389outlinedTextFieldColorsStqZLY(long textColor, long disabledTextColor, long containerColor, long cursorColor, long errorCursorColor, TextSelectionColors selectionColors, long focusedBorderColor, long unfocusedBorderColor, long disabledBorderColor, long errorBorderColor, long focusedLeadingIconColor, long unfocusedLeadingIconColor, long disabledLeadingIconColor, long errorLeadingIconColor, long focusedTrailingIconColor, long unfocusedTrailingIconColor, long disabledTrailingIconColor, long errorTrailingIconColor, long focusedLabelColor, long unfocusedLabelColor, long disabledLabelColor, long errorLabelColor, long placeholderColor, long disabledPlaceholderColor, Composer $composer, int $changed, int $changed1, int $changed2, int i) {
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
        long m2604copywmQWz5c;
        long m2604copywmQWz5c2;
        long m2604copywmQWz5c3;
        long m2604copywmQWz5c4;
        long m2604copywmQWz5c5;
        long m2604copywmQWz5c6;
        $composer.startReplaceableGroup(-83147315);
        ComposerKt.sourceInformation($composer, "C(outlinedTextFieldColors)P(19:c#ui.graphics.Color,6:c#ui.graphics.Color,0:c#ui.graphics.Color,1:c#ui.graphics.Color,9:c#ui.graphics.Color,18,13:c#ui.graphics.Color,20:c#ui.graphics.Color,2:c#ui.graphics.Color,8:c#ui.graphics.Color,15:c#ui.graphics.Color,22:c#ui.graphics.Color,4:c#ui.graphics.Color,11:c#ui.graphics.Color,16:c#ui.graphics.Color,23:c#ui.graphics.Color,7:c#ui.graphics.Color,12:c#ui.graphics.Color,14:c#ui.graphics.Color,21:c#ui.graphics.Color,3:c#ui.graphics.Color,10:c#ui.graphics.Color,17:c#ui.graphics.Color,5:c#ui.graphics.Color)441@21894L9,442@21995L9,445@22217L9,447@22331L9,448@22414L7,449@22513L9,450@22611L9,452@22728L9,454@22917L9,456@23039L9,458@23158L9,460@23284L9,463@23498L9,465@23622L9,467@23743L9,469@23871L9,472@24088L9,473@24186L9,474@24281L9,475@24383L9,477@24563L9,478@24660L9,480@24780L9,483@24929L1349:ExposedDropdownMenu.kt#uh7d8r");
        long textColor2 = (i & 1) != 0 ? ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getFieldInputTextColor(), $composer, 6) : textColor;
        if ((i & 2) != 0) {
            m2604copywmQWz5c6 = Color.m2604copywmQWz5c(r4, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r4) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r4) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r4) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getFieldDisabledInputTextColor(), $composer, 6)) : 0.0f);
            disabledTextColor2 = m2604copywmQWz5c6;
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
            cursorColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldCaretColor(), $composer, 6);
        }
        if ((i & 16) == 0) {
            errorCursorColor2 = errorCursorColor;
        } else {
            errorCursorColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldErrorFocusCaretColor(), $composer, 6);
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
            focusedBorderColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldFocusOutlineColor(), $composer, 6);
        } else {
            focusedBorderColor2 = focusedBorderColor;
        }
        if ((i & 128) == 0) {
            unfocusedBorderColor2 = unfocusedBorderColor;
        } else {
            unfocusedBorderColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldOutlineColor(), $composer, 6);
        }
        if ((i & 256) != 0) {
            m2604copywmQWz5c5 = Color.m2604copywmQWz5c(r4, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r4) : 0.12f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r4) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r4) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldDisabledOutlineColor(), $composer, 6)) : 0.0f);
            disabledBorderColor2 = m2604copywmQWz5c5;
        } else {
            disabledBorderColor2 = disabledBorderColor;
        }
        if ((i & 512) == 0) {
            errorBorderColor2 = errorBorderColor;
        } else {
            errorBorderColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldErrorOutlineColor(), $composer, 6);
        }
        if ((i & 1024) == 0) {
            focusedLeadingIconColor2 = focusedLeadingIconColor;
        } else {
            focusedLeadingIconColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldFocusLeadingIconColor(), $composer, 6);
        }
        if ((i & 2048) == 0) {
            unfocusedLeadingIconColor2 = unfocusedLeadingIconColor;
        } else {
            unfocusedLeadingIconColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldLeadingIconColor(), $composer, 6);
        }
        if ((i & 4096) != 0) {
            m2604copywmQWz5c4 = Color.m2604copywmQWz5c(r4, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r4) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r4) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r4) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldDisabledLeadingIconColor(), $composer, 6)) : 0.0f);
            disabledLeadingIconColor2 = m2604copywmQWz5c4;
        } else {
            disabledLeadingIconColor2 = disabledLeadingIconColor;
        }
        if ((i & 8192) == 0) {
            errorLeadingIconColor2 = errorLeadingIconColor;
        } else {
            errorLeadingIconColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldErrorLeadingIconColor(), $composer, 6);
        }
        if ((i & 16384) == 0) {
            focusedTrailingIconColor2 = focusedTrailingIconColor;
        } else {
            focusedTrailingIconColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldFocusTrailingIconColor(), $composer, 6);
        }
        if ((32768 & i) == 0) {
            unfocusedTrailingIconColor2 = unfocusedTrailingIconColor;
        } else {
            unfocusedTrailingIconColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldTrailingIconColor(), $composer, 6);
        }
        if ((65536 & i) != 0) {
            m2604copywmQWz5c3 = Color.m2604copywmQWz5c(r4, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r4) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r4) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r4) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldDisabledTrailingIconColor(), $composer, 6)) : 0.0f);
            disabledTrailingIconColor2 = m2604copywmQWz5c3;
        } else {
            disabledTrailingIconColor2 = disabledTrailingIconColor;
        }
        if ((131072 & i) == 0) {
            errorTrailingIconColor2 = errorTrailingIconColor;
        } else {
            errorTrailingIconColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getTextFieldErrorTrailingIconColor(), $composer, 6);
        }
        if ((262144 & i) == 0) {
            focusedLabelColor2 = focusedLabelColor;
        } else {
            focusedLabelColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getFieldFocusLabelTextColor(), $composer, 6);
        }
        if ((524288 & i) == 0) {
            unfocusedLabelColor2 = unfocusedLabelColor;
        } else {
            unfocusedLabelColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getFieldLabelTextColor(), $composer, 6);
        }
        if ((1048576 & i) != 0) {
            m2604copywmQWz5c2 = Color.m2604copywmQWz5c(r4, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r4) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r4) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r4) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getFieldDisabledLabelTextColor(), $composer, 6)) : 0.0f);
            disabledLabelColor2 = m2604copywmQWz5c2;
        } else {
            disabledLabelColor2 = disabledLabelColor;
        }
        if ((2097152 & i) == 0) {
            errorLabelColor2 = errorLabelColor;
        } else {
            errorLabelColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getFieldErrorLabelTextColor(), $composer, 6);
        }
        if ((4194304 & i) == 0) {
            placeholderColor2 = placeholderColor;
        } else {
            placeholderColor2 = ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getFieldSupportingTextColor(), $composer, 6);
        }
        if ((i & 8388608) != 0) {
            m2604copywmQWz5c = Color.m2604copywmQWz5c(r2, (r12 & 1) != 0 ? Color.m2608getAlphaimpl(r2) : 0.38f, (r12 & 2) != 0 ? Color.m2612getRedimpl(r2) : 0.0f, (r12 & 4) != 0 ? Color.m2611getGreenimpl(r2) : 0.0f, (r12 & 8) != 0 ? Color.m2609getBlueimpl(ColorSchemeKt.toColor(OutlinedAutocompleteTokens.INSTANCE.getFieldDisabledInputTextColor(), $composer, 6)) : 0.0f);
            disabledPlaceholderColor2 = m2604copywmQWz5c;
        } else {
            disabledPlaceholderColor2 = disabledPlaceholderColor;
        }
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(-83147315, $changed, $changed1, "androidx.compose.material3.ExposedDropdownMenuDefaults.outlinedTextFieldColors (ExposedDropdownMenu.kt:440)");
        }
        TextFieldColors m1617outlinedTextFieldColorsl59Burw = TextFieldDefaults.INSTANCE.m1617outlinedTextFieldColorsl59Burw(textColor2, disabledTextColor2, containerColor2, cursorColor2, errorCursorColor2, selectionColors2, focusedBorderColor2, unfocusedBorderColor2, disabledBorderColor2, errorBorderColor2, focusedLeadingIconColor2, unfocusedLeadingIconColor2, disabledLeadingIconColor2, errorLeadingIconColor2, focusedTrailingIconColor2, unfocusedTrailingIconColor2, disabledTrailingIconColor2, errorTrailingIconColor2, focusedLabelColor2, unfocusedLabelColor2, disabledLabelColor2, errorLabelColor2, placeholderColor2, disabledPlaceholderColor2, 0L, 0L, 0L, 0L, $composer, ($changed & 14) | ($changed & 112) | ($changed & 896) | ($changed & 7168) | ($changed & 57344) | ($changed & 458752) | ($changed & 3670016) | ($changed & 29360128) | ($changed & 234881024) | ($changed & 1879048192), ($changed1 & 14) | ($changed1 & 112) | ($changed1 & 896) | ($changed1 & 7168) | (57344 & $changed1) | ($changed1 & 458752) | ($changed1 & 3670016) | ($changed1 & 29360128) | ($changed1 & 234881024) | ($changed1 & 1879048192), 100663296 | ($changed2 & 14) | ($changed2 & 112) | ($changed2 & 896) | ($changed2 & 7168), 251658240);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return m1617outlinedTextFieldColorsl59Burw;
    }

    static {
        float f;
        f = ExposedDropdownMenuKt.ExposedDropdownMenuItemHorizontalPadding;
        ItemContentPadding = PaddingKt.m408PaddingValuesYgX7TsA(f, Dp.m5122constructorimpl(0));
    }

    public final PaddingValues getItemContentPadding() {
        return ItemContentPadding;
    }
}
