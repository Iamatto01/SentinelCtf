package androidx.compose.foundation.text;

import androidx.compose.foundation.layout.SizeKt;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.State;
import androidx.compose.ui.ComposedModifierKt;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.platform.CompositionLocalsKt;
import androidx.compose.ui.platform.InspectableValueKt;
import androidx.compose.ui.platform.InspectorInfo;
import androidx.compose.ui.text.TextStyle;
import androidx.compose.ui.text.TextStyleKt;
import androidx.compose.ui.text.font.FontFamily;
import androidx.compose.ui.text.font.FontStyle;
import androidx.compose.ui.text.font.FontSynthesis;
import androidx.compose.ui.text.font.FontWeight;
import androidx.compose.ui.unit.Density;
import androidx.compose.ui.unit.Dp;
import androidx.compose.ui.unit.IntSize;
import androidx.compose.ui.unit.LayoutDirection;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: HeightInLinesModifier.kt */
@Metadata(d1 = {"\u0000\u001c\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u001a\u0018\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0001H\u0000\u001a(\u0010\u0006\u001a\u00020\u0007*\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\b\b\u0002\u0010\u0004\u001a\u00020\u00012\b\b\u0002\u0010\u0005\u001a\u00020\u0001H\u0000\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0080T¢\u0006\u0002\n\u0000¨\u0006\n"}, d2 = {"DefaultMinLines", "", "validateMinMaxLines", "", "minLines", "maxLines", "heightInLines", "Landroidx/compose/ui/Modifier;", "textStyle", "Landroidx/compose/ui/text/TextStyle;", "foundation_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class HeightInLinesModifierKt {
    public static final int DefaultMinLines = 1;

    public static /* synthetic */ Modifier heightInLines$default(Modifier modifier, TextStyle textStyle, int i, int i2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            i = 1;
        }
        if ((i3 & 4) != 0) {
            i2 = Integer.MAX_VALUE;
        }
        return heightInLines(modifier, textStyle, i, i2);
    }

    public static final Modifier heightInLines(Modifier $this$heightInLines, final TextStyle textStyle, final int minLines, final int maxLines) {
        Intrinsics.checkNotNullParameter($this$heightInLines, "<this>");
        Intrinsics.checkNotNullParameter(textStyle, "textStyle");
        return ComposedModifierKt.composed($this$heightInLines, InspectableValueKt.isDebugInspectorInfoEnabled() ? new Function1<InspectorInfo, Unit>() { // from class: androidx.compose.foundation.text.HeightInLinesModifierKt$heightInLines$$inlined$debugInspectorInfo$1
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
                $this$null.setName("heightInLines");
                $this$null.getProperties().set("minLines", Integer.valueOf(minLines));
                $this$null.getProperties().set("maxLines", Integer.valueOf(maxLines));
                $this$null.getProperties().set("textStyle", textStyle);
            }
        } : InspectableValueKt.getNoInspectorInfo(), new Function3<Modifier, Composer, Integer, Modifier>() { // from class: androidx.compose.foundation.text.HeightInLinesModifierKt$heightInLines$2
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
                Object value$iv$iv;
                State value$iv$iv2;
                Object value$iv$iv3;
                Object value$iv$iv4;
                Intrinsics.checkNotNullParameter(composed, "$this$composed");
                $composer.startReplaceableGroup(408240218);
                ComposerKt.sourceInformation($composer, "C62@2391L7,63@2452L7,64@2507L7,68@2678L96,71@2795L312,80@3135L366,96@3533L428:HeightInLinesModifier.kt#423gt5");
                if (ComposerKt.isTraceInProgress()) {
                    ComposerKt.traceEventStart(408240218, $changed, -1, "androidx.compose.foundation.text.heightInLines.<anonymous> (HeightInLinesModifier.kt:58)");
                }
                HeightInLinesModifierKt.validateMinMaxLines(minLines, maxLines);
                if (minLines == 1 && maxLines == Integer.MAX_VALUE) {
                    Modifier.Companion companion = Modifier.Companion;
                    if (ComposerKt.isTraceInProgress()) {
                        ComposerKt.traceEventEnd();
                    }
                    $composer.endReplaceableGroup();
                    return companion;
                }
                ComposerKt.sourceInformationMarkerStart($composer, 2023513938, "CC:CompositionLocal.kt#9igjgp");
                Object consume = $composer.consume(CompositionLocalsKt.getLocalDensity());
                ComposerKt.sourceInformationMarkerEnd($composer);
                Density density = (Density) consume;
                ComposerKt.sourceInformationMarkerStart($composer, 2023513938, "CC:CompositionLocal.kt#9igjgp");
                Object consume2 = $composer.consume(CompositionLocalsKt.getLocalFontFamilyResolver());
                ComposerKt.sourceInformationMarkerEnd($composer);
                FontFamily.Resolver fontFamilyResolver = (FontFamily.Resolver) consume2;
                ComposerKt.sourceInformationMarkerStart($composer, 2023513938, "CC:CompositionLocal.kt#9igjgp");
                Object consume3 = $composer.consume(CompositionLocalsKt.getLocalLayoutDirection());
                ComposerKt.sourceInformationMarkerEnd($composer);
                LayoutDirection layoutDirection = (LayoutDirection) consume3;
                Object key1$iv = textStyle;
                TextStyle textStyle2 = textStyle;
                $composer.startReplaceableGroup(511388516);
                ComposerKt.sourceInformation($composer, "CC(remember)P(1,2):Composables.kt#9igjgp");
                boolean invalid$iv$iv = $composer.changed(key1$iv) | $composer.changed(layoutDirection);
                Object it$iv$iv = $composer.rememberedValue();
                if (invalid$iv$iv || it$iv$iv == Composer.Companion.getEmpty()) {
                    Object value$iv$iv5 = TextStyleKt.resolveDefaults(textStyle2, layoutDirection);
                    $composer.updateRememberedValue(value$iv$iv5);
                    value$iv$iv = value$iv$iv5;
                } else {
                    value$iv$iv = it$iv$iv;
                }
                $composer.endReplaceableGroup();
                TextStyle resolvedStyle = (TextStyle) value$iv$iv;
                $composer.startReplaceableGroup(511388516);
                ComposerKt.sourceInformation($composer, "CC(remember)P(1,2):Composables.kt#9igjgp");
                boolean invalid$iv$iv2 = $composer.changed(fontFamilyResolver) | $composer.changed(resolvedStyle);
                Object it$iv$iv2 = $composer.rememberedValue();
                if (invalid$iv$iv2 || it$iv$iv2 == Composer.Companion.getEmpty()) {
                    FontFamily fontFamily = resolvedStyle.getFontFamily();
                    FontWeight fontWeight = resolvedStyle.getFontWeight();
                    if (fontWeight == null) {
                        fontWeight = FontWeight.Companion.getNormal();
                    }
                    FontWeight fontWeight2 = fontWeight;
                    FontStyle m4659getFontStyle4Lr2A7w = resolvedStyle.m4659getFontStyle4Lr2A7w();
                    int m4725unboximpl = m4659getFontStyle4Lr2A7w != null ? m4659getFontStyle4Lr2A7w.m4725unboximpl() : FontStyle.Companion.m4727getNormal_LCdwA();
                    FontSynthesis m4660getFontSynthesisZQGJjVo = resolvedStyle.m4660getFontSynthesisZQGJjVo();
                    int $changed$iv = m4660getFontSynthesisZQGJjVo != null ? m4660getFontSynthesisZQGJjVo.m4736unboximpl() : FontSynthesis.Companion.m4737getAllGVVA2EU();
                    value$iv$iv2 = fontFamilyResolver.mo4697resolveDPcqOEQ(fontFamily, fontWeight2, m4725unboximpl, $changed$iv);
                    $composer.updateRememberedValue(value$iv$iv2);
                } else {
                    value$iv$iv2 = it$iv$iv2;
                }
                $composer.endReplaceableGroup();
                State typeface$delegate = value$iv$iv2;
                Object[] keys$iv = {density, fontFamilyResolver, textStyle, layoutDirection, typeface$delegate.getValue()};
                $composer.startReplaceableGroup(-568225417);
                ComposerKt.sourceInformation($composer, "CC(remember)P(1):Composables.kt#9igjgp");
                boolean invalid$iv = false;
                for (Object key$iv : keys$iv) {
                    invalid$iv |= $composer.changed(key$iv);
                }
                Object it$iv$iv3 = $composer.rememberedValue();
                if (invalid$iv || it$iv$iv3 == Composer.Companion.getEmpty()) {
                    Object value$iv$iv6 = Integer.valueOf(IntSize.m5281getHeightimpl(TextFieldDelegateKt.computeSizeForDefaultText(resolvedStyle, density, fontFamilyResolver, TextFieldDelegateKt.getEmptyTextReplacement(), 1)));
                    $composer.updateRememberedValue(value$iv$iv6);
                    value$iv$iv3 = value$iv$iv6;
                } else {
                    value$iv$iv3 = it$iv$iv3;
                }
                $composer.endReplaceableGroup();
                int firstLineHeight = ((Number) value$iv$iv3).intValue();
                Object[] keys$iv2 = {density, fontFamilyResolver, textStyle, layoutDirection, typeface$delegate.getValue()};
                $composer.startReplaceableGroup(-568225417);
                ComposerKt.sourceInformation($composer, "CC(remember)P(1):Composables.kt#9igjgp");
                boolean invalid$iv2 = false;
                for (Object key$iv2 : keys$iv2) {
                    invalid$iv2 |= $composer.changed(key$iv2);
                }
                Object it$iv$iv4 = $composer.rememberedValue();
                if (invalid$iv2 || it$iv$iv4 == Composer.Companion.getEmpty()) {
                    String twoLines = TextFieldDelegateKt.getEmptyTextReplacement() + '\n' + TextFieldDelegateKt.getEmptyTextReplacement();
                    Object value$iv$iv7 = Integer.valueOf(IntSize.m5281getHeightimpl(TextFieldDelegateKt.computeSizeForDefaultText(resolvedStyle, density, fontFamilyResolver, twoLines, 2)));
                    $composer.updateRememberedValue(value$iv$iv7);
                    value$iv$iv4 = value$iv$iv7;
                } else {
                    value$iv$iv4 = it$iv$iv4;
                }
                $composer.endReplaceableGroup();
                int firstTwoLinesHeight = ((Number) value$iv$iv4).intValue();
                int lineHeight = firstTwoLinesHeight - firstLineHeight;
                int i = minLines;
                Integer precomputedMinLinesHeight = i == 1 ? null : Integer.valueOf(((i - 1) * lineHeight) + firstLineHeight);
                int i2 = maxLines;
                Integer precomputedMaxLinesHeight = i2 != Integer.MAX_VALUE ? Integer.valueOf(((i2 - 1) * lineHeight) + firstLineHeight) : null;
                Modifier m444heightInVpY3zN4 = SizeKt.m444heightInVpY3zN4(Modifier.Companion, precomputedMinLinesHeight != null ? density.mo298toDpu2uoSUM(precomputedMinLinesHeight.intValue()) : Dp.Companion.m5142getUnspecifiedD9Ej5fM(), precomputedMaxLinesHeight != null ? density.mo298toDpu2uoSUM(precomputedMaxLinesHeight.intValue()) : Dp.Companion.m5142getUnspecifiedD9Ej5fM());
                if (ComposerKt.isTraceInProgress()) {
                    ComposerKt.traceEventEnd();
                }
                $composer.endReplaceableGroup();
                return m444heightInVpY3zN4;
            }
        });
    }

    public static final void validateMinMaxLines(int minLines, int maxLines) {
        if (!(minLines > 0 && maxLines > 0)) {
            throw new IllegalArgumentException(("both minLines " + minLines + " and maxLines " + maxLines + " must be greater than zero").toString());
        }
        if (!(minLines <= maxLines)) {
            throw new IllegalArgumentException(("minLines " + minLines + " must be less than or equal to maxLines " + maxLines).toString());
        }
    }
}
