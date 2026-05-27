package androidx.compose.ui.text.platform.extensions;

import android.graphics.Typeface;
import android.text.Spannable;
import android.text.style.AbsoluteSizeSpan;
import android.text.style.BackgroundColorSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.LeadingMarginSpan;
import android.text.style.MetricAffectingSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.ScaleXSpan;
import androidx.compose.ui.geometry.Offset;
import androidx.compose.ui.graphics.Brush;
import androidx.compose.ui.graphics.Color;
import androidx.compose.ui.graphics.ColorKt;
import androidx.compose.ui.graphics.ShaderBrush;
import androidx.compose.ui.graphics.Shadow;
import androidx.compose.ui.graphics.SolidColor;
import androidx.compose.ui.graphics.drawscope.DrawStyle;
import androidx.compose.ui.text.AnnotatedString;
import androidx.compose.ui.text.AnnotatedStringKt;
import androidx.compose.ui.text.SpanStyle;
import androidx.compose.ui.text.TextStyle;
import androidx.compose.ui.text.android.style.BaselineShiftSpan;
import androidx.compose.ui.text.android.style.FontFeatureSpan;
import androidx.compose.ui.text.android.style.LetterSpacingSpanEm;
import androidx.compose.ui.text.android.style.LetterSpacingSpanPx;
import androidx.compose.ui.text.android.style.LineHeightSpan;
import androidx.compose.ui.text.android.style.LineHeightStyleSpan;
import androidx.compose.ui.text.android.style.ShadowSpan;
import androidx.compose.ui.text.android.style.SkewXSpan;
import androidx.compose.ui.text.android.style.TextDecorationSpan;
import androidx.compose.ui.text.android.style.TypefaceSpan;
import androidx.compose.ui.text.font.FontFamily;
import androidx.compose.ui.text.font.FontStyle;
import androidx.compose.ui.text.font.FontSynthesis;
import androidx.compose.ui.text.font.FontWeight;
import androidx.compose.ui.text.intl.LocaleList;
import androidx.compose.ui.text.platform.style.DrawStyleSpan;
import androidx.compose.ui.text.platform.style.ShaderBrushSpan;
import androidx.compose.ui.text.style.BaselineShift;
import androidx.compose.ui.text.style.LineHeightStyle;
import androidx.compose.ui.text.style.TextDecoration;
import androidx.compose.ui.text.style.TextGeometricTransform;
import androidx.compose.ui.text.style.TextIndent;
import androidx.compose.ui.unit.Density;
import androidx.compose.ui.unit.TextUnit;
import androidx.compose.ui.unit.TextUnitKt;
import androidx.compose.ui.unit.TextUnitType;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.ArraysKt;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.math.MathKt;
import kotlin.text.StringsKt;
/* compiled from: SpannableExtensions.android.kt */
@Metadata(d1 = {"\u0000Î\u0001\n\u0000\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\u001a'\u0010\u0005\u001a\u0004\u0018\u00010\u00062\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\nH\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u000b\u0010\f\u001aF\u0010\r\u001a\u00020\u000e2\b\u0010\u000f\u001a\u0004\u0018\u00010\u00022\u0012\u0010\u0010\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00020\u00120\u00112\u001e\u0010\u0013\u001a\u001a\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0015\u0012\u0004\u0012\u00020\u0015\u0012\u0004\u0012\u00020\u000e0\u0014H\u0000\u001a-\u0010\u0016\u001a\u00020\u00172\u0006\u0010\u0018\u001a\u00020\b2\u0006\u0010\u0019\u001a\u00020\u00172\u0006\u0010\t\u001a\u00020\nH\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001a\u0010\u001b\u001a\f\u0010\u001c\u001a\u00020\u0001*\u00020\u001dH\u0002\u001a\u0016\u0010\u001e\u001a\u00020\u0002*\u0004\u0018\u00010\u00022\u0006\u0010\u001f\u001a\u00020\u0002H\u0002\u001a1\u0010 \u001a\u00020\u000e*\u00020!2\u0006\u0010\"\u001a\u00020#2\u0006\u0010$\u001a\u00020\u00152\u0006\u0010%\u001a\u00020\u0015H\u0000ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b&\u0010'\u001a1\u0010(\u001a\u00020\u000e*\u00020!2\b\u0010)\u001a\u0004\u0018\u00010*2\u0006\u0010$\u001a\u00020\u00152\u0006\u0010%\u001a\u00020\u0015H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0002\b+\u001a.\u0010,\u001a\u00020\u000e*\u00020!2\b\u0010-\u001a\u0004\u0018\u00010.2\u0006\u0010/\u001a\u00020\u00172\u0006\u0010$\u001a\u00020\u00152\u0006\u0010%\u001a\u00020\u0015H\u0002\u001a1\u00100\u001a\u00020\u000e*\u00020!2\u0006\u0010\"\u001a\u00020#2\u0006\u0010$\u001a\u00020\u00152\u0006\u0010%\u001a\u00020\u0015H\u0000ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b1\u0010'\u001a&\u00102\u001a\u00020\u000e*\u00020!2\b\u00103\u001a\u0004\u0018\u0001042\u0006\u0010$\u001a\u00020\u00152\u0006\u0010%\u001a\u00020\u0015H\u0002\u001aS\u00105\u001a\u00020\u000e*\u00020!2\u0006\u00106\u001a\u00020\u001d2\u0012\u0010\u0010\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00020\u00120\u00112&\u00107\u001a\"\u0012\u0006\u0012\u0004\u0018\u000109\u0012\u0004\u0012\u00020:\u0012\u0004\u0012\u00020;\u0012\u0004\u0012\u00020<\u0012\u0004\u0012\u00020=08H\u0002ø\u0001\u0001\u001a&\u0010>\u001a\u00020\u000e*\u00020!2\b\u0010?\u001a\u0004\u0018\u00010@2\u0006\u0010$\u001a\u00020\u00152\u0006\u0010%\u001a\u00020\u0015H\u0002\u001a9\u0010A\u001a\u00020\u000e*\u00020!2\u0006\u0010B\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\n2\u0006\u0010$\u001a\u00020\u00152\u0006\u0010%\u001a\u00020\u0015H\u0000ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\bC\u0010D\u001a&\u0010E\u001a\u00020\u000e*\u00020!2\b\u0010F\u001a\u0004\u0018\u00010G2\u0006\u0010$\u001a\u00020\u00152\u0006\u0010%\u001a\u00020\u0015H\u0002\u001a1\u0010H\u001a\u00020\u000e*\u00020!2\u0006\u0010\u0018\u001a\u00020\b2\u0006\u0010\u0019\u001a\u00020\u00172\u0006\u0010\t\u001a\u00020\nH\u0000ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\bI\u0010J\u001a9\u0010H\u001a\u00020\u000e*\u00020!2\u0006\u0010\u0018\u001a\u00020\b2\u0006\u0010\u0019\u001a\u00020\u00172\u0006\u0010\t\u001a\u00020\n2\u0006\u0010K\u001a\u00020LH\u0000ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\bM\u0010N\u001a&\u0010O\u001a\u00020\u000e*\u00020!2\b\u0010P\u001a\u0004\u0018\u00010Q2\u0006\u0010$\u001a\u00020\u00152\u0006\u0010%\u001a\u00020\u0015H\u0000\u001a&\u0010R\u001a\u00020\u000e*\u00020!2\b\u0010S\u001a\u0004\u0018\u00010T2\u0006\u0010$\u001a\u00020\u00152\u0006\u0010%\u001a\u00020\u0015H\u0002\u001a$\u0010U\u001a\u00020\u000e*\u00020!2\u0006\u0010V\u001a\u00020W2\u0006\u0010$\u001a\u00020\u00152\u0006\u0010%\u001a\u00020\u0015H\u0000\u001a\"\u0010X\u001a\u00020\u000e*\u00020!2\f\u0010Y\u001a\b\u0012\u0004\u0012\u00020\u00020\u00122\u0006\u0010\t\u001a\u00020\nH\u0002\u001a[\u0010Z\u001a\u00020\u000e*\u00020!2\u0006\u00106\u001a\u00020\u001d2\u0012\u0010\u0010\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00020\u00120\u00112\u0006\u0010\t\u001a\u00020\n2&\u00107\u001a\"\u0012\u0006\u0012\u0004\u0018\u000109\u0012\u0004\u0012\u00020:\u0012\u0004\u0012\u00020;\u0012\u0004\u0012\u00020<\u0012\u0004\u0012\u00020=08H\u0000ø\u0001\u0001\u001a&\u0010[\u001a\u00020\u000e*\u00020!2\b\u0010\\\u001a\u0004\u0018\u00010]2\u0006\u0010$\u001a\u00020\u00152\u0006\u0010%\u001a\u00020\u0015H\u0000\u001a&\u0010^\u001a\u00020\u000e*\u00020!2\b\u0010_\u001a\u0004\u0018\u00010`2\u0006\u0010\u0019\u001a\u00020\u00172\u0006\u0010\t\u001a\u00020\nH\u0000\"\u0018\u0010\u0000\u001a\u00020\u0001*\u00020\u00028BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u0003\u0010\u0004\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006a"}, d2 = {"needsLetterSpacingSpan", "", "Landroidx/compose/ui/text/SpanStyle;", "getNeedsLetterSpacingSpan", "(Landroidx/compose/ui/text/SpanStyle;)Z", "createLetterSpacingSpan", "Landroid/text/style/MetricAffectingSpan;", "letterSpacing", "Landroidx/compose/ui/unit/TextUnit;", "density", "Landroidx/compose/ui/unit/Density;", "createLetterSpacingSpan-eAf_CNQ", "(JLandroidx/compose/ui/unit/Density;)Landroid/text/style/MetricAffectingSpan;", "flattenFontStylesAndApply", "", "contextFontSpanStyle", "spanStyles", "", "Landroidx/compose/ui/text/AnnotatedString$Range;", "block", "Lkotlin/Function3;", "", "resolveLineHeightInPx", "", "lineHeight", "contextFontSize", "resolveLineHeightInPx-o2QH7mI", "(JFLandroidx/compose/ui/unit/Density;)F", "hasFontAttributes", "Landroidx/compose/ui/text/TextStyle;", "merge", "spanStyle", "setBackground", "Landroid/text/Spannable;", "color", "Landroidx/compose/ui/graphics/Color;", "start", "end", "setBackground-RPmYEkk", "(Landroid/text/Spannable;JII)V", "setBaselineShift", "baselineShift", "Landroidx/compose/ui/text/style/BaselineShift;", "setBaselineShift-0ocSgnM", "setBrush", "brush", "Landroidx/compose/ui/graphics/Brush;", "alpha", "setColor", "setColor-RPmYEkk", "setDrawStyle", "drawStyle", "Landroidx/compose/ui/graphics/drawscope/DrawStyle;", "setFontAttributes", "contextTextStyle", "resolveTypeface", "Lkotlin/Function4;", "Landroidx/compose/ui/text/font/FontFamily;", "Landroidx/compose/ui/text/font/FontWeight;", "Landroidx/compose/ui/text/font/FontStyle;", "Landroidx/compose/ui/text/font/FontSynthesis;", "Landroid/graphics/Typeface;", "setFontFeatureSettings", "fontFeatureSettings", "", "setFontSize", "fontSize", "setFontSize-KmRG4DE", "(Landroid/text/Spannable;JLandroidx/compose/ui/unit/Density;II)V", "setGeometricTransform", "textGeometricTransform", "Landroidx/compose/ui/text/style/TextGeometricTransform;", "setLineHeight", "setLineHeight-r9BaKPg", "(Landroid/text/Spannable;JFLandroidx/compose/ui/unit/Density;)V", "lineHeightStyle", "Landroidx/compose/ui/text/style/LineHeightStyle;", "setLineHeight-KmRG4DE", "(Landroid/text/Spannable;JFLandroidx/compose/ui/unit/Density;Landroidx/compose/ui/text/style/LineHeightStyle;)V", "setLocaleList", "localeList", "Landroidx/compose/ui/text/intl/LocaleList;", "setShadow", "shadow", "Landroidx/compose/ui/graphics/Shadow;", "setSpan", "span", "", "setSpanStyle", "spanStyleRange", "setSpanStyles", "setTextDecoration", "textDecoration", "Landroidx/compose/ui/text/style/TextDecoration;", "setTextIndent", "textIndent", "Landroidx/compose/ui/text/style/TextIndent;", "ui-text_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class SpannableExtensions_androidKt {
    public static final void setSpan(Spannable $this$setSpan, Object span, int start, int end) {
        Intrinsics.checkNotNullParameter($this$setSpan, "<this>");
        Intrinsics.checkNotNullParameter(span, "span");
        $this$setSpan.setSpan(span, start, end, 33);
    }

    public static final void setTextIndent(Spannable $this$setTextIndent, TextIndent textIndent, float contextFontSize, Density density) {
        float firstLine;
        Intrinsics.checkNotNullParameter($this$setTextIndent, "<this>");
        Intrinsics.checkNotNullParameter(density, "density");
        if (textIndent != null) {
            if ((!TextUnit.m5300equalsimpl0(textIndent.m5016getFirstLineXSAIIZE(), TextUnitKt.getSp(0)) || !TextUnit.m5300equalsimpl0(textIndent.m5017getRestLineXSAIIZE(), TextUnitKt.getSp(0))) && !TextUnitKt.m5321isUnspecifiedR2X_6o(textIndent.m5016getFirstLineXSAIIZE()) && !TextUnitKt.m5321isUnspecifiedR2X_6o(textIndent.m5017getRestLineXSAIIZE())) {
                long m5302getTypeUIouoOA = TextUnit.m5302getTypeUIouoOA(textIndent.m5016getFirstLineXSAIIZE());
                float f = 0.0f;
                if (TextUnitType.m5331equalsimpl0(m5302getTypeUIouoOA, TextUnitType.Companion.m5336getSpUIouoOA())) {
                    firstLine = density.mo300toPxR2X_6o(textIndent.m5016getFirstLineXSAIIZE());
                } else {
                    firstLine = TextUnitType.m5331equalsimpl0(m5302getTypeUIouoOA, TextUnitType.Companion.m5335getEmUIouoOA()) ? TextUnit.m5303getValueimpl(textIndent.m5016getFirstLineXSAIIZE()) * contextFontSize : 0.0f;
                }
                long m5302getTypeUIouoOA2 = TextUnit.m5302getTypeUIouoOA(textIndent.m5017getRestLineXSAIIZE());
                if (TextUnitType.m5331equalsimpl0(m5302getTypeUIouoOA2, TextUnitType.Companion.m5336getSpUIouoOA())) {
                    f = density.mo300toPxR2X_6o(textIndent.m5017getRestLineXSAIIZE());
                } else if (TextUnitType.m5331equalsimpl0(m5302getTypeUIouoOA2, TextUnitType.Companion.m5335getEmUIouoOA())) {
                    f = TextUnit.m5303getValueimpl(textIndent.m5017getRestLineXSAIIZE()) * contextFontSize;
                }
                float restLine = f;
                setSpan($this$setTextIndent, new LeadingMarginSpan.Standard((int) Math.ceil(firstLine), (int) Math.ceil(restLine)), 0, $this$setTextIndent.length());
            }
        }
    }

    /* renamed from: setLineHeight-KmRG4DE  reason: not valid java name */
    public static final void m4876setLineHeightKmRG4DE(Spannable setLineHeight, long lineHeight, float contextFontSize, Density density, LineHeightStyle lineHeightStyle) {
        Intrinsics.checkNotNullParameter(setLineHeight, "$this$setLineHeight");
        Intrinsics.checkNotNullParameter(density, "density");
        Intrinsics.checkNotNullParameter(lineHeightStyle, "lineHeightStyle");
        float resolvedLineHeight = m4871resolveLineHeightInPxo2QH7mI(lineHeight, contextFontSize, density);
        if (!Float.isNaN(resolvedLineHeight)) {
            int endIndex = ((setLineHeight.length() == 0) || StringsKt.last(setLineHeight) == '\n') ? setLineHeight.length() + 1 : setLineHeight.length();
            setSpan(setLineHeight, new LineHeightStyleSpan(resolvedLineHeight, 0, endIndex, LineHeightStyle.Trim.m4979isTrimFirstLineTopimpl$ui_text_release(lineHeightStyle.m4958getTrimEVpEnUU()), LineHeightStyle.Trim.m4980isTrimLastLineBottomimpl$ui_text_release(lineHeightStyle.m4958getTrimEVpEnUU()), lineHeightStyle.m4957getAlignmentPIaL0Z0()), 0, setLineHeight.length());
        }
    }

    /* renamed from: setLineHeight-r9BaKPg  reason: not valid java name */
    public static final void m4877setLineHeightr9BaKPg(Spannable setLineHeight, long lineHeight, float contextFontSize, Density density) {
        Intrinsics.checkNotNullParameter(setLineHeight, "$this$setLineHeight");
        Intrinsics.checkNotNullParameter(density, "density");
        float resolvedLineHeight = m4871resolveLineHeightInPxo2QH7mI(lineHeight, contextFontSize, density);
        if (!Float.isNaN(resolvedLineHeight)) {
            setSpan(setLineHeight, new LineHeightSpan(resolvedLineHeight), 0, setLineHeight.length());
        }
    }

    /* renamed from: resolveLineHeightInPx-o2QH7mI  reason: not valid java name */
    private static final float m4871resolveLineHeightInPxo2QH7mI(long lineHeight, float contextFontSize, Density density) {
        long m5302getTypeUIouoOA = TextUnit.m5302getTypeUIouoOA(lineHeight);
        if (TextUnitType.m5331equalsimpl0(m5302getTypeUIouoOA, TextUnitType.Companion.m5336getSpUIouoOA())) {
            return density.mo300toPxR2X_6o(lineHeight);
        }
        if (TextUnitType.m5331equalsimpl0(m5302getTypeUIouoOA, TextUnitType.Companion.m5335getEmUIouoOA())) {
            return TextUnit.m5303getValueimpl(lineHeight) * contextFontSize;
        }
        return Float.NaN;
    }

    public static final void setSpanStyles(Spannable $this$setSpanStyles, TextStyle contextTextStyle, List<AnnotatedString.Range<SpanStyle>> spanStyles, Density density, Function4<? super FontFamily, ? super FontWeight, ? super FontStyle, ? super FontSynthesis, ? extends Typeface> resolveTypeface) {
        MetricAffectingSpan it;
        Intrinsics.checkNotNullParameter($this$setSpanStyles, "<this>");
        Intrinsics.checkNotNullParameter(contextTextStyle, "contextTextStyle");
        Intrinsics.checkNotNullParameter(spanStyles, "spanStyles");
        Intrinsics.checkNotNullParameter(density, "density");
        Intrinsics.checkNotNullParameter(resolveTypeface, "resolveTypeface");
        setFontAttributes($this$setSpanStyles, contextTextStyle, spanStyles, resolveTypeface);
        boolean hasLetterSpacing = false;
        int size = spanStyles.size();
        for (int i = 0; i < size; i++) {
            AnnotatedString.Range spanStyleRange = spanStyles.get(i);
            int start = spanStyleRange.getStart();
            int end = spanStyleRange.getEnd();
            if (start >= 0 && start < $this$setSpanStyles.length() && end > start && end <= $this$setSpanStyles.length()) {
                setSpanStyle($this$setSpanStyles, spanStyleRange, density);
                if (getNeedsLetterSpacingSpan(spanStyleRange.getItem())) {
                    hasLetterSpacing = true;
                }
            }
        }
        if (hasLetterSpacing) {
            int size2 = spanStyles.size();
            for (int i2 = 0; i2 < size2; i2++) {
                AnnotatedString.Range spanStyleRange2 = spanStyles.get(i2);
                int start2 = spanStyleRange2.getStart();
                int end2 = spanStyleRange2.getEnd();
                SpanStyle style = spanStyleRange2.getItem();
                if (start2 >= 0 && start2 < $this$setSpanStyles.length() && end2 > start2 && end2 <= $this$setSpanStyles.length() && (it = m4870createLetterSpacingSpaneAf_CNQ(style.m4601getLetterSpacingXSAIIZE(), density)) != null) {
                    setSpan($this$setSpanStyles, it, start2, end2);
                }
            }
        }
    }

    private static final void setSpanStyle(Spannable $this$setSpanStyle, AnnotatedString.Range<SpanStyle> range, Density density) {
        int start = range.getStart();
        int end = range.getEnd();
        SpanStyle style = range.getItem();
        m4873setBaselineShift0ocSgnM($this$setSpanStyle, style.m4596getBaselineShift5SSeXJ0(), start, end);
        m4874setColorRPmYEkk($this$setSpanStyle, style.m4597getColor0d7_KjU(), start, end);
        setBrush($this$setSpanStyle, style.getBrush(), style.getAlpha(), start, end);
        setTextDecoration($this$setSpanStyle, style.getTextDecoration(), start, end);
        m4875setFontSizeKmRG4DE($this$setSpanStyle, style.m4598getFontSizeXSAIIZE(), density, start, end);
        setFontFeatureSettings($this$setSpanStyle, style.getFontFeatureSettings(), start, end);
        setGeometricTransform($this$setSpanStyle, style.getTextGeometricTransform(), start, end);
        setLocaleList($this$setSpanStyle, style.getLocaleList(), start, end);
        m4872setBackgroundRPmYEkk($this$setSpanStyle, style.m4595getBackground0d7_KjU(), start, end);
        setShadow($this$setSpanStyle, style.getShadow(), start, end);
        setDrawStyle($this$setSpanStyle, style.getDrawStyle(), start, end);
    }

    private static final void setFontAttributes(final Spannable $this$setFontAttributes, TextStyle contextTextStyle, List<AnnotatedString.Range<SpanStyle>> list, final Function4<? super FontFamily, ? super FontWeight, ? super FontStyle, ? super FontSynthesis, ? extends Typeface> function4) {
        SpanStyle contextFontSpanStyle;
        List target$iv = new ArrayList(list.size());
        int size = list.size();
        for (int index$iv$iv = 0; index$iv$iv < size; index$iv$iv++) {
            AnnotatedString.Range range = list.get(index$iv$iv);
            AnnotatedString.Range it = range;
            if (TextPaintExtensions_androidKt.hasFontAttributes(it.getItem()) || it.getItem().m4600getFontSynthesisZQGJjVo() != null) {
                target$iv.add(range);
            }
        }
        List fontRelatedSpanStyles = target$iv;
        if (hasFontAttributes(contextTextStyle)) {
            contextFontSpanStyle = new SpanStyle(0L, 0L, contextTextStyle.getFontWeight(), contextTextStyle.m4659getFontStyle4Lr2A7w(), contextTextStyle.m4660getFontSynthesisZQGJjVo(), contextTextStyle.getFontFamily(), (String) null, 0L, (BaselineShift) null, (TextGeometricTransform) null, (LocaleList) null, 0L, (TextDecoration) null, (Shadow) null, 16323, (DefaultConstructorMarker) null);
        } else {
            contextFontSpanStyle = null;
        }
        flattenFontStylesAndApply(contextFontSpanStyle, fontRelatedSpanStyles, new Function3<SpanStyle, Integer, Integer, Unit>() { // from class: androidx.compose.ui.text.platform.extensions.SpannableExtensions_androidKt$setFontAttributes$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(3);
            }

            @Override // kotlin.jvm.functions.Function3
            public /* bridge */ /* synthetic */ Unit invoke(SpanStyle spanStyle, Integer num, Integer num2) {
                invoke(spanStyle, num.intValue(), num2.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(SpanStyle spanStyle, int start, int end) {
                Intrinsics.checkNotNullParameter(spanStyle, "spanStyle");
                Spannable spannable = $this$setFontAttributes;
                Function4<FontFamily, FontWeight, FontStyle, FontSynthesis, Typeface> function42 = function4;
                FontFamily fontFamily = spanStyle.getFontFamily();
                FontWeight fontWeight = spanStyle.getFontWeight();
                if (fontWeight == null) {
                    fontWeight = FontWeight.Companion.getNormal();
                }
                FontStyle m4599getFontStyle4Lr2A7w = spanStyle.m4599getFontStyle4Lr2A7w();
                FontStyle m4719boximpl = FontStyle.m4719boximpl(m4599getFontStyle4Lr2A7w != null ? m4599getFontStyle4Lr2A7w.m4725unboximpl() : FontStyle.Companion.m4727getNormal_LCdwA());
                FontSynthesis m4600getFontSynthesisZQGJjVo = spanStyle.m4600getFontSynthesisZQGJjVo();
                spannable.setSpan(new TypefaceSpan(function42.invoke(fontFamily, fontWeight, m4719boximpl, FontSynthesis.m4728boximpl(m4600getFontSynthesisZQGJjVo != null ? m4600getFontSynthesisZQGJjVo.m4736unboximpl() : FontSynthesis.Companion.m4737getAllGVVA2EU()))), start, end, 33);
            }
        });
    }

    public static final void flattenFontStylesAndApply(SpanStyle contextFontSpanStyle, List<AnnotatedString.Range<SpanStyle>> spanStyles, Function3<? super SpanStyle, ? super Integer, ? super Integer, Unit> block) {
        int spanCount;
        Intrinsics.checkNotNullParameter(spanStyles, "spanStyles");
        Intrinsics.checkNotNullParameter(block, "block");
        int i = 0;
        if (spanStyles.size() <= 1) {
            if (!spanStyles.isEmpty()) {
                block.invoke(merge(contextFontSpanStyle, spanStyles.get(0).getItem()), Integer.valueOf(spanStyles.get(0).getStart()), Integer.valueOf(spanStyles.get(0).getEnd()));
                return;
            }
            return;
        }
        int spanCount2 = spanStyles.size();
        int i2 = spanCount2 * 2;
        Integer[] transitionOffsets = new Integer[i2];
        for (int i3 = 0; i3 < i2; i3++) {
            transitionOffsets[i3] = 0;
        }
        int size = spanStyles.size();
        for (int index$iv = 0; index$iv < size; index$iv++) {
            AnnotatedString.Range item$iv = spanStyles.get(index$iv);
            AnnotatedString.Range spanStyle = item$iv;
            int idx = index$iv;
            transitionOffsets[idx] = Integer.valueOf(spanStyle.getStart());
            transitionOffsets[idx + spanCount2] = Integer.valueOf(spanStyle.getEnd());
        }
        ArraysKt.sort((Object[]) transitionOffsets);
        int lastTransitionOffsets = ((Number) ArraysKt.first(transitionOffsets)).intValue();
        int length = transitionOffsets.length;
        while (i < length) {
            int transitionOffset = transitionOffsets[i].intValue();
            if (transitionOffset == lastTransitionOffsets) {
                spanCount = spanCount2;
            } else {
                SpanStyle spanStyle2 = contextFontSpanStyle;
                int index$iv2 = 0;
                int size2 = spanStyles.size();
                while (index$iv2 < size2) {
                    AnnotatedString.Range item$iv2 = spanStyles.get(index$iv2);
                    AnnotatedString.Range spanStyle3 = item$iv2;
                    int spanCount3 = spanCount2;
                    if (spanStyle3.getStart() != spanStyle3.getEnd() && AnnotatedStringKt.intersect(lastTransitionOffsets, transitionOffset, spanStyle3.getStart(), spanStyle3.getEnd())) {
                        spanStyle2 = merge(spanStyle2, spanStyle3.getItem());
                    }
                    index$iv2++;
                    spanCount2 = spanCount3;
                }
                spanCount = spanCount2;
                if (spanStyle2 != null) {
                    SpanStyle it = spanStyle2;
                    block.invoke(it, Integer.valueOf(lastTransitionOffsets), Integer.valueOf(transitionOffset));
                }
                lastTransitionOffsets = transitionOffset;
            }
            i++;
            spanCount2 = spanCount;
        }
    }

    /* renamed from: createLetterSpacingSpan-eAf_CNQ  reason: not valid java name */
    private static final MetricAffectingSpan m4870createLetterSpacingSpaneAf_CNQ(long letterSpacing, Density density) {
        long m5302getTypeUIouoOA = TextUnit.m5302getTypeUIouoOA(letterSpacing);
        if (TextUnitType.m5331equalsimpl0(m5302getTypeUIouoOA, TextUnitType.Companion.m5336getSpUIouoOA())) {
            return new LetterSpacingSpanPx(density.mo300toPxR2X_6o(letterSpacing));
        }
        if (TextUnitType.m5331equalsimpl0(m5302getTypeUIouoOA, TextUnitType.Companion.m5335getEmUIouoOA())) {
            return new LetterSpacingSpanEm(TextUnit.m5303getValueimpl(letterSpacing));
        }
        return null;
    }

    private static final boolean getNeedsLetterSpacingSpan(SpanStyle $this$needsLetterSpacingSpan) {
        return TextUnitType.m5331equalsimpl0(TextUnit.m5302getTypeUIouoOA($this$needsLetterSpacingSpan.m4601getLetterSpacingXSAIIZE()), TextUnitType.Companion.m5336getSpUIouoOA()) || TextUnitType.m5331equalsimpl0(TextUnit.m5302getTypeUIouoOA($this$needsLetterSpacingSpan.m4601getLetterSpacingXSAIIZE()), TextUnitType.Companion.m5335getEmUIouoOA());
    }

    private static final void setShadow(Spannable $this$setShadow, Shadow shadow, int start, int end) {
        if (shadow != null) {
            setSpan($this$setShadow, new ShadowSpan(ColorKt.m2660toArgb8_81llA(shadow.m2921getColor0d7_KjU()), Offset.m2368getXimpl(shadow.m2922getOffsetF1C5BW0()), Offset.m2369getYimpl(shadow.m2922getOffsetF1C5BW0()), TextPaintExtensions_androidKt.correctBlurRadius(shadow.getBlurRadius())), start, end);
        }
    }

    private static final void setDrawStyle(Spannable $this$setDrawStyle, DrawStyle drawStyle, int start, int end) {
        if (drawStyle != null) {
            setSpan($this$setDrawStyle, new DrawStyleSpan(drawStyle), start, end);
        }
    }

    /* renamed from: setBackground-RPmYEkk  reason: not valid java name */
    public static final void m4872setBackgroundRPmYEkk(Spannable setBackground, long color, int start, int end) {
        Intrinsics.checkNotNullParameter(setBackground, "$this$setBackground");
        if (color != Color.Companion.m2642getUnspecified0d7_KjU()) {
            setSpan(setBackground, new BackgroundColorSpan(ColorKt.m2660toArgb8_81llA(color)), start, end);
        }
    }

    public static final void setLocaleList(Spannable $this$setLocaleList, LocaleList localeList, int start, int end) {
        Intrinsics.checkNotNullParameter($this$setLocaleList, "<this>");
        if (localeList != null) {
            setSpan($this$setLocaleList, LocaleListHelperMethods.INSTANCE.localeSpan(localeList), start, end);
        }
    }

    private static final void setGeometricTransform(Spannable $this$setGeometricTransform, TextGeometricTransform textGeometricTransform, int start, int end) {
        if (textGeometricTransform != null) {
            setSpan($this$setGeometricTransform, new ScaleXSpan(textGeometricTransform.getScaleX()), start, end);
            setSpan($this$setGeometricTransform, new SkewXSpan(textGeometricTransform.getSkewX()), start, end);
        }
    }

    private static final void setFontFeatureSettings(Spannable $this$setFontFeatureSettings, String fontFeatureSettings, int start, int end) {
        if (fontFeatureSettings != null) {
            setSpan($this$setFontFeatureSettings, new FontFeatureSpan(fontFeatureSettings), start, end);
        }
    }

    /* renamed from: setFontSize-KmRG4DE  reason: not valid java name */
    public static final void m4875setFontSizeKmRG4DE(Spannable setFontSize, long fontSize, Density density, int start, int end) {
        Intrinsics.checkNotNullParameter(setFontSize, "$this$setFontSize");
        Intrinsics.checkNotNullParameter(density, "density");
        long m5302getTypeUIouoOA = TextUnit.m5302getTypeUIouoOA(fontSize);
        if (TextUnitType.m5331equalsimpl0(m5302getTypeUIouoOA, TextUnitType.Companion.m5336getSpUIouoOA())) {
            setSpan(setFontSize, new AbsoluteSizeSpan(MathKt.roundToInt(density.mo300toPxR2X_6o(fontSize)), false), start, end);
        } else if (TextUnitType.m5331equalsimpl0(m5302getTypeUIouoOA, TextUnitType.Companion.m5335getEmUIouoOA())) {
            setSpan(setFontSize, new RelativeSizeSpan(TextUnit.m5303getValueimpl(fontSize)), start, end);
        }
    }

    public static final void setTextDecoration(Spannable $this$setTextDecoration, TextDecoration textDecoration, int start, int end) {
        Intrinsics.checkNotNullParameter($this$setTextDecoration, "<this>");
        if (textDecoration != null) {
            TextDecorationSpan textDecorationSpan = new TextDecorationSpan(textDecoration.contains(TextDecoration.Companion.getUnderline()), textDecoration.contains(TextDecoration.Companion.getLineThrough()));
            setSpan($this$setTextDecoration, textDecorationSpan, start, end);
        }
    }

    /* renamed from: setColor-RPmYEkk  reason: not valid java name */
    public static final void m4874setColorRPmYEkk(Spannable setColor, long color, int start, int end) {
        Intrinsics.checkNotNullParameter(setColor, "$this$setColor");
        if (color != Color.Companion.m2642getUnspecified0d7_KjU()) {
            setSpan(setColor, new ForegroundColorSpan(ColorKt.m2660toArgb8_81llA(color)), start, end);
        }
    }

    /* renamed from: setBaselineShift-0ocSgnM  reason: not valid java name */
    private static final void m4873setBaselineShift0ocSgnM(Spannable $this$setBaselineShift_u2d0ocSgnM, BaselineShift baselineShift, int start, int end) {
        if (baselineShift != null) {
            float it = baselineShift.m4889unboximpl();
            setSpan($this$setBaselineShift_u2d0ocSgnM, new BaselineShiftSpan(it), start, end);
        }
    }

    private static final void setBrush(Spannable $this$setBrush, Brush brush, float alpha, int start, int end) {
        if (brush != null) {
            if (brush instanceof SolidColor) {
                m4874setColorRPmYEkk($this$setBrush, ((SolidColor) brush).m2931getValue0d7_KjU(), start, end);
            } else if (brush instanceof ShaderBrush) {
                setSpan($this$setBrush, new ShaderBrushSpan((ShaderBrush) brush, alpha), start, end);
            }
        }
    }

    private static final boolean hasFontAttributes(TextStyle $this$hasFontAttributes) {
        return TextPaintExtensions_androidKt.hasFontAttributes($this$hasFontAttributes.toSpanStyle()) || $this$hasFontAttributes.m4660getFontSynthesisZQGJjVo() != null;
    }

    private static final SpanStyle merge(SpanStyle $this$merge, SpanStyle spanStyle) {
        return $this$merge == null ? spanStyle : $this$merge.merge(spanStyle);
    }
}
