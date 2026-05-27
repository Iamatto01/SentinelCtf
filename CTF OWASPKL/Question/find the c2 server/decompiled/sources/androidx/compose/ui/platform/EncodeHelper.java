package androidx.compose.ui.platform;

import android.os.Parcel;
import android.util.Base64;
import androidx.compose.ui.geometry.Offset;
import androidx.compose.ui.graphics.Color;
import androidx.compose.ui.graphics.Shadow;
import androidx.compose.ui.text.SpanStyle;
import androidx.compose.ui.text.font.FontStyle;
import androidx.compose.ui.text.font.FontSynthesis;
import androidx.compose.ui.text.font.FontWeight;
import androidx.compose.ui.text.style.BaselineShift;
import androidx.compose.ui.text.style.TextDecoration;
import androidx.compose.ui.text.style.TextGeometricTransform;
import androidx.compose.ui.unit.TextUnit;
import androidx.compose.ui.unit.TextUnitType;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: AndroidClipboardManager.android.kt */
@Metadata(d1 = {"\u0000~\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\u0007\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\b\u0000\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u001b\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\bø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\t\u0010\nJ\u000e\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u000b\u001a\u00020\fJ\u000e\u0010\u0005\u001a\u00020\u00062\u0006\u0010\r\u001a\u00020\u000eJ\u001b\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u000f\u001a\u00020\u0010ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0011\u0010\u0012J\u001b\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0013\u001a\u00020\u0014ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0015\u0010\u0012J\u000e\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0016\u001a\u00020\u0017J\u001b\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0018\u001a\u00020\u0019ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001a\u0010\u001bJ\u000e\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u001c\u001a\u00020\u001dJ\u000e\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u001e\u001a\u00020\u001fJ\u001b\u0010\u0005\u001a\u00020\u00062\u0006\u0010 \u001a\u00020!ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\"\u0010\nJ\u000e\u0010\u0005\u001a\u00020\u00062\u0006\u0010#\u001a\u00020$J\u000e\u0010\u0005\u001a\u00020\u00062\u0006\u0010%\u001a\u00020&J\u000e\u0010\u0005\u001a\u00020\u00062\u0006\u0010'\u001a\u00020(J\u000e\u0010\u0005\u001a\u00020\u00062\u0006\u0010)\u001a\u00020*J\u001b\u0010\u0005\u001a\u00020\u00062\u0006\u0010+\u001a\u00020,ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b-\u0010\nJ\u0006\u0010.\u001a\u00020*J\u0006\u0010/\u001a\u00020\u0006R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082\u000e¢\u0006\u0002\n\u0000\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u00060"}, d2 = {"Landroidx/compose/ui/platform/EncodeHelper;", "", "()V", "parcel", "Landroid/os/Parcel;", "encode", "", "color", "Landroidx/compose/ui/graphics/Color;", "encode-8_81llA", "(J)V", "shadow", "Landroidx/compose/ui/graphics/Shadow;", "spanStyle", "Landroidx/compose/ui/text/SpanStyle;", "fontStyle", "Landroidx/compose/ui/text/font/FontStyle;", "encode-nzbMABs", "(I)V", "fontSynthesis", "Landroidx/compose/ui/text/font/FontSynthesis;", "encode-6p3vJLY", "fontWeight", "Landroidx/compose/ui/text/font/FontWeight;", "baselineShift", "Landroidx/compose/ui/text/style/BaselineShift;", "encode-4Dl_Bck", "(F)V", "textDecoration", "Landroidx/compose/ui/text/style/TextDecoration;", "textGeometricTransform", "Landroidx/compose/ui/text/style/TextGeometricTransform;", "textUnit", "Landroidx/compose/ui/unit/TextUnit;", "encode--R2X_6o", "byte", "", "float", "", "int", "", "string", "", "uLong", "Lkotlin/ULong;", "encode-VKZWuLQ", "encodedString", "reset", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class EncodeHelper {
    private Parcel parcel;

    public EncodeHelper() {
        Parcel obtain = Parcel.obtain();
        Intrinsics.checkNotNullExpressionValue(obtain, "obtain()");
        this.parcel = obtain;
    }

    public final void reset() {
        this.parcel.recycle();
        Parcel obtain = Parcel.obtain();
        Intrinsics.checkNotNullExpressionValue(obtain, "obtain()");
        this.parcel = obtain;
    }

    public final String encodedString() {
        byte[] bytes = this.parcel.marshall();
        String encodeToString = Base64.encodeToString(bytes, 0);
        Intrinsics.checkNotNullExpressionValue(encodeToString, "encodeToString(bytes, Base64.DEFAULT)");
        return encodeToString;
    }

    public final void encode(SpanStyle spanStyle) {
        Intrinsics.checkNotNullParameter(spanStyle, "spanStyle");
        if (!Color.m2607equalsimpl0(spanStyle.m4597getColor0d7_KjU(), Color.Companion.m2642getUnspecified0d7_KjU())) {
            encode((byte) 1);
            m4427encode8_81llA(spanStyle.m4597getColor0d7_KjU());
        }
        if (!TextUnit.m5300equalsimpl0(spanStyle.m4598getFontSizeXSAIIZE(), TextUnit.Companion.m5314getUnspecifiedXSAIIZE())) {
            encode((byte) 2);
            m4424encodeR2X_6o(spanStyle.m4598getFontSizeXSAIIZE());
        }
        FontWeight it = spanStyle.getFontWeight();
        if (it != null) {
            encode((byte) 3);
            encode(it);
        }
        FontStyle m4599getFontStyle4Lr2A7w = spanStyle.m4599getFontStyle4Lr2A7w();
        if (m4599getFontStyle4Lr2A7w != null) {
            int it2 = m4599getFontStyle4Lr2A7w.m4725unboximpl();
            encode((byte) 4);
            m4429encodenzbMABs(it2);
        }
        FontSynthesis m4600getFontSynthesisZQGJjVo = spanStyle.m4600getFontSynthesisZQGJjVo();
        if (m4600getFontSynthesisZQGJjVo != null) {
            int it3 = m4600getFontSynthesisZQGJjVo.m4736unboximpl();
            encode((byte) 5);
            m4426encode6p3vJLY(it3);
        }
        String it4 = spanStyle.getFontFeatureSettings();
        if (it4 != null) {
            encode((byte) 6);
            encode(it4);
        }
        if (!TextUnit.m5300equalsimpl0(spanStyle.m4601getLetterSpacingXSAIIZE(), TextUnit.Companion.m5314getUnspecifiedXSAIIZE())) {
            encode((byte) 7);
            m4424encodeR2X_6o(spanStyle.m4601getLetterSpacingXSAIIZE());
        }
        BaselineShift m4596getBaselineShift5SSeXJ0 = spanStyle.m4596getBaselineShift5SSeXJ0();
        if (m4596getBaselineShift5SSeXJ0 != null) {
            float it5 = m4596getBaselineShift5SSeXJ0.m4889unboximpl();
            encode((byte) 8);
            m4425encode4Dl_Bck(it5);
        }
        TextGeometricTransform it6 = spanStyle.getTextGeometricTransform();
        if (it6 != null) {
            encode((byte) 9);
            encode(it6);
        }
        if (!Color.m2607equalsimpl0(spanStyle.m4595getBackground0d7_KjU(), Color.Companion.m2642getUnspecified0d7_KjU())) {
            encode((byte) 10);
            m4427encode8_81llA(spanStyle.m4595getBackground0d7_KjU());
        }
        TextDecoration it7 = spanStyle.getTextDecoration();
        if (it7 != null) {
            encode((byte) 11);
            encode(it7);
        }
        Shadow it8 = spanStyle.getShadow();
        if (it8 != null) {
            encode((byte) 12);
            encode(it8);
        }
    }

    /* renamed from: encode-8_81llA  reason: not valid java name */
    public final void m4427encode8_81llA(long color) {
        m4428encodeVKZWuLQ(color);
    }

    /* renamed from: encode--R2X_6o  reason: not valid java name */
    public final void m4424encodeR2X_6o(long textUnit) {
        long m5302getTypeUIouoOA = TextUnit.m5302getTypeUIouoOA(textUnit);
        byte b = 0;
        if (!TextUnitType.m5331equalsimpl0(m5302getTypeUIouoOA, TextUnitType.Companion.m5337getUnspecifiedUIouoOA())) {
            if (TextUnitType.m5331equalsimpl0(m5302getTypeUIouoOA, TextUnitType.Companion.m5336getSpUIouoOA())) {
                b = 1;
            } else if (TextUnitType.m5331equalsimpl0(m5302getTypeUIouoOA, TextUnitType.Companion.m5335getEmUIouoOA())) {
                b = 2;
            }
        }
        byte typeCode = b;
        encode(typeCode);
        if (!TextUnitType.m5331equalsimpl0(TextUnit.m5302getTypeUIouoOA(textUnit), TextUnitType.Companion.m5337getUnspecifiedUIouoOA())) {
            encode(TextUnit.m5303getValueimpl(textUnit));
        }
    }

    public final void encode(FontWeight fontWeight) {
        Intrinsics.checkNotNullParameter(fontWeight, "fontWeight");
        encode(fontWeight.getWeight());
    }

    /* renamed from: encode-nzbMABs  reason: not valid java name */
    public final void m4429encodenzbMABs(int fontStyle) {
        byte b = 0;
        if (!FontStyle.m4722equalsimpl0(fontStyle, FontStyle.Companion.m4727getNormal_LCdwA()) && FontStyle.m4722equalsimpl0(fontStyle, FontStyle.Companion.m4726getItalic_LCdwA())) {
            b = 1;
        }
        encode(b);
    }

    /* renamed from: encode-6p3vJLY  reason: not valid java name */
    public final void m4426encode6p3vJLY(int fontSynthesis) {
        byte b = 0;
        if (!FontSynthesis.m4731equalsimpl0(fontSynthesis, FontSynthesis.Companion.m4738getNoneGVVA2EU())) {
            if (FontSynthesis.m4731equalsimpl0(fontSynthesis, FontSynthesis.Companion.m4737getAllGVVA2EU())) {
                b = 1;
            } else if (FontSynthesis.m4731equalsimpl0(fontSynthesis, FontSynthesis.Companion.m4740getWeightGVVA2EU())) {
                b = 2;
            } else if (FontSynthesis.m4731equalsimpl0(fontSynthesis, FontSynthesis.Companion.m4739getStyleGVVA2EU())) {
                b = 3;
            }
        }
        byte value = b;
        encode(value);
    }

    /* renamed from: encode-4Dl_Bck  reason: not valid java name */
    public final void m4425encode4Dl_Bck(float baselineShift) {
        encode(baselineShift);
    }

    public final void encode(TextGeometricTransform textGeometricTransform) {
        Intrinsics.checkNotNullParameter(textGeometricTransform, "textGeometricTransform");
        encode(textGeometricTransform.getScaleX());
        encode(textGeometricTransform.getSkewX());
    }

    public final void encode(TextDecoration textDecoration) {
        Intrinsics.checkNotNullParameter(textDecoration, "textDecoration");
        encode(textDecoration.getMask());
    }

    public final void encode(Shadow shadow) {
        Intrinsics.checkNotNullParameter(shadow, "shadow");
        m4427encode8_81llA(shadow.m2921getColor0d7_KjU());
        encode(Offset.m2368getXimpl(shadow.m2922getOffsetF1C5BW0()));
        encode(Offset.m2369getYimpl(shadow.m2922getOffsetF1C5BW0()));
        encode(shadow.getBlurRadius());
    }

    public final void encode(byte b) {
        this.parcel.writeByte(b);
    }

    public final void encode(int i) {
        this.parcel.writeInt(i);
    }

    public final void encode(float f) {
        this.parcel.writeFloat(f);
    }

    /* renamed from: encode-VKZWuLQ  reason: not valid java name */
    public final void m4428encodeVKZWuLQ(long uLong) {
        this.parcel.writeLong(uLong);
    }

    public final void encode(String string) {
        Intrinsics.checkNotNullParameter(string, "string");
        this.parcel.writeString(string);
    }
}
