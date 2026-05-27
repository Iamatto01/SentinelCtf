package androidx.compose.ui.platform;

import android.os.Parcel;
import android.util.Base64;
import androidx.compose.ui.geometry.OffsetKt;
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
import androidx.compose.ui.unit.TextUnitKt;
import androidx.compose.ui.unit.TextUnitType;
import kotlin.Metadata;
import kotlin.ULong;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: AndroidClipboardManager.android.kt */
@Metadata(d1 = {"\u0000|\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0005\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0000\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\b\u0010\u0007\u001a\u00020\bH\u0002J\u0018\u0010\t\u001a\u00020\nH\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\b\u000b\u0010\fJ\b\u0010\r\u001a\u00020\u000eH\u0002J\u0016\u0010\u000f\u001a\u00020\u0010ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\b\u0011\u0010\u0012J\b\u0010\u0013\u001a\u00020\u0014H\u0002J\u0016\u0010\u0015\u001a\u00020\u0016ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\b\u0017\u0010\u0018J\u0016\u0010\u0019\u001a\u00020\u001aø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\b\u001b\u0010\u0018J\u0006\u0010\u001c\u001a\u00020\u001dJ\b\u0010\u001e\u001a\u00020\bH\u0002J\b\u0010\u001f\u001a\u00020 H\u0002J\u0006\u0010!\u001a\u00020\"J\n\u0010#\u001a\u0004\u0018\u00010\u0003H\u0002J\b\u0010$\u001a\u00020%H\u0002J\b\u0010&\u001a\u00020'H\u0002J\u0016\u0010(\u001a\u00020)ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\b*\u0010\u0012J\u0018\u0010+\u001a\u00020,H\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\b-\u0010\u0012R\u000e\u0010\u0005\u001a\u00020\u0006X\u0082\u0004¢\u0006\u0002\n\u0000\u0082\u0002\u000f\n\u0002\b!\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006."}, d2 = {"Landroidx/compose/ui/platform/DecodeHelper;", "", "string", "", "(Ljava/lang/String;)V", "parcel", "Landroid/os/Parcel;", "dataAvailable", "", "decodeBaselineShift", "Landroidx/compose/ui/text/style/BaselineShift;", "decodeBaselineShift-y9eOQZs", "()F", "decodeByte", "", "decodeColor", "Landroidx/compose/ui/graphics/Color;", "decodeColor-0d7_KjU", "()J", "decodeFloat", "", "decodeFontStyle", "Landroidx/compose/ui/text/font/FontStyle;", "decodeFontStyle-_-LCdwA", "()I", "decodeFontSynthesis", "Landroidx/compose/ui/text/font/FontSynthesis;", "decodeFontSynthesis-GVVA2EU", "decodeFontWeight", "Landroidx/compose/ui/text/font/FontWeight;", "decodeInt", "decodeShadow", "Landroidx/compose/ui/graphics/Shadow;", "decodeSpanStyle", "Landroidx/compose/ui/text/SpanStyle;", "decodeString", "decodeTextDecoration", "Landroidx/compose/ui/text/style/TextDecoration;", "decodeTextGeometricTransform", "Landroidx/compose/ui/text/style/TextGeometricTransform;", "decodeTextUnit", "Landroidx/compose/ui/unit/TextUnit;", "decodeTextUnit-XSAIIZE", "decodeULong", "Lkotlin/ULong;", "decodeULong-s-VKNKU", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class DecodeHelper {
    private final Parcel parcel;

    public DecodeHelper(String string) {
        Intrinsics.checkNotNullParameter(string, "string");
        Parcel obtain = Parcel.obtain();
        Intrinsics.checkNotNullExpressionValue(obtain, "obtain()");
        this.parcel = obtain;
        byte[] bytes = Base64.decode(string, 0);
        obtain.unmarshall(bytes, 0, bytes.length);
        obtain.setDataPosition(0);
    }

    public final SpanStyle decodeSpanStyle() {
        MutableSpanStyle mutableSpanStyle = new MutableSpanStyle(0L, 0L, null, null, null, null, null, 0L, null, null, null, 0L, null, null, 16383, null);
        while (this.parcel.dataAvail() > 1) {
            byte decodeByte = decodeByte();
            if (decodeByte == 1) {
                if (dataAvailable() < 8) {
                    break;
                }
                mutableSpanStyle.m4443setColor8_81llA(m4413decodeColor0d7_KjU());
            } else if (decodeByte == 2) {
                if (dataAvailable() < 5) {
                    break;
                }
                mutableSpanStyle.m4444setFontSizeR2X_6o(m4416decodeTextUnitXSAIIZE());
            } else if (decodeByte == 3) {
                if (dataAvailable() < 4) {
                    break;
                }
                mutableSpanStyle.setFontWeight(decodeFontWeight());
            } else if (decodeByte == 4) {
                if (dataAvailable() < 1) {
                    break;
                }
                mutableSpanStyle.m4445setFontStylemLjRB2g(FontStyle.m4719boximpl(m4414decodeFontStyle_LCdwA()));
            } else if (decodeByte == 5) {
                if (dataAvailable() < 1) {
                    break;
                }
                mutableSpanStyle.m4446setFontSynthesistDdu0R4(FontSynthesis.m4728boximpl(m4415decodeFontSynthesisGVVA2EU()));
            } else if (decodeByte == 6) {
                mutableSpanStyle.setFontFeatureSettings(decodeString());
            } else if (decodeByte == 7) {
                if (dataAvailable() < 5) {
                    break;
                }
                mutableSpanStyle.m4447setLetterSpacingR2X_6o(m4416decodeTextUnitXSAIIZE());
            } else if (decodeByte == 8) {
                if (dataAvailable() < 4) {
                    break;
                }
                mutableSpanStyle.m4442setBaselineShift_isdbwI(BaselineShift.m4883boximpl(m4411decodeBaselineShifty9eOQZs()));
            } else if (decodeByte == 9) {
                if (dataAvailable() < 8) {
                    break;
                }
                mutableSpanStyle.setTextGeometricTransform(decodeTextGeometricTransform());
            } else if (decodeByte == 10) {
                if (dataAvailable() < 8) {
                    break;
                }
                mutableSpanStyle.m4441setBackground8_81llA(m4413decodeColor0d7_KjU());
            } else if (decodeByte == 11) {
                if (dataAvailable() < 4) {
                    break;
                }
                mutableSpanStyle.setTextDecoration(decodeTextDecoration());
            } else if (decodeByte == 12) {
                if (dataAvailable() < 20) {
                    break;
                }
                mutableSpanStyle.setShadow(decodeShadow());
            } else {
                continue;
            }
        }
        return mutableSpanStyle.toSpanStyle();
    }

    /* renamed from: decodeColor-0d7_KjU  reason: not valid java name */
    public final long m4413decodeColor0d7_KjU() {
        return Color.m2602constructorimpl(m4412decodeULongsVKNKU());
    }

    /* renamed from: decodeTextUnit-XSAIIZE  reason: not valid java name */
    public final long m4416decodeTextUnitXSAIIZE() {
        long type;
        byte decodeByte = decodeByte();
        if (decodeByte == 1) {
            type = TextUnitType.Companion.m5336getSpUIouoOA();
        } else {
            type = decodeByte == 2 ? TextUnitType.Companion.m5335getEmUIouoOA() : TextUnitType.Companion.m5337getUnspecifiedUIouoOA();
        }
        if (TextUnitType.m5331equalsimpl0(type, TextUnitType.Companion.m5337getUnspecifiedUIouoOA())) {
            return TextUnit.Companion.m5314getUnspecifiedXSAIIZE();
        }
        float value = decodeFloat();
        return TextUnitKt.m5315TextUnitanM5pPY(value, type);
    }

    public final FontWeight decodeFontWeight() {
        return new FontWeight(decodeInt());
    }

    /* renamed from: decodeFontStyle-_-LCdwA  reason: not valid java name */
    public final int m4414decodeFontStyle_LCdwA() {
        byte decodeByte = decodeByte();
        return decodeByte == 0 ? FontStyle.Companion.m4727getNormal_LCdwA() : decodeByte == 1 ? FontStyle.Companion.m4726getItalic_LCdwA() : FontStyle.Companion.m4727getNormal_LCdwA();
    }

    /* renamed from: decodeFontSynthesis-GVVA2EU  reason: not valid java name */
    public final int m4415decodeFontSynthesisGVVA2EU() {
        byte decodeByte = decodeByte();
        return decodeByte == 0 ? FontSynthesis.Companion.m4738getNoneGVVA2EU() : decodeByte == 1 ? FontSynthesis.Companion.m4737getAllGVVA2EU() : decodeByte == 3 ? FontSynthesis.Companion.m4739getStyleGVVA2EU() : decodeByte == 2 ? FontSynthesis.Companion.m4740getWeightGVVA2EU() : FontSynthesis.Companion.m4738getNoneGVVA2EU();
    }

    /* renamed from: decodeBaselineShift-y9eOQZs  reason: not valid java name */
    private final float m4411decodeBaselineShifty9eOQZs() {
        return BaselineShift.m4884constructorimpl(decodeFloat());
    }

    private final TextGeometricTransform decodeTextGeometricTransform() {
        return new TextGeometricTransform(decodeFloat(), decodeFloat());
    }

    private final TextDecoration decodeTextDecoration() {
        int mask = decodeInt();
        boolean hasLineThrough = (TextDecoration.Companion.getLineThrough().getMask() & mask) != 0;
        boolean hasUnderline = (TextDecoration.Companion.getUnderline().getMask() & mask) != 0;
        if (hasLineThrough && hasUnderline) {
            return TextDecoration.Companion.combine(CollectionsKt.listOf((Object[]) new TextDecoration[]{TextDecoration.Companion.getLineThrough(), TextDecoration.Companion.getUnderline()}));
        }
        if (hasLineThrough) {
            return TextDecoration.Companion.getLineThrough();
        }
        if (hasUnderline) {
            return TextDecoration.Companion.getUnderline();
        }
        return TextDecoration.Companion.getNone();
    }

    private final Shadow decodeShadow() {
        return new Shadow(m4413decodeColor0d7_KjU(), OffsetKt.Offset(decodeFloat(), decodeFloat()), decodeFloat(), null);
    }

    private final byte decodeByte() {
        return this.parcel.readByte();
    }

    private final int decodeInt() {
        return this.parcel.readInt();
    }

    /* renamed from: decodeULong-s-VKNKU  reason: not valid java name */
    private final long m4412decodeULongsVKNKU() {
        return ULong.m5607constructorimpl(this.parcel.readLong());
    }

    private final float decodeFloat() {
        return this.parcel.readFloat();
    }

    private final String decodeString() {
        return this.parcel.readString();
    }

    private final int dataAvailable() {
        return this.parcel.dataAvail();
    }
}
