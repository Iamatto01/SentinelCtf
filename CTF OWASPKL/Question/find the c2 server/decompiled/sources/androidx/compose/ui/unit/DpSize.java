package androidx.compose.ui.unit;

import kotlin.Metadata;
import kotlin.jvm.JvmInline;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.FloatCompanionObject;
/* compiled from: Dp.kt */
@Metadata(d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\t\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0011\n\u0002\u0010\u0007\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\r\n\u0002\u0010\u000e\n\u0002\b\u0004\b\u0087@\u0018\u0000 02\u00020\u0001:\u00010B\u0014\b\u0000\u0012\u0006\u0010\u0002\u001a\u00020\u0003ø\u0001\u0000¢\u0006\u0004\b\u0004\u0010\u0005J\u0019\u0010\u0010\u001a\u00020\u0007H\u0087\nø\u0001\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\u0011\u0010\u000bJ\u0019\u0010\u0012\u001a\u00020\u0007H\u0087\nø\u0001\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\u0013\u0010\u000bJ'\u0010\u0014\u001a\u00020\u00002\b\b\u0002\u0010\r\u001a\u00020\u00072\b\b\u0002\u0010\u0006\u001a\u00020\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\u0015\u0010\u0016J!\u0010\u0017\u001a\u00020\u00002\u0006\u0010\u0018\u001a\u00020\u0019H\u0087\u0002ø\u0001\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\u001a\u0010\u001bJ!\u0010\u0017\u001a\u00020\u00002\u0006\u0010\u0018\u001a\u00020\u001cH\u0087\u0002ø\u0001\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\u001a\u0010\u001dJ\u001a\u0010\u001e\u001a\u00020\u001f2\b\u0010\u0018\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b \u0010!J\u0010\u0010\"\u001a\u00020\u001cHÖ\u0001¢\u0006\u0004\b#\u0010$J\u001e\u0010%\u001a\u00020\u00002\u0006\u0010\u0018\u001a\u00020\u0000H\u0087\nø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b&\u0010'J\u001e\u0010(\u001a\u00020\u00002\u0006\u0010\u0018\u001a\u00020\u0000H\u0087\nø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b)\u0010'J!\u0010*\u001a\u00020\u00002\u0006\u0010\u0018\u001a\u00020\u0019H\u0087\u0002ø\u0001\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b+\u0010\u001bJ!\u0010*\u001a\u00020\u00002\u0006\u0010\u0018\u001a\u00020\u001cH\u0087\u0002ø\u0001\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b+\u0010\u001dJ\u000f\u0010,\u001a\u00020-H\u0017¢\u0006\u0004\b.\u0010/R#\u0010\u0006\u001a\u00020\u00078FX\u0087\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\f\u0012\u0004\b\b\u0010\t\u001a\u0004\b\n\u0010\u000bR\u0016\u0010\u0002\u001a\u00020\u00038\u0000X\u0081\u0004¢\u0006\b\n\u0000\u0012\u0004\b\f\u0010\tR#\u0010\r\u001a\u00020\u00078FX\u0087\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\f\u0012\u0004\b\u000e\u0010\t\u001a\u0004\b\u000f\u0010\u000b\u0088\u0001\u0002\u0092\u0001\u00020\u0003ø\u0001\u0000\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u00061"}, d2 = {"Landroidx/compose/ui/unit/DpSize;", "", "packedValue", "", "constructor-impl", "(J)J", "height", "Landroidx/compose/ui/unit/Dp;", "getHeight-D9Ej5fM$annotations", "()V", "getHeight-D9Ej5fM", "(J)F", "getPackedValue$annotations", "width", "getWidth-D9Ej5fM$annotations", "getWidth-D9Ej5fM", "component1", "component1-D9Ej5fM", "component2", "component2-D9Ej5fM", "copy", "copy-DwJknco", "(JFF)J", "div", "other", "", "div-Gh9hcWk", "(JF)J", "", "(JI)J", "equals", "", "equals-impl", "(JLjava/lang/Object;)Z", "hashCode", "hashCode-impl", "(J)I", "minus", "minus-e_xh8Ic", "(JJ)J", "plus", "plus-e_xh8Ic", "times", "times-Gh9hcWk", "toString", "", "toString-impl", "(J)Ljava/lang/String;", "Companion", "ui-unit_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
@JvmInline
/* loaded from: classes.dex */
public final class DpSize {
    private final long packedValue;
    public static final Companion Companion = new Companion(null);
    private static final long Zero = DpKt.m5144DpSizeYgX7TsA(Dp.m5122constructorimpl(0), Dp.m5122constructorimpl(0));
    private static final long Unspecified = DpKt.m5144DpSizeYgX7TsA(Dp.Companion.m5142getUnspecifiedD9Ej5fM(), Dp.Companion.m5142getUnspecifiedD9Ej5fM());

    /* renamed from: box-impl  reason: not valid java name */
    public static final /* synthetic */ DpSize m5208boximpl(long j) {
        return new DpSize(j);
    }

    /* renamed from: constructor-impl  reason: not valid java name */
    public static long m5211constructorimpl(long j) {
        return j;
    }

    /* renamed from: equals-impl  reason: not valid java name */
    public static boolean m5216equalsimpl(long j, Object obj) {
        return (obj instanceof DpSize) && j == ((DpSize) obj).m5228unboximpl();
    }

    /* renamed from: equals-impl0  reason: not valid java name */
    public static final boolean m5217equalsimpl0(long j, long j2) {
        return j == j2;
    }

    /* renamed from: getHeight-D9Ej5fM$annotations  reason: not valid java name */
    public static /* synthetic */ void m5219getHeightD9Ej5fM$annotations() {
    }

    public static /* synthetic */ void getPackedValue$annotations() {
    }

    /* renamed from: getWidth-D9Ej5fM$annotations  reason: not valid java name */
    public static /* synthetic */ void m5221getWidthD9Ej5fM$annotations() {
    }

    /* renamed from: hashCode-impl  reason: not valid java name */
    public static int m5222hashCodeimpl(long j) {
        return Long.hashCode(j);
    }

    public boolean equals(Object obj) {
        return m5216equalsimpl(this.packedValue, obj);
    }

    public int hashCode() {
        return m5222hashCodeimpl(this.packedValue);
    }

    /* renamed from: unbox-impl  reason: not valid java name */
    public final /* synthetic */ long m5228unboximpl() {
        return this.packedValue;
    }

    private /* synthetic */ DpSize(long packedValue) {
        this.packedValue = packedValue;
    }

    /* renamed from: getWidth-D9Ej5fM  reason: not valid java name */
    public static final float m5220getWidthD9Ej5fM(long arg0) {
        if (!(arg0 != Unspecified)) {
            throw new IllegalStateException("DpSize is unspecified".toString());
        }
        FloatCompanionObject floatCompanionObject = FloatCompanionObject.INSTANCE;
        float $this$dp$iv = Float.intBitsToFloat((int) (arg0 >> 32));
        return Dp.m5122constructorimpl($this$dp$iv);
    }

    /* renamed from: getHeight-D9Ej5fM  reason: not valid java name */
    public static final float m5218getHeightD9Ej5fM(long arg0) {
        if (!(arg0 != Unspecified)) {
            throw new IllegalStateException("DpSize is unspecified".toString());
        }
        FloatCompanionObject floatCompanionObject = FloatCompanionObject.INSTANCE;
        float $this$dp$iv = Float.intBitsToFloat((int) (4294967295L & arg0));
        return Dp.m5122constructorimpl($this$dp$iv);
    }

    /* renamed from: copy-DwJknco  reason: not valid java name */
    public static final long m5212copyDwJknco(long arg0, float width, float height) {
        return DpKt.m5144DpSizeYgX7TsA(width, height);
    }

    /* renamed from: copy-DwJknco$default  reason: not valid java name */
    public static /* synthetic */ long m5213copyDwJknco$default(long j, float f, float f2, int i, Object obj) {
        if ((i & 1) != 0) {
            f = m5220getWidthD9Ej5fM(j);
        }
        if ((i & 2) != 0) {
            f2 = m5218getHeightD9Ej5fM(j);
        }
        return m5212copyDwJknco(j, f, f2);
    }

    /* renamed from: minus-e_xh8Ic  reason: not valid java name */
    public static final long m5223minuse_xh8Ic(long arg0, long other) {
        float arg0$iv = m5220getWidthD9Ej5fM(arg0);
        float other$iv = m5220getWidthD9Ej5fM(other);
        float arg0$iv2 = Dp.m5122constructorimpl(arg0$iv - other$iv);
        float arg0$iv3 = m5218getHeightD9Ej5fM(arg0);
        float other$iv2 = m5218getHeightD9Ej5fM(other);
        return DpKt.m5144DpSizeYgX7TsA(arg0$iv2, Dp.m5122constructorimpl(arg0$iv3 - other$iv2));
    }

    /* renamed from: plus-e_xh8Ic  reason: not valid java name */
    public static final long m5224pluse_xh8Ic(long arg0, long other) {
        float arg0$iv = m5220getWidthD9Ej5fM(arg0);
        float other$iv = m5220getWidthD9Ej5fM(other);
        float arg0$iv2 = Dp.m5122constructorimpl(arg0$iv + other$iv);
        float arg0$iv3 = m5218getHeightD9Ej5fM(arg0);
        float other$iv2 = m5218getHeightD9Ej5fM(other);
        return DpKt.m5144DpSizeYgX7TsA(arg0$iv2, Dp.m5122constructorimpl(arg0$iv3 + other$iv2));
    }

    /* renamed from: component1-D9Ej5fM  reason: not valid java name */
    public static final float m5209component1D9Ej5fM(long arg0) {
        return m5220getWidthD9Ej5fM(arg0);
    }

    /* renamed from: component2-D9Ej5fM  reason: not valid java name */
    public static final float m5210component2D9Ej5fM(long arg0) {
        return m5218getHeightD9Ej5fM(arg0);
    }

    /* renamed from: times-Gh9hcWk  reason: not valid java name */
    public static final long m5226timesGh9hcWk(long arg0, int other) {
        float arg0$iv = m5220getWidthD9Ej5fM(arg0);
        float arg0$iv2 = Dp.m5122constructorimpl(other * arg0$iv);
        float arg0$iv3 = m5218getHeightD9Ej5fM(arg0);
        return DpKt.m5144DpSizeYgX7TsA(arg0$iv2, Dp.m5122constructorimpl(other * arg0$iv3));
    }

    /* renamed from: times-Gh9hcWk  reason: not valid java name */
    public static final long m5225timesGh9hcWk(long arg0, float other) {
        float arg0$iv = m5220getWidthD9Ej5fM(arg0);
        float arg0$iv2 = Dp.m5122constructorimpl(arg0$iv * other);
        float arg0$iv3 = m5218getHeightD9Ej5fM(arg0);
        return DpKt.m5144DpSizeYgX7TsA(arg0$iv2, Dp.m5122constructorimpl(arg0$iv3 * other));
    }

    /* renamed from: div-Gh9hcWk  reason: not valid java name */
    public static final long m5215divGh9hcWk(long arg0, int other) {
        float arg0$iv = m5220getWidthD9Ej5fM(arg0);
        float arg0$iv2 = Dp.m5122constructorimpl(arg0$iv / other);
        float arg0$iv3 = m5218getHeightD9Ej5fM(arg0);
        return DpKt.m5144DpSizeYgX7TsA(arg0$iv2, Dp.m5122constructorimpl(arg0$iv3 / other));
    }

    /* renamed from: div-Gh9hcWk  reason: not valid java name */
    public static final long m5214divGh9hcWk(long arg0, float other) {
        float arg0$iv = m5220getWidthD9Ej5fM(arg0);
        float arg0$iv2 = Dp.m5122constructorimpl(arg0$iv / other);
        float arg0$iv3 = m5218getHeightD9Ej5fM(arg0);
        return DpKt.m5144DpSizeYgX7TsA(arg0$iv2, Dp.m5122constructorimpl(arg0$iv3 / other));
    }

    public String toString() {
        return m5227toStringimpl(this.packedValue);
    }

    /* renamed from: toString-impl  reason: not valid java name */
    public static String m5227toStringimpl(long arg0) {
        if (arg0 != Companion.m5229getUnspecifiedMYxV2XQ()) {
            return ((Object) Dp.m5133toStringimpl(m5220getWidthD9Ej5fM(arg0))) + " x " + ((Object) Dp.m5133toStringimpl(m5218getHeightD9Ej5fM(arg0)));
        }
        return "DpSize.Unspecified";
    }

    /* compiled from: Dp.kt */
    @Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u001c\u0010\u0003\u001a\u00020\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010\u0007\u001a\u0004\b\u0005\u0010\u0006R\u001c\u0010\b\u001a\u00020\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010\u0007\u001a\u0004\b\t\u0010\u0006\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u0006\n"}, d2 = {"Landroidx/compose/ui/unit/DpSize$Companion;", "", "()V", "Unspecified", "Landroidx/compose/ui/unit/DpSize;", "getUnspecified-MYxV2XQ", "()J", "J", "Zero", "getZero-MYxV2XQ", "ui-unit_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        /* renamed from: getZero-MYxV2XQ  reason: not valid java name */
        public final long m5230getZeroMYxV2XQ() {
            return DpSize.Zero;
        }

        /* renamed from: getUnspecified-MYxV2XQ  reason: not valid java name */
        public final long m5229getUnspecifiedMYxV2XQ() {
            return DpSize.Unspecified;
        }
    }
}
