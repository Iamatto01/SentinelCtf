package androidx.compose.ui.geometry;

import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
/* compiled from: RoundRect.kt */
@Metadata(d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b!\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\b\n\u0002\b\u0007\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0087\b\u0018\u0000 >2\u00020\u0001:\u0001>BP\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0003\u0012\b\b\u0002\u0010\u0007\u001a\u00020\b\u0012\b\b\u0002\u0010\t\u001a\u00020\b\u0012\b\b\u0002\u0010\n\u001a\u00020\b\u0012\b\b\u0002\u0010\u000b\u001a\u00020\bø\u0001\u0000¢\u0006\u0002\u0010\fJ\t\u0010\u001d\u001a\u00020\u0003HÆ\u0003J\t\u0010\u001e\u001a\u00020\u0003HÆ\u0003J\t\u0010\u001f\u001a\u00020\u0003HÆ\u0003J\t\u0010 \u001a\u00020\u0003HÆ\u0003J\u0019\u0010!\u001a\u00020\bHÆ\u0003ø\u0001\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\"\u0010\u0011J\u0019\u0010#\u001a\u00020\bHÆ\u0003ø\u0001\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b$\u0010\u0011J\u0019\u0010%\u001a\u00020\bHÆ\u0003ø\u0001\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b&\u0010\u0011J\u0019\u0010'\u001a\u00020\bHÆ\u0003ø\u0001\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b(\u0010\u0011J\u001e\u0010)\u001a\u00020*2\u0006\u0010+\u001a\u00020,H\u0086\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b-\u0010.Jf\u0010/\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00032\b\b\u0002\u0010\u0005\u001a\u00020\u00032\b\b\u0002\u0010\u0006\u001a\u00020\u00032\b\b\u0002\u0010\u0007\u001a\u00020\b2\b\b\u0002\u0010\t\u001a\u00020\b2\b\b\u0002\u0010\n\u001a\u00020\b2\b\b\u0002\u0010\u000b\u001a\u00020\bHÆ\u0001ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b0\u00101J\u0013\u00102\u001a\u00020*2\b\u00103\u001a\u0004\u0018\u00010\u0001HÖ\u0003J\t\u00104\u001a\u000205HÖ\u0001J(\u00106\u001a\u00020\u00032\u0006\u00107\u001a\u00020\u00032\u0006\u00108\u001a\u00020\u00032\u0006\u00109\u001a\u00020\u00032\u0006\u0010:\u001a\u00020\u0003H\u0002J\b\u0010;\u001a\u00020\u0000H\u0002J\b\u0010<\u001a\u00020=H\u0016R\u0010\u0010\r\u001a\u0004\u0018\u00010\u0000X\u0082\u000e¢\u0006\u0002\n\u0000R\u0011\u0010\u0006\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u000e\u0010\u000fR\u001c\u0010\u000b\u001a\u00020\bø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010\u0012\u001a\u0004\b\u0010\u0010\u0011R\u001c\u0010\n\u001a\u00020\bø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010\u0012\u001a\u0004\b\u0013\u0010\u0011R\u0011\u0010\u0014\u001a\u00020\u00038F¢\u0006\u0006\u001a\u0004\b\u0015\u0010\u000fR\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0016\u0010\u000fR\u0011\u0010\u0005\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0017\u0010\u000fR\u0011\u0010\u0004\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0018\u0010\u000fR\u001c\u0010\u0007\u001a\u00020\bø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010\u0012\u001a\u0004\b\u0019\u0010\u0011R\u001c\u0010\t\u001a\u00020\bø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\n\n\u0002\u0010\u0012\u001a\u0004\b\u001a\u0010\u0011R\u0011\u0010\u001b\u001a\u00020\u00038F¢\u0006\u0006\u001a\u0004\b\u001c\u0010\u000f\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u0006?"}, d2 = {"Landroidx/compose/ui/geometry/RoundRect;", "", "left", "", "top", "right", "bottom", "topLeftCornerRadius", "Landroidx/compose/ui/geometry/CornerRadius;", "topRightCornerRadius", "bottomRightCornerRadius", "bottomLeftCornerRadius", "(FFFFJJJJLkotlin/jvm/internal/DefaultConstructorMarker;)V", "_scaledRadiiRect", "getBottom", "()F", "getBottomLeftCornerRadius-kKHJgLs", "()J", "J", "getBottomRightCornerRadius-kKHJgLs", "height", "getHeight", "getLeft", "getRight", "getTop", "getTopLeftCornerRadius-kKHJgLs", "getTopRightCornerRadius-kKHJgLs", "width", "getWidth", "component1", "component2", "component3", "component4", "component5", "component5-kKHJgLs", "component6", "component6-kKHJgLs", "component7", "component7-kKHJgLs", "component8", "component8-kKHJgLs", "contains", "", "point", "Landroidx/compose/ui/geometry/Offset;", "contains-k-4lQ0M", "(J)Z", "copy", "copy-MDFrsts", "(FFFFJJJJ)Landroidx/compose/ui/geometry/RoundRect;", "equals", "other", "hashCode", "", "minRadius", "min", "radius1", "radius2", "limit", "scaledRadiiRect", "toString", "", "Companion", "ui-geometry_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class RoundRect {
    public static final int $stable = 0;
    public static final Companion Companion = new Companion(null);
    private static final RoundRect Zero = RoundRectKt.m2422RoundRectgG7oq9Y(0.0f, 0.0f, 0.0f, 0.0f, CornerRadius.Companion.m2353getZerokKHJgLs());
    private RoundRect _scaledRadiiRect;
    private final float bottom;
    private final long bottomLeftCornerRadius;
    private final long bottomRightCornerRadius;
    private final float left;
    private final float right;
    private final float top;
    private final long topLeftCornerRadius;
    private final long topRightCornerRadius;

    public /* synthetic */ RoundRect(float f, float f2, float f3, float f4, long j, long j2, long j3, long j4, DefaultConstructorMarker defaultConstructorMarker) {
        this(f, f2, f3, f4, j, j2, j3, j4);
    }

    public static final RoundRect getZero() {
        return Companion.getZero();
    }

    public final float component1() {
        return this.left;
    }

    public final float component2() {
        return this.top;
    }

    public final float component3() {
        return this.right;
    }

    public final float component4() {
        return this.bottom;
    }

    /* renamed from: component5-kKHJgLs  reason: not valid java name */
    public final long m2410component5kKHJgLs() {
        return this.topLeftCornerRadius;
    }

    /* renamed from: component6-kKHJgLs  reason: not valid java name */
    public final long m2411component6kKHJgLs() {
        return this.topRightCornerRadius;
    }

    /* renamed from: component7-kKHJgLs  reason: not valid java name */
    public final long m2412component7kKHJgLs() {
        return this.bottomRightCornerRadius;
    }

    /* renamed from: component8-kKHJgLs  reason: not valid java name */
    public final long m2413component8kKHJgLs() {
        return this.bottomLeftCornerRadius;
    }

    /* renamed from: copy-MDFrsts  reason: not valid java name */
    public final RoundRect m2415copyMDFrsts(float f, float f2, float f3, float f4, long j, long j2, long j3, long j4) {
        return new RoundRect(f, f2, f3, f4, j, j2, j3, j4, null);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof RoundRect) {
            RoundRect roundRect = (RoundRect) obj;
            return Float.compare(this.left, roundRect.left) == 0 && Float.compare(this.top, roundRect.top) == 0 && Float.compare(this.right, roundRect.right) == 0 && Float.compare(this.bottom, roundRect.bottom) == 0 && CornerRadius.m2342equalsimpl0(this.topLeftCornerRadius, roundRect.topLeftCornerRadius) && CornerRadius.m2342equalsimpl0(this.topRightCornerRadius, roundRect.topRightCornerRadius) && CornerRadius.m2342equalsimpl0(this.bottomRightCornerRadius, roundRect.bottomRightCornerRadius) && CornerRadius.m2342equalsimpl0(this.bottomLeftCornerRadius, roundRect.bottomLeftCornerRadius);
        }
        return false;
    }

    public int hashCode() {
        return (((((((((((((Float.hashCode(this.left) * 31) + Float.hashCode(this.top)) * 31) + Float.hashCode(this.right)) * 31) + Float.hashCode(this.bottom)) * 31) + CornerRadius.m2345hashCodeimpl(this.topLeftCornerRadius)) * 31) + CornerRadius.m2345hashCodeimpl(this.topRightCornerRadius)) * 31) + CornerRadius.m2345hashCodeimpl(this.bottomRightCornerRadius)) * 31) + CornerRadius.m2345hashCodeimpl(this.bottomLeftCornerRadius);
    }

    private RoundRect(float left, float top, float right, float bottom, long topLeftCornerRadius, long topRightCornerRadius, long bottomRightCornerRadius, long bottomLeftCornerRadius) {
        this.left = left;
        this.top = top;
        this.right = right;
        this.bottom = bottom;
        this.topLeftCornerRadius = topLeftCornerRadius;
        this.topRightCornerRadius = topRightCornerRadius;
        this.bottomRightCornerRadius = bottomRightCornerRadius;
        this.bottomLeftCornerRadius = bottomLeftCornerRadius;
    }

    public /* synthetic */ RoundRect(float f, float f2, float f3, float f4, long j, long j2, long j3, long j4, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(f, f2, f3, f4, (i & 16) != 0 ? CornerRadius.Companion.m2353getZerokKHJgLs() : j, (i & 32) != 0 ? CornerRadius.Companion.m2353getZerokKHJgLs() : j2, (i & 64) != 0 ? CornerRadius.Companion.m2353getZerokKHJgLs() : j3, (i & 128) != 0 ? CornerRadius.Companion.m2353getZerokKHJgLs() : j4, null);
    }

    public final float getLeft() {
        return this.left;
    }

    public final float getTop() {
        return this.top;
    }

    public final float getRight() {
        return this.right;
    }

    public final float getBottom() {
        return this.bottom;
    }

    /* renamed from: getTopLeftCornerRadius-kKHJgLs  reason: not valid java name */
    public final long m2418getTopLeftCornerRadiuskKHJgLs() {
        return this.topLeftCornerRadius;
    }

    /* renamed from: getTopRightCornerRadius-kKHJgLs  reason: not valid java name */
    public final long m2419getTopRightCornerRadiuskKHJgLs() {
        return this.topRightCornerRadius;
    }

    /* renamed from: getBottomRightCornerRadius-kKHJgLs  reason: not valid java name */
    public final long m2417getBottomRightCornerRadiuskKHJgLs() {
        return this.bottomRightCornerRadius;
    }

    /* renamed from: getBottomLeftCornerRadius-kKHJgLs  reason: not valid java name */
    public final long m2416getBottomLeftCornerRadiuskKHJgLs() {
        return this.bottomLeftCornerRadius;
    }

    public final float getWidth() {
        return this.right - this.left;
    }

    public final float getHeight() {
        return this.bottom - this.top;
    }

    private final RoundRect scaledRadiiRect() {
        RoundRect roundRect = this._scaledRadiiRect;
        if (roundRect == null) {
            RoundRect $this$scaledRadiiRect_u24lambda_u240 = this;
            float scale = $this$scaledRadiiRect_u24lambda_u240.minRadius($this$scaledRadiiRect_u24lambda_u240.minRadius($this$scaledRadiiRect_u24lambda_u240.minRadius($this$scaledRadiiRect_u24lambda_u240.minRadius(1.0f, CornerRadius.m2344getYimpl($this$scaledRadiiRect_u24lambda_u240.bottomLeftCornerRadius), CornerRadius.m2344getYimpl($this$scaledRadiiRect_u24lambda_u240.topLeftCornerRadius), $this$scaledRadiiRect_u24lambda_u240.getHeight()), CornerRadius.m2343getXimpl($this$scaledRadiiRect_u24lambda_u240.topLeftCornerRadius), CornerRadius.m2343getXimpl($this$scaledRadiiRect_u24lambda_u240.topRightCornerRadius), $this$scaledRadiiRect_u24lambda_u240.getWidth()), CornerRadius.m2344getYimpl($this$scaledRadiiRect_u24lambda_u240.topRightCornerRadius), CornerRadius.m2344getYimpl($this$scaledRadiiRect_u24lambda_u240.bottomRightCornerRadius), $this$scaledRadiiRect_u24lambda_u240.getHeight()), CornerRadius.m2343getXimpl($this$scaledRadiiRect_u24lambda_u240.bottomRightCornerRadius), CornerRadius.m2343getXimpl($this$scaledRadiiRect_u24lambda_u240.bottomLeftCornerRadius), $this$scaledRadiiRect_u24lambda_u240.getWidth());
            RoundRect it = new RoundRect($this$scaledRadiiRect_u24lambda_u240.left * scale, $this$scaledRadiiRect_u24lambda_u240.top * scale, $this$scaledRadiiRect_u24lambda_u240.right * scale, $this$scaledRadiiRect_u24lambda_u240.bottom * scale, CornerRadiusKt.CornerRadius(CornerRadius.m2343getXimpl($this$scaledRadiiRect_u24lambda_u240.topLeftCornerRadius) * scale, CornerRadius.m2344getYimpl($this$scaledRadiiRect_u24lambda_u240.topLeftCornerRadius) * scale), CornerRadiusKt.CornerRadius(CornerRadius.m2343getXimpl($this$scaledRadiiRect_u24lambda_u240.topRightCornerRadius) * scale, CornerRadius.m2344getYimpl($this$scaledRadiiRect_u24lambda_u240.topRightCornerRadius) * scale), CornerRadiusKt.CornerRadius(CornerRadius.m2343getXimpl($this$scaledRadiiRect_u24lambda_u240.bottomRightCornerRadius) * scale, CornerRadius.m2344getYimpl($this$scaledRadiiRect_u24lambda_u240.bottomRightCornerRadius) * scale), CornerRadiusKt.CornerRadius(CornerRadius.m2343getXimpl($this$scaledRadiiRect_u24lambda_u240.bottomLeftCornerRadius) * scale, CornerRadius.m2344getYimpl($this$scaledRadiiRect_u24lambda_u240.bottomLeftCornerRadius) * scale), null);
            this._scaledRadiiRect = it;
            return it;
        }
        return roundRect;
    }

    private final float minRadius(float min, float radius1, float radius2, float limit) {
        float sum = radius1 + radius2;
        if (sum > limit) {
            if (!(sum == 0.0f)) {
                return Math.min(min, limit / sum);
            }
        }
        return min;
    }

    /* renamed from: contains-k-4lQ0M  reason: not valid java name */
    public final boolean m2414containsk4lQ0M(long point) {
        float x;
        float y;
        float radiusX;
        float radiusY;
        if (Offset.m2368getXimpl(point) < this.left || Offset.m2368getXimpl(point) >= this.right || Offset.m2369getYimpl(point) < this.top || Offset.m2369getYimpl(point) >= this.bottom) {
            return false;
        }
        RoundRect scaled = scaledRadiiRect();
        if (Offset.m2368getXimpl(point) < this.left + CornerRadius.m2343getXimpl(scaled.topLeftCornerRadius) && Offset.m2369getYimpl(point) < this.top + CornerRadius.m2344getYimpl(scaled.topLeftCornerRadius)) {
            x = (Offset.m2368getXimpl(point) - this.left) - CornerRadius.m2343getXimpl(scaled.topLeftCornerRadius);
            float x2 = Offset.m2369getYimpl(point);
            y = (x2 - this.top) - CornerRadius.m2344getYimpl(scaled.topLeftCornerRadius);
            radiusX = CornerRadius.m2343getXimpl(scaled.topLeftCornerRadius);
            radiusY = CornerRadius.m2344getYimpl(scaled.topLeftCornerRadius);
        } else {
            float x3 = Offset.m2368getXimpl(point);
            if (x3 > this.right - CornerRadius.m2343getXimpl(scaled.topRightCornerRadius) && Offset.m2369getYimpl(point) < this.top + CornerRadius.m2344getYimpl(scaled.topRightCornerRadius)) {
                x = (Offset.m2368getXimpl(point) - this.right) + CornerRadius.m2343getXimpl(scaled.topRightCornerRadius);
                float x4 = Offset.m2369getYimpl(point);
                y = (x4 - this.top) - CornerRadius.m2344getYimpl(scaled.topRightCornerRadius);
                radiusX = CornerRadius.m2343getXimpl(scaled.topRightCornerRadius);
                radiusY = CornerRadius.m2344getYimpl(scaled.topRightCornerRadius);
            } else {
                float x5 = Offset.m2368getXimpl(point);
                if (x5 > this.right - CornerRadius.m2343getXimpl(scaled.bottomRightCornerRadius) && Offset.m2369getYimpl(point) > this.bottom - CornerRadius.m2344getYimpl(scaled.bottomRightCornerRadius)) {
                    x = (Offset.m2368getXimpl(point) - this.right) + CornerRadius.m2343getXimpl(scaled.bottomRightCornerRadius);
                    float x6 = Offset.m2369getYimpl(point);
                    y = (x6 - this.bottom) + CornerRadius.m2344getYimpl(scaled.bottomRightCornerRadius);
                    radiusX = CornerRadius.m2343getXimpl(scaled.bottomRightCornerRadius);
                    radiusY = CornerRadius.m2344getYimpl(scaled.bottomRightCornerRadius);
                } else {
                    float x7 = Offset.m2368getXimpl(point);
                    if (x7 >= this.left + CornerRadius.m2343getXimpl(scaled.bottomLeftCornerRadius) || Offset.m2369getYimpl(point) <= this.bottom - CornerRadius.m2344getYimpl(scaled.bottomLeftCornerRadius)) {
                        return true;
                    }
                    x = (Offset.m2368getXimpl(point) - this.left) - CornerRadius.m2343getXimpl(scaled.bottomLeftCornerRadius);
                    float x8 = Offset.m2369getYimpl(point);
                    y = (x8 - this.bottom) + CornerRadius.m2344getYimpl(scaled.bottomLeftCornerRadius);
                    radiusX = CornerRadius.m2343getXimpl(scaled.bottomLeftCornerRadius);
                    radiusY = CornerRadius.m2344getYimpl(scaled.bottomLeftCornerRadius);
                }
            }
        }
        float radiusY2 = x / radiusX;
        float newY = y / radiusY;
        return (radiusY2 * radiusY2) + (newY * newY) <= 1.0f;
    }

    public String toString() {
        long tlRadius = this.topLeftCornerRadius;
        long trRadius = this.topRightCornerRadius;
        long brRadius = this.bottomRightCornerRadius;
        long blRadius = this.bottomLeftCornerRadius;
        String rect = GeometryUtilsKt.toStringAsFixed(this.left, 1) + ", " + GeometryUtilsKt.toStringAsFixed(this.top, 1) + ", " + GeometryUtilsKt.toStringAsFixed(this.right, 1) + ", " + GeometryUtilsKt.toStringAsFixed(this.bottom, 1);
        if (CornerRadius.m2342equalsimpl0(tlRadius, trRadius) && CornerRadius.m2342equalsimpl0(trRadius, brRadius) && CornerRadius.m2342equalsimpl0(brRadius, blRadius)) {
            return (CornerRadius.m2343getXimpl(tlRadius) > CornerRadius.m2344getYimpl(tlRadius) ? 1 : (CornerRadius.m2343getXimpl(tlRadius) == CornerRadius.m2344getYimpl(tlRadius) ? 0 : -1)) == 0 ? "RoundRect(rect=" + rect + ", radius=" + GeometryUtilsKt.toStringAsFixed(CornerRadius.m2343getXimpl(tlRadius), 1) + ')' : "RoundRect(rect=" + rect + ", x=" + GeometryUtilsKt.toStringAsFixed(CornerRadius.m2343getXimpl(tlRadius), 1) + ", y=" + GeometryUtilsKt.toStringAsFixed(CornerRadius.m2344getYimpl(tlRadius), 1) + ')';
        }
        return "RoundRect(rect=" + rect + ", topLeft=" + ((Object) CornerRadius.m2349toStringimpl(tlRadius)) + ", topRight=" + ((Object) CornerRadius.m2349toStringimpl(trRadius)) + ", bottomRight=" + ((Object) CornerRadius.m2349toStringimpl(brRadius)) + ", bottomLeft=" + ((Object) CornerRadius.m2349toStringimpl(blRadius)) + ')';
    }

    /* compiled from: RoundRect.kt */
    @Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u001c\u0010\u0003\u001a\u00020\u00048\u0006X\u0087\u0004¢\u0006\u000e\n\u0000\u0012\u0004\b\u0005\u0010\u0002\u001a\u0004\b\u0006\u0010\u0007¨\u0006\b"}, d2 = {"Landroidx/compose/ui/geometry/RoundRect$Companion;", "", "()V", "Zero", "Landroidx/compose/ui/geometry/RoundRect;", "getZero$annotations", "getZero", "()Landroidx/compose/ui/geometry/RoundRect;", "ui-geometry_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @JvmStatic
        public static /* synthetic */ void getZero$annotations() {
        }

        private Companion() {
        }

        public final RoundRect getZero() {
            return RoundRect.Zero;
        }
    }
}
