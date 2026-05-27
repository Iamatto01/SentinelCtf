package androidx.compose.material;

import androidx.compose.runtime.MutableState;
import androidx.compose.runtime.SnapshotStateKt;
import androidx.compose.runtime.State;
import androidx.compose.ui.graphics.Color;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
/* compiled from: Colors.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0010\u000b\n\u0002\b1\n\u0002\u0010\u000e\n\u0000\b\u0007\u0018\u00002\u00020\u0001Bp\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0003\u0012\u0006\u0010\u0007\u001a\u00020\u0003\u0012\u0006\u0010\b\u001a\u00020\u0003\u0012\u0006\u0010\t\u001a\u00020\u0003\u0012\u0006\u0010\n\u001a\u00020\u0003\u0012\u0006\u0010\u000b\u001a\u00020\u0003\u0012\u0006\u0010\f\u001a\u00020\u0003\u0012\u0006\u0010\r\u001a\u00020\u0003\u0012\u0006\u0010\u000e\u001a\u00020\u0003\u0012\u0006\u0010\u000f\u001a\u00020\u0010ø\u0001\u0000¢\u0006\u0002\u0010\u0011J\u0095\u0001\u0010>\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00032\b\b\u0002\u0010\u0005\u001a\u00020\u00032\b\b\u0002\u0010\u0006\u001a\u00020\u00032\b\b\u0002\u0010\u0007\u001a\u00020\u00032\b\b\u0002\u0010\b\u001a\u00020\u00032\b\b\u0002\u0010\t\u001a\u00020\u00032\b\b\u0002\u0010\n\u001a\u00020\u00032\b\b\u0002\u0010\u000b\u001a\u00020\u00032\b\b\u0002\u0010\f\u001a\u00020\u00032\b\b\u0002\u0010\r\u001a\u00020\u00032\b\b\u0002\u0010\u000e\u001a\u00020\u00032\b\b\u0002\u0010\u000f\u001a\u00020\u0010ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b?\u0010@J\b\u0010A\u001a\u00020BH\u0016R4\u0010\u0007\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00038F@@X\u0086\u008e\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0012\n\u0004\b\u0017\u0010\u0018\u001a\u0004\b\u0013\u0010\u0014\"\u0004\b\u0015\u0010\u0016R4\u0010\t\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00038F@@X\u0086\u008e\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0012\n\u0004\b\u001b\u0010\u0018\u001a\u0004\b\u0019\u0010\u0014\"\u0004\b\u001a\u0010\u0016R+\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u0012\u001a\u00020\u00108F@@X\u0086\u008e\u0002¢\u0006\u0012\n\u0004\b\u001f\u0010\u0018\u001a\u0004\b\u000f\u0010\u001c\"\u0004\b\u001d\u0010\u001eR4\u0010\f\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00038F@@X\u0086\u008e\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0012\n\u0004\b\"\u0010\u0018\u001a\u0004\b \u0010\u0014\"\u0004\b!\u0010\u0016R4\u0010\u000e\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00038F@@X\u0086\u008e\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0012\n\u0004\b%\u0010\u0018\u001a\u0004\b#\u0010\u0014\"\u0004\b$\u0010\u0016R4\u0010\n\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00038F@@X\u0086\u008e\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0012\n\u0004\b(\u0010\u0018\u001a\u0004\b&\u0010\u0014\"\u0004\b'\u0010\u0016R4\u0010\u000b\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00038F@@X\u0086\u008e\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0012\n\u0004\b+\u0010\u0018\u001a\u0004\b)\u0010\u0014\"\u0004\b*\u0010\u0016R4\u0010\r\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00038F@@X\u0086\u008e\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0012\n\u0004\b.\u0010\u0018\u001a\u0004\b,\u0010\u0014\"\u0004\b-\u0010\u0016R4\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00038F@@X\u0086\u008e\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0012\n\u0004\b1\u0010\u0018\u001a\u0004\b/\u0010\u0014\"\u0004\b0\u0010\u0016R4\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00038F@@X\u0086\u008e\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0012\n\u0004\b4\u0010\u0018\u001a\u0004\b2\u0010\u0014\"\u0004\b3\u0010\u0016R4\u0010\u0005\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00038F@@X\u0086\u008e\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0012\n\u0004\b7\u0010\u0018\u001a\u0004\b5\u0010\u0014\"\u0004\b6\u0010\u0016R4\u0010\u0006\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00038F@@X\u0086\u008e\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0012\n\u0004\b:\u0010\u0018\u001a\u0004\b8\u0010\u0014\"\u0004\b9\u0010\u0016R4\u0010\b\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u00038F@@X\u0086\u008e\u0002ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0012\n\u0004\b=\u0010\u0018\u001a\u0004\b;\u0010\u0014\"\u0004\b<\u0010\u0016\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u0006C"}, d2 = {"Landroidx/compose/material/Colors;", "", "primary", "Landroidx/compose/ui/graphics/Color;", "primaryVariant", "secondary", "secondaryVariant", "background", "surface", "error", "onPrimary", "onSecondary", "onBackground", "onSurface", "onError", "isLight", "", "(JJJJJJJJJJJJZLkotlin/jvm/internal/DefaultConstructorMarker;)V", "<set-?>", "getBackground-0d7_KjU", "()J", "setBackground-8_81llA$material_release", "(J)V", "background$delegate", "Landroidx/compose/runtime/MutableState;", "getError-0d7_KjU", "setError-8_81llA$material_release", "error$delegate", "()Z", "setLight$material_release", "(Z)V", "isLight$delegate", "getOnBackground-0d7_KjU", "setOnBackground-8_81llA$material_release", "onBackground$delegate", "getOnError-0d7_KjU", "setOnError-8_81llA$material_release", "onError$delegate", "getOnPrimary-0d7_KjU", "setOnPrimary-8_81llA$material_release", "onPrimary$delegate", "getOnSecondary-0d7_KjU", "setOnSecondary-8_81llA$material_release", "onSecondary$delegate", "getOnSurface-0d7_KjU", "setOnSurface-8_81llA$material_release", "onSurface$delegate", "getPrimary-0d7_KjU", "setPrimary-8_81llA$material_release", "primary$delegate", "getPrimaryVariant-0d7_KjU", "setPrimaryVariant-8_81llA$material_release", "primaryVariant$delegate", "getSecondary-0d7_KjU", "setSecondary-8_81llA$material_release", "secondary$delegate", "getSecondaryVariant-0d7_KjU", "setSecondaryVariant-8_81llA$material_release", "secondaryVariant$delegate", "getSurface-0d7_KjU", "setSurface-8_81llA$material_release", "surface$delegate", "copy", "copy-pvPzIIM", "(JJJJJJJJJJJJZ)Landroidx/compose/material/Colors;", "toString", "", "material_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class Colors {
    public static final int $stable = 0;
    private final MutableState background$delegate;
    private final MutableState error$delegate;
    private final MutableState isLight$delegate;
    private final MutableState onBackground$delegate;
    private final MutableState onError$delegate;
    private final MutableState onPrimary$delegate;
    private final MutableState onSecondary$delegate;
    private final MutableState onSurface$delegate;
    private final MutableState primary$delegate;
    private final MutableState primaryVariant$delegate;
    private final MutableState secondary$delegate;
    private final MutableState secondaryVariant$delegate;
    private final MutableState surface$delegate;

    public /* synthetic */ Colors(long j, long j2, long j3, long j4, long j5, long j6, long j7, long j8, long j9, long j10, long j11, long j12, boolean z, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, z);
    }

    private Colors(long primary, long primaryVariant, long secondary, long secondaryVariant, long background, long surface, long error, long onPrimary, long onSecondary, long onBackground, long onSurface, long onError, boolean isLight) {
        this.primary$delegate = SnapshotStateKt.mutableStateOf(Color.m2596boximpl(primary), SnapshotStateKt.structuralEqualityPolicy());
        this.primaryVariant$delegate = SnapshotStateKt.mutableStateOf(Color.m2596boximpl(primaryVariant), SnapshotStateKt.structuralEqualityPolicy());
        this.secondary$delegate = SnapshotStateKt.mutableStateOf(Color.m2596boximpl(secondary), SnapshotStateKt.structuralEqualityPolicy());
        this.secondaryVariant$delegate = SnapshotStateKt.mutableStateOf(Color.m2596boximpl(secondaryVariant), SnapshotStateKt.structuralEqualityPolicy());
        this.background$delegate = SnapshotStateKt.mutableStateOf(Color.m2596boximpl(background), SnapshotStateKt.structuralEqualityPolicy());
        this.surface$delegate = SnapshotStateKt.mutableStateOf(Color.m2596boximpl(surface), SnapshotStateKt.structuralEqualityPolicy());
        this.error$delegate = SnapshotStateKt.mutableStateOf(Color.m2596boximpl(error), SnapshotStateKt.structuralEqualityPolicy());
        this.onPrimary$delegate = SnapshotStateKt.mutableStateOf(Color.m2596boximpl(onPrimary), SnapshotStateKt.structuralEqualityPolicy());
        this.onSecondary$delegate = SnapshotStateKt.mutableStateOf(Color.m2596boximpl(onSecondary), SnapshotStateKt.structuralEqualityPolicy());
        this.onBackground$delegate = SnapshotStateKt.mutableStateOf(Color.m2596boximpl(onBackground), SnapshotStateKt.structuralEqualityPolicy());
        this.onSurface$delegate = SnapshotStateKt.mutableStateOf(Color.m2596boximpl(onSurface), SnapshotStateKt.structuralEqualityPolicy());
        this.onError$delegate = SnapshotStateKt.mutableStateOf(Color.m2596boximpl(onError), SnapshotStateKt.structuralEqualityPolicy());
        this.isLight$delegate = SnapshotStateKt.mutableStateOf(Boolean.valueOf(isLight), SnapshotStateKt.structuralEqualityPolicy());
    }

    /* renamed from: getPrimary-0d7_KjU  reason: not valid java name */
    public final long m962getPrimary0d7_KjU() {
        State $this$getValue$iv = this.primary$delegate;
        return ((Color) $this$getValue$iv.getValue()).m2616unboximpl();
    }

    /* renamed from: setPrimary-8_81llA$material_release  reason: not valid java name */
    public final void m974setPrimary8_81llA$material_release(long j) {
        MutableState $this$setValue$iv = this.primary$delegate;
        $this$setValue$iv.setValue(Color.m2596boximpl(j));
    }

    /* renamed from: getPrimaryVariant-0d7_KjU  reason: not valid java name */
    public final long m963getPrimaryVariant0d7_KjU() {
        State $this$getValue$iv = this.primaryVariant$delegate;
        return ((Color) $this$getValue$iv.getValue()).m2616unboximpl();
    }

    /* renamed from: setPrimaryVariant-8_81llA$material_release  reason: not valid java name */
    public final void m975setPrimaryVariant8_81llA$material_release(long j) {
        MutableState $this$setValue$iv = this.primaryVariant$delegate;
        $this$setValue$iv.setValue(Color.m2596boximpl(j));
    }

    /* renamed from: getSecondary-0d7_KjU  reason: not valid java name */
    public final long m964getSecondary0d7_KjU() {
        State $this$getValue$iv = this.secondary$delegate;
        return ((Color) $this$getValue$iv.getValue()).m2616unboximpl();
    }

    /* renamed from: setSecondary-8_81llA$material_release  reason: not valid java name */
    public final void m976setSecondary8_81llA$material_release(long j) {
        MutableState $this$setValue$iv = this.secondary$delegate;
        $this$setValue$iv.setValue(Color.m2596boximpl(j));
    }

    /* renamed from: getSecondaryVariant-0d7_KjU  reason: not valid java name */
    public final long m965getSecondaryVariant0d7_KjU() {
        State $this$getValue$iv = this.secondaryVariant$delegate;
        return ((Color) $this$getValue$iv.getValue()).m2616unboximpl();
    }

    /* renamed from: setSecondaryVariant-8_81llA$material_release  reason: not valid java name */
    public final void m977setSecondaryVariant8_81llA$material_release(long j) {
        MutableState $this$setValue$iv = this.secondaryVariant$delegate;
        $this$setValue$iv.setValue(Color.m2596boximpl(j));
    }

    /* renamed from: getBackground-0d7_KjU  reason: not valid java name */
    public final long m955getBackground0d7_KjU() {
        State $this$getValue$iv = this.background$delegate;
        return ((Color) $this$getValue$iv.getValue()).m2616unboximpl();
    }

    /* renamed from: setBackground-8_81llA$material_release  reason: not valid java name */
    public final void m967setBackground8_81llA$material_release(long j) {
        MutableState $this$setValue$iv = this.background$delegate;
        $this$setValue$iv.setValue(Color.m2596boximpl(j));
    }

    /* renamed from: getSurface-0d7_KjU  reason: not valid java name */
    public final long m966getSurface0d7_KjU() {
        State $this$getValue$iv = this.surface$delegate;
        return ((Color) $this$getValue$iv.getValue()).m2616unboximpl();
    }

    /* renamed from: setSurface-8_81llA$material_release  reason: not valid java name */
    public final void m978setSurface8_81llA$material_release(long j) {
        MutableState $this$setValue$iv = this.surface$delegate;
        $this$setValue$iv.setValue(Color.m2596boximpl(j));
    }

    /* renamed from: getError-0d7_KjU  reason: not valid java name */
    public final long m956getError0d7_KjU() {
        State $this$getValue$iv = this.error$delegate;
        return ((Color) $this$getValue$iv.getValue()).m2616unboximpl();
    }

    /* renamed from: setError-8_81llA$material_release  reason: not valid java name */
    public final void m968setError8_81llA$material_release(long j) {
        MutableState $this$setValue$iv = this.error$delegate;
        $this$setValue$iv.setValue(Color.m2596boximpl(j));
    }

    /* renamed from: getOnPrimary-0d7_KjU  reason: not valid java name */
    public final long m959getOnPrimary0d7_KjU() {
        State $this$getValue$iv = this.onPrimary$delegate;
        return ((Color) $this$getValue$iv.getValue()).m2616unboximpl();
    }

    /* renamed from: setOnPrimary-8_81llA$material_release  reason: not valid java name */
    public final void m971setOnPrimary8_81llA$material_release(long j) {
        MutableState $this$setValue$iv = this.onPrimary$delegate;
        $this$setValue$iv.setValue(Color.m2596boximpl(j));
    }

    /* renamed from: getOnSecondary-0d7_KjU  reason: not valid java name */
    public final long m960getOnSecondary0d7_KjU() {
        State $this$getValue$iv = this.onSecondary$delegate;
        return ((Color) $this$getValue$iv.getValue()).m2616unboximpl();
    }

    /* renamed from: setOnSecondary-8_81llA$material_release  reason: not valid java name */
    public final void m972setOnSecondary8_81llA$material_release(long j) {
        MutableState $this$setValue$iv = this.onSecondary$delegate;
        $this$setValue$iv.setValue(Color.m2596boximpl(j));
    }

    /* renamed from: getOnBackground-0d7_KjU  reason: not valid java name */
    public final long m957getOnBackground0d7_KjU() {
        State $this$getValue$iv = this.onBackground$delegate;
        return ((Color) $this$getValue$iv.getValue()).m2616unboximpl();
    }

    /* renamed from: setOnBackground-8_81llA$material_release  reason: not valid java name */
    public final void m969setOnBackground8_81llA$material_release(long j) {
        MutableState $this$setValue$iv = this.onBackground$delegate;
        $this$setValue$iv.setValue(Color.m2596boximpl(j));
    }

    /* renamed from: getOnSurface-0d7_KjU  reason: not valid java name */
    public final long m961getOnSurface0d7_KjU() {
        State $this$getValue$iv = this.onSurface$delegate;
        return ((Color) $this$getValue$iv.getValue()).m2616unboximpl();
    }

    /* renamed from: setOnSurface-8_81llA$material_release  reason: not valid java name */
    public final void m973setOnSurface8_81llA$material_release(long j) {
        MutableState $this$setValue$iv = this.onSurface$delegate;
        $this$setValue$iv.setValue(Color.m2596boximpl(j));
    }

    /* renamed from: getOnError-0d7_KjU  reason: not valid java name */
    public final long m958getOnError0d7_KjU() {
        State $this$getValue$iv = this.onError$delegate;
        return ((Color) $this$getValue$iv.getValue()).m2616unboximpl();
    }

    /* renamed from: setOnError-8_81llA$material_release  reason: not valid java name */
    public final void m970setOnError8_81llA$material_release(long j) {
        MutableState $this$setValue$iv = this.onError$delegate;
        $this$setValue$iv.setValue(Color.m2596boximpl(j));
    }

    public final boolean isLight() {
        State $this$getValue$iv = this.isLight$delegate;
        return ((Boolean) $this$getValue$iv.getValue()).booleanValue();
    }

    public final void setLight$material_release(boolean z) {
        MutableState $this$setValue$iv = this.isLight$delegate;
        $this$setValue$iv.setValue(Boolean.valueOf(z));
    }

    /* renamed from: copy-pvPzIIM  reason: not valid java name */
    public final Colors m954copypvPzIIM(long primary, long primaryVariant, long secondary, long secondaryVariant, long background, long surface, long error, long onPrimary, long onSecondary, long onBackground, long onSurface, long onError, boolean isLight) {
        return new Colors(primary, primaryVariant, secondary, secondaryVariant, background, surface, error, onPrimary, onSecondary, onBackground, onSurface, onError, isLight, null);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Colors(primary=").append((Object) Color.m2614toStringimpl(m962getPrimary0d7_KjU())).append(", primaryVariant=").append((Object) Color.m2614toStringimpl(m963getPrimaryVariant0d7_KjU())).append(", secondary=").append((Object) Color.m2614toStringimpl(m964getSecondary0d7_KjU())).append(", secondaryVariant=").append((Object) Color.m2614toStringimpl(m965getSecondaryVariant0d7_KjU())).append(", background=").append((Object) Color.m2614toStringimpl(m955getBackground0d7_KjU())).append(", surface=").append((Object) Color.m2614toStringimpl(m966getSurface0d7_KjU())).append(", error=").append((Object) Color.m2614toStringimpl(m956getError0d7_KjU())).append(", onPrimary=").append((Object) Color.m2614toStringimpl(m959getOnPrimary0d7_KjU())).append(", onSecondary=").append((Object) Color.m2614toStringimpl(m960getOnSecondary0d7_KjU())).append(", onBackground=").append((Object) Color.m2614toStringimpl(m957getOnBackground0d7_KjU())).append(", onSurface=").append((Object) Color.m2614toStringimpl(m961getOnSurface0d7_KjU())).append(", onError=");
        sb.append((Object) Color.m2614toStringimpl(m958getOnError0d7_KjU())).append(", isLight=").append(isLight()).append(')');
        return sb.toString();
    }
}
