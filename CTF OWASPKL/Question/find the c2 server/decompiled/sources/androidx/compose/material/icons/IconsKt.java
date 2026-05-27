package androidx.compose.material.icons;

import androidx.autofill.HintConstants;
import androidx.compose.ui.graphics.vector.ImageVector;
import androidx.compose.ui.unit.Dp;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: Icons.kt */
@Metadata(d1 = {"\u00008\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\u001a-\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0017\u0010\b\u001a\u0013\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\n0\t¢\u0006\u0002\b\u000bH\u0086\bø\u0001\u0000\u001aT\u0010\f\u001a\u00020\n*\u00020\n2\b\b\u0002\u0010\r\u001a\u00020\u00012\b\b\u0002\u0010\u000e\u001a\u00020\u00012\b\b\u0002\u0010\u000f\u001a\u00020\u00102\u0017\u0010\u0011\u001a\u0013\u0012\u0004\u0012\u00020\u0012\u0012\u0004\u0012\u00020\u00130\t¢\u0006\u0002\b\u000bH\u0086\bø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\b\u0014\u0010\u0015\"\u0016\u0010\u0000\u001a\u00020\u00018\u0000X\u0081T¢\u0006\b\n\u0000\u0012\u0004\b\u0002\u0010\u0003\u0082\u0002\u0012\n\u0005\b\u009920\u0001\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006\u0016"}, d2 = {"MaterialIconDimension", "", "getMaterialIconDimension$annotations", "()V", "materialIcon", "Landroidx/compose/ui/graphics/vector/ImageVector;", HintConstants.AUTOFILL_HINT_NAME, "", "block", "Lkotlin/Function1;", "Landroidx/compose/ui/graphics/vector/ImageVector$Builder;", "Lkotlin/ExtensionFunctionType;", "materialPath", "fillAlpha", "strokeAlpha", "pathFillType", "Landroidx/compose/ui/graphics/PathFillType;", "pathBuilder", "Landroidx/compose/ui/graphics/vector/PathBuilder;", "", "materialPath-YwgOQQI", "(Landroidx/compose/ui/graphics/vector/ImageVector$Builder;FFILkotlin/jvm/functions/Function1;)Landroidx/compose/ui/graphics/vector/ImageVector$Builder;", "material-icons-core_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class IconsKt {
    public static final float MaterialIconDimension = 24.0f;

    public static /* synthetic */ void getMaterialIconDimension$annotations() {
    }

    public static final ImageVector materialIcon(String name, Function1<? super ImageVector.Builder, ImageVector.Builder> block) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(block, "block");
        return block.invoke(new ImageVector.Builder(name, Dp.m5122constructorimpl(24.0f), Dp.m5122constructorimpl(24.0f), 24.0f, 24.0f, 0L, 0, false, 224, null)).build();
    }

    /*  JADX ERROR: JadxRuntimeException in pass: InlineMethods
        jadx.core.utils.exceptions.JadxRuntimeException: Failed to process method for inline: androidx.compose.ui.graphics.vector.ImageVector.Builder.addPath-oIyEayM$default(androidx.compose.ui.graphics.vector.ImageVector$Builder, java.util.List, int, java.lang.String, androidx.compose.ui.graphics.Brush, float, androidx.compose.ui.graphics.Brush, float, float, int, int, float, float, float, float, int, java.lang.Object):androidx.compose.ui.graphics.vector.ImageVector$Builder
        	at jadx.core.dex.visitors.InlineMethods.processInvokeInsn(InlineMethods.java:76)
        	at jadx.core.dex.visitors.InlineMethods.visit(InlineMethods.java:51)
        Caused by: java.lang.NullPointerException
        */
    /* renamed from: materialPath-YwgOQQI$default  reason: not valid java name */
    public static /* synthetic */ androidx.compose.ui.graphics.vector.ImageVector.Builder m1194materialPathYwgOQQI$default(androidx.compose.ui.graphics.vector.ImageVector.Builder r24, float r25, float r26, int r27, kotlin.jvm.functions.Function1 r28, int r29, java.lang.Object r30) {
        /*
            r0 = r28
            r1 = r29 & 1
            if (r1 == 0) goto L9
            r1 = 1065353216(0x3f800000, float:1.0)
            goto Lb
        L9:
            r1 = r25
        Lb:
            r2 = r29 & 2
            if (r2 == 0) goto L14
            r2 = 1065353216(0x3f800000, float:1.0)
            r19 = r2
            goto L16
        L14:
            r19 = r26
        L16:
            r2 = r29 & 4
            if (r2 == 0) goto L21
            int r2 = androidx.compose.ui.graphics.vector.VectorKt.getDefaultFillType()
            r20 = r2
            goto L23
        L21:
            r20 = r27
        L23:
            java.lang.String r2 = "$this$materialPath"
            r9 = r24
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r2)
            java.lang.String r2 = "pathBuilder"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            r21 = 0
            androidx.compose.ui.graphics.SolidColor r2 = new androidx.compose.ui.graphics.SolidColor
            androidx.compose.ui.graphics.Color$Companion r3 = androidx.compose.ui.graphics.Color.Companion
            long r3 = r3.m2632getBlack0d7_KjU()
            r8 = 0
            r2.<init>(r3, r8)
            r6 = r2
            androidx.compose.ui.graphics.Brush r6 = (androidx.compose.ui.graphics.Brush) r6
            androidx.compose.ui.graphics.StrokeCap$Companion r2 = androidx.compose.ui.graphics.StrokeCap.Companion
            int r11 = r2.m2949getButtKaPHkGw()
            androidx.compose.ui.graphics.StrokeJoin$Companion r2 = androidx.compose.ui.graphics.StrokeJoin.Companion
            int r12 = r2.m2959getBevelLxFBmk8()
            r2 = r24
            r10 = 1065353216(0x3f800000, float:1.0)
            r13 = r10
            java.lang.String r22 = ""
            r5 = r22
            r23 = 0
            r4 = 0
            androidx.compose.ui.graphics.vector.PathBuilder r3 = new androidx.compose.ui.graphics.vector.PathBuilder
            r3.<init>()
            r7 = 0
            r0.invoke(r3)
            java.util.List r3 = r3.getNodes()
            r14 = 0
            r15 = 0
            r16 = 0
            r17 = 14336(0x3800, float:2.0089E-41)
            r18 = 0
            r4 = r20
            r7 = r1
            r9 = r19
            androidx.compose.ui.graphics.vector.ImageVector$Builder r3 = androidx.compose.ui.graphics.vector.ImageVector.Builder.m3227addPathoIyEayM$default(r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18)
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material.icons.IconsKt.m1194materialPathYwgOQQI$default(androidx.compose.ui.graphics.vector.ImageVector$Builder, float, float, int, kotlin.jvm.functions.Function1, int, java.lang.Object):androidx.compose.ui.graphics.vector.ImageVector$Builder");
    }

    /*  JADX ERROR: JadxRuntimeException in pass: InlineMethods
        jadx.core.utils.exceptions.JadxRuntimeException: Failed to process method for inline: androidx.compose.ui.graphics.vector.ImageVector.Builder.addPath-oIyEayM$default(androidx.compose.ui.graphics.vector.ImageVector$Builder, java.util.List, int, java.lang.String, androidx.compose.ui.graphics.Brush, float, androidx.compose.ui.graphics.Brush, float, float, int, int, float, float, float, float, int, java.lang.Object):androidx.compose.ui.graphics.vector.ImageVector$Builder
        	at jadx.core.dex.visitors.InlineMethods.processInvokeInsn(InlineMethods.java:76)
        	at jadx.core.dex.visitors.InlineMethods.visit(InlineMethods.java:51)
        Caused by: java.lang.NullPointerException
        */
    /* renamed from: materialPath-YwgOQQI  reason: not valid java name */
    public static final androidx.compose.ui.graphics.vector.ImageVector.Builder m1193materialPathYwgOQQI(androidx.compose.ui.graphics.vector.ImageVector.Builder r21, float r22, float r23, int r24, kotlin.jvm.functions.Function1<? super androidx.compose.ui.graphics.vector.PathBuilder, kotlin.Unit> r25) {
        /*
            r0 = r25
            r6 = r22
            r8 = r23
            r3 = r24
            java.lang.String r1 = "$this$materialPath"
            r15 = r21
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r15, r1)
            java.lang.String r1 = "pathBuilder"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            r18 = 0
            androidx.compose.ui.graphics.SolidColor r1 = new androidx.compose.ui.graphics.SolidColor
            androidx.compose.ui.graphics.Color$Companion r2 = androidx.compose.ui.graphics.Color.Companion
            long r4 = r2.m2632getBlack0d7_KjU()
            r7 = 0
            r1.<init>(r4, r7)
            r5 = r1
            androidx.compose.ui.graphics.Brush r5 = (androidx.compose.ui.graphics.Brush) r5
            androidx.compose.ui.graphics.StrokeCap$Companion r1 = androidx.compose.ui.graphics.StrokeCap.Companion
            int r10 = r1.m2949getButtKaPHkGw()
            androidx.compose.ui.graphics.StrokeJoin$Companion r1 = androidx.compose.ui.graphics.StrokeJoin.Companion
            int r11 = r1.m2959getBevelLxFBmk8()
            r1 = r21
            r9 = 1065353216(0x3f800000, float:1.0)
            r12 = r9
            java.lang.String r19 = ""
            r4 = r19
            r20 = 0
            r13 = 0
            androidx.compose.ui.graphics.vector.PathBuilder r2 = new androidx.compose.ui.graphics.vector.PathBuilder
            r2.<init>()
            r14 = 0
            r0.invoke(r2)
            java.util.List r2 = r2.getNodes()
            r13 = 0
            r14 = 0
            r16 = 0
            r15 = r16
            r16 = 14336(0x3800, float:2.0089E-41)
            r17 = 0
            androidx.compose.ui.graphics.vector.ImageVector$Builder r2 = androidx.compose.ui.graphics.vector.ImageVector.Builder.m3227addPathoIyEayM$default(r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material.icons.IconsKt.m1193materialPathYwgOQQI(androidx.compose.ui.graphics.vector.ImageVector$Builder, float, float, int, kotlin.jvm.functions.Function1):androidx.compose.ui.graphics.vector.ImageVector$Builder");
    }
}
