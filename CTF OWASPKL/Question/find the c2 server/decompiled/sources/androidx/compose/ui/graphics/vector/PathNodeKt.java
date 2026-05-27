package androidx.compose.ui.graphics.vector;

import androidx.autofill.HintConstants;
import androidx.compose.ui.graphics.vector.PathNode;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.ArraysKt;
import kotlin.collections.CollectionsKt;
import kotlin.collections.IntIterator;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.ranges.RangesKt;
/* compiled from: PathNode.kt */
@Metadata(d1 = {"\u00000\n\u0000\n\u0002\u0010\f\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\u0017\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0014\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\u001aB\u0010\u001f\u001a\b\u0012\u0004\u0012\u00020!0 2\u0006\u0010\"\u001a\u00020#2\u0006\u0010$\u001a\u00020\b2!\u0010%\u001a\u001d\u0012\u0013\u0012\u00110#¢\u0006\f\b'\u0012\b\b(\u0012\u0004\b\b()\u0012\u0004\u0012\u00020!0&H\u0082\b\u001a\u001a\u0010*\u001a\b\u0012\u0004\u0012\u00020!0 *\u00020\u00012\u0006\u0010\"\u001a\u00020#H\u0000\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0002\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0003\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0004\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0005\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0006\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0007\u001a\u00020\bX\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\t\u001a\u00020\bX\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\n\u001a\u00020\bX\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u000b\u001a\u00020\bX\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\f\u001a\u00020\bX\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\r\u001a\u00020\bX\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u000e\u001a\u00020\bX\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u000f\u001a\u00020\bX\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0010\u001a\u00020\bX\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0011\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0012\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0013\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0014\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0015\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0016\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0017\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0018\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0019\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u001a\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u001b\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u001c\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u001d\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u001e\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000¨\u0006+"}, d2 = {"ArcToKey", "", "CloseKey", "CurveToKey", "HorizontalToKey", "LineToKey", "MoveToKey", "NUM_ARC_TO_ARGS", "", "NUM_CURVE_TO_ARGS", "NUM_HORIZONTAL_TO_ARGS", "NUM_LINE_TO_ARGS", "NUM_MOVE_TO_ARGS", "NUM_QUAD_TO_ARGS", "NUM_REFLECTIVE_CURVE_TO_ARGS", "NUM_REFLECTIVE_QUAD_TO_ARGS", "NUM_VERTICAL_TO_ARGS", "QuadToKey", "ReflectiveCurveToKey", "ReflectiveQuadToKey", "RelativeArcToKey", "RelativeCloseKey", "RelativeCurveToKey", "RelativeHorizontalToKey", "RelativeLineToKey", "RelativeMoveToKey", "RelativeQuadToKey", "RelativeReflectiveCurveToKey", "RelativeReflectiveQuadToKey", "RelativeVerticalToKey", "VerticalToKey", "pathNodesFromArgs", "", "Landroidx/compose/ui/graphics/vector/PathNode;", "args", "", "numArgs", "nodeFor", "Lkotlin/Function1;", "Lkotlin/ParameterName;", HintConstants.AUTOFILL_HINT_NAME, "subArray", "toPathNodes", "ui-graphics_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class PathNodeKt {
    private static final char ArcToKey = 'A';
    private static final char CloseKey = 'Z';
    private static final char CurveToKey = 'C';
    private static final char HorizontalToKey = 'H';
    private static final char LineToKey = 'L';
    private static final char MoveToKey = 'M';
    private static final int NUM_ARC_TO_ARGS = 7;
    private static final int NUM_CURVE_TO_ARGS = 6;
    private static final int NUM_HORIZONTAL_TO_ARGS = 1;
    private static final int NUM_LINE_TO_ARGS = 2;
    private static final int NUM_MOVE_TO_ARGS = 2;
    private static final int NUM_QUAD_TO_ARGS = 4;
    private static final int NUM_REFLECTIVE_CURVE_TO_ARGS = 4;
    private static final int NUM_REFLECTIVE_QUAD_TO_ARGS = 2;
    private static final int NUM_VERTICAL_TO_ARGS = 1;
    private static final char QuadToKey = 'Q';
    private static final char ReflectiveCurveToKey = 'S';
    private static final char ReflectiveQuadToKey = 'T';
    private static final char RelativeArcToKey = 'a';
    private static final char RelativeCloseKey = 'z';
    private static final char RelativeCurveToKey = 'c';
    private static final char RelativeHorizontalToKey = 'h';
    private static final char RelativeLineToKey = 'l';
    private static final char RelativeMoveToKey = 'm';
    private static final char RelativeQuadToKey = 'q';
    private static final char RelativeReflectiveCurveToKey = 's';
    private static final char RelativeReflectiveQuadToKey = 't';
    private static final char RelativeVerticalToKey = 'v';
    private static final char VerticalToKey = 'V';

    public static final List<PathNode> toPathNodes(char $this$toPathNodes, float[] args) {
        PathNode.RelativeLineTo relativeLineTo;
        boolean z;
        PathNode.RelativeLineTo relativeLineTo2;
        PathNode.RelativeLineTo relativeLineTo3;
        PathNode.RelativeLineTo relativeLineTo4;
        PathNode.RelativeLineTo relativeLineTo5;
        PathNode.RelativeLineTo relativeLineTo6;
        PathNode.RelativeLineTo relativeLineTo7;
        PathNode.RelativeLineTo relativeLineTo8;
        int numArgs$iv;
        boolean z2;
        Iterable $this$map$iv$iv;
        PathNode.RelativeLineTo relativeLineTo9;
        int numArgs$iv2;
        PathNode.RelativeLineTo relativeLineTo10;
        Iterable $this$map$iv$iv2;
        PathNode.RelativeLineTo relativeLineTo11;
        Iterable $this$map$iv$iv3;
        PathNode.RelativeLineTo relativeLineTo12;
        Iterable $this$map$iv$iv4;
        PathNode.RelativeLineTo relativeLineTo13;
        boolean z3;
        Iterable $this$map$iv$iv5;
        PathNode.RelativeLineTo relativeLineTo14;
        PathNode.RelativeLineTo relativeLineTo15;
        PathNode.RelativeLineTo relativeLineTo16;
        PathNode.RelativeLineTo relativeLineTo17;
        PathNode.RelativeLineTo relativeLineTo18;
        float[] args2 = args;
        Intrinsics.checkNotNullParameter(args2, "args");
        char c = 0;
        if ($this$toPathNodes == 'z' || $this$toPathNodes == 'Z') {
            return CollectionsKt.listOf(PathNode.Close.INSTANCE);
        }
        if ($this$toPathNodes != 'm') {
            if ($this$toPathNodes != 'M') {
                if ($this$toPathNodes != 'l') {
                    if ($this$toPathNodes != 'L') {
                        if ($this$toPathNodes != 'h') {
                            if ($this$toPathNodes != 'H') {
                                if ($this$toPathNodes != 'v') {
                                    if ($this$toPathNodes != 'V') {
                                        char c2 = 4;
                                        char c3 = 3;
                                        char c4 = 2;
                                        if ($this$toPathNodes != 'c') {
                                            if ($this$toPathNodes != 'C') {
                                                if ($this$toPathNodes != 's') {
                                                    if ($this$toPathNodes != 'S') {
                                                        if ($this$toPathNodes != 'q') {
                                                            if ($this$toPathNodes != 'Q') {
                                                                if ($this$toPathNodes != 't') {
                                                                    if ($this$toPathNodes != 'T') {
                                                                        float f = 0.0f;
                                                                        if ($this$toPathNodes != 'a') {
                                                                            if ($this$toPathNodes != 'A') {
                                                                                throw new IllegalArgumentException("Unknown command for: " + $this$toPathNodes);
                                                                            }
                                                                            int numArgs$iv3 = 7;
                                                                            boolean z4 = false;
                                                                            Iterable $this$map$iv$iv6 = RangesKt.step(new IntRange(0, args2.length - 7), 7);
                                                                            Collection destination$iv$iv$iv = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv6, 10));
                                                                            Iterator<Integer> it = $this$map$iv$iv6.iterator();
                                                                            while (it.hasNext()) {
                                                                                int item$iv$iv$iv = ((IntIterator) it).nextInt();
                                                                                float[] subArray$iv = ArraysKt.copyOfRange(args2, item$iv$iv$iv, item$iv$iv$iv + numArgs$iv3);
                                                                                int numArgs$iv4 = numArgs$iv3;
                                                                                boolean z5 = z4;
                                                                                PathNode node$iv = new PathNode.ArcTo(subArray$iv[0], subArray$iv[1], subArray$iv[2], Float.compare(subArray$iv[3], 0.0f) != 0, Float.compare(subArray$iv[4], 0.0f) != 0, subArray$iv[5], subArray$iv[6]);
                                                                                if ((node$iv instanceof PathNode.MoveTo) && item$iv$iv$iv > 0) {
                                                                                    relativeLineTo = new PathNode.LineTo(subArray$iv[0], subArray$iv[1]);
                                                                                } else if ((node$iv instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv > 0) {
                                                                                    relativeLineTo = new PathNode.RelativeLineTo(subArray$iv[0], subArray$iv[1]);
                                                                                } else {
                                                                                    relativeLineTo = node$iv;
                                                                                }
                                                                                destination$iv$iv$iv.add(relativeLineTo);
                                                                                args2 = args;
                                                                                z4 = z5;
                                                                                numArgs$iv3 = numArgs$iv4;
                                                                            }
                                                                            return (List) destination$iv$iv$iv;
                                                                        }
                                                                        int numArgs$iv5 = 7;
                                                                        boolean z6 = false;
                                                                        Iterable $this$map$iv$iv7 = RangesKt.step(new IntRange(0, args2.length - 7), 7);
                                                                        Collection destination$iv$iv$iv2 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv7, 10));
                                                                        Iterator<Integer> it2 = $this$map$iv$iv7.iterator();
                                                                        while (it2.hasNext()) {
                                                                            int item$iv$iv$iv2 = ((IntIterator) it2).nextInt();
                                                                            float[] subArray$iv2 = ArraysKt.copyOfRange(args2, item$iv$iv$iv2, item$iv$iv$iv2 + numArgs$iv5);
                                                                            int numArgs$iv6 = numArgs$iv5;
                                                                            PathNode node$iv2 = new PathNode.RelativeArcTo(subArray$iv2[0], subArray$iv2[1], subArray$iv2[2], Float.compare(subArray$iv2[3], f) != 0, Float.compare(subArray$iv2[4], f) != 0, subArray$iv2[5], subArray$iv2[6]);
                                                                            if (!(node$iv2 instanceof PathNode.MoveTo) || item$iv$iv$iv2 <= 0) {
                                                                                z = z6;
                                                                                if ((node$iv2 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv2 > 0) {
                                                                                    relativeLineTo2 = new PathNode.RelativeLineTo(subArray$iv2[0], subArray$iv2[1]);
                                                                                } else {
                                                                                    relativeLineTo2 = node$iv2;
                                                                                }
                                                                            } else {
                                                                                z = z6;
                                                                                relativeLineTo2 = new PathNode.LineTo(subArray$iv2[0], subArray$iv2[1]);
                                                                            }
                                                                            destination$iv$iv$iv2.add(relativeLineTo2);
                                                                            z6 = z;
                                                                            numArgs$iv5 = numArgs$iv6;
                                                                            f = 0.0f;
                                                                        }
                                                                        return (List) destination$iv$iv$iv2;
                                                                    }
                                                                    int numArgs$iv7 = 2;
                                                                    boolean z7 = false;
                                                                    Iterable $this$map$iv$iv8 = RangesKt.step(new IntRange(0, args2.length - 2), 2);
                                                                    Collection destination$iv$iv$iv3 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv8, 10));
                                                                    Iterator<Integer> it3 = $this$map$iv$iv8.iterator();
                                                                    while (it3.hasNext()) {
                                                                        int item$iv$iv$iv3 = ((IntIterator) it3).nextInt();
                                                                        float[] subArray$iv3 = ArraysKt.copyOfRange(args2, item$iv$iv$iv3, item$iv$iv$iv3 + numArgs$iv7);
                                                                        int numArgs$iv8 = numArgs$iv7;
                                                                        boolean z8 = z7;
                                                                        Iterable $this$map$iv$iv9 = $this$map$iv$iv8;
                                                                        PathNode node$iv3 = new PathNode.ReflectiveQuadTo(subArray$iv3[0], subArray$iv3[1]);
                                                                        if ((node$iv3 instanceof PathNode.MoveTo) && item$iv$iv$iv3 > 0) {
                                                                            relativeLineTo3 = new PathNode.LineTo(subArray$iv3[0], subArray$iv3[1]);
                                                                        } else if ((node$iv3 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv3 > 0) {
                                                                            relativeLineTo3 = new PathNode.RelativeLineTo(subArray$iv3[0], subArray$iv3[1]);
                                                                        } else {
                                                                            relativeLineTo3 = node$iv3;
                                                                        }
                                                                        destination$iv$iv$iv3.add(relativeLineTo3);
                                                                        numArgs$iv7 = numArgs$iv8;
                                                                        $this$map$iv$iv8 = $this$map$iv$iv9;
                                                                        z7 = z8;
                                                                    }
                                                                    return (List) destination$iv$iv$iv3;
                                                                }
                                                                int numArgs$iv9 = 2;
                                                                boolean z9 = false;
                                                                Iterable $this$map$iv$iv10 = RangesKt.step(new IntRange(0, args2.length - 2), 2);
                                                                Collection destination$iv$iv$iv4 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv10, 10));
                                                                Iterator<Integer> it4 = $this$map$iv$iv10.iterator();
                                                                while (it4.hasNext()) {
                                                                    int item$iv$iv$iv4 = ((IntIterator) it4).nextInt();
                                                                    float[] subArray$iv4 = ArraysKt.copyOfRange(args2, item$iv$iv$iv4, item$iv$iv$iv4 + numArgs$iv9);
                                                                    int numArgs$iv10 = numArgs$iv9;
                                                                    boolean z10 = z9;
                                                                    Iterable $this$map$iv$iv11 = $this$map$iv$iv10;
                                                                    PathNode node$iv4 = new PathNode.RelativeReflectiveQuadTo(subArray$iv4[0], subArray$iv4[1]);
                                                                    if ((node$iv4 instanceof PathNode.MoveTo) && item$iv$iv$iv4 > 0) {
                                                                        relativeLineTo4 = new PathNode.LineTo(subArray$iv4[0], subArray$iv4[1]);
                                                                    } else if ((node$iv4 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv4 > 0) {
                                                                        relativeLineTo4 = new PathNode.RelativeLineTo(subArray$iv4[0], subArray$iv4[1]);
                                                                    } else {
                                                                        relativeLineTo4 = node$iv4;
                                                                    }
                                                                    destination$iv$iv$iv4.add(relativeLineTo4);
                                                                    numArgs$iv9 = numArgs$iv10;
                                                                    $this$map$iv$iv10 = $this$map$iv$iv11;
                                                                    z9 = z10;
                                                                }
                                                                return (List) destination$iv$iv$iv4;
                                                            }
                                                            int numArgs$iv11 = 4;
                                                            boolean z11 = false;
                                                            Iterable $this$map$iv$iv12 = RangesKt.step(new IntRange(0, args2.length - 4), 4);
                                                            boolean z12 = false;
                                                            Collection destination$iv$iv$iv5 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv12, 10));
                                                            Iterable $this$mapTo$iv$iv$iv = $this$map$iv$iv12;
                                                            Iterator<Integer> it5 = $this$mapTo$iv$iv$iv.iterator();
                                                            while (it5.hasNext()) {
                                                                int item$iv$iv$iv5 = ((IntIterator) it5).nextInt();
                                                                float[] subArray$iv5 = ArraysKt.copyOfRange(args2, item$iv$iv$iv5, item$iv$iv$iv5 + numArgs$iv11);
                                                                int numArgs$iv12 = numArgs$iv11;
                                                                boolean z13 = z11;
                                                                Iterable $this$map$iv$iv13 = $this$map$iv$iv12;
                                                                boolean z14 = z12;
                                                                Iterable $this$mapTo$iv$iv$iv2 = $this$mapTo$iv$iv$iv;
                                                                PathNode node$iv5 = new PathNode.QuadTo(subArray$iv5[0], subArray$iv5[1], subArray$iv5[2], subArray$iv5[3]);
                                                                if ((node$iv5 instanceof PathNode.MoveTo) && item$iv$iv$iv5 > 0) {
                                                                    relativeLineTo5 = new PathNode.LineTo(subArray$iv5[0], subArray$iv5[1]);
                                                                } else if ((node$iv5 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv5 > 0) {
                                                                    relativeLineTo5 = new PathNode.RelativeLineTo(subArray$iv5[0], subArray$iv5[1]);
                                                                } else {
                                                                    relativeLineTo5 = node$iv5;
                                                                }
                                                                destination$iv$iv$iv5.add(relativeLineTo5);
                                                                numArgs$iv11 = numArgs$iv12;
                                                                $this$map$iv$iv12 = $this$map$iv$iv13;
                                                                z11 = z13;
                                                                z12 = z14;
                                                                $this$mapTo$iv$iv$iv = $this$mapTo$iv$iv$iv2;
                                                            }
                                                            return (List) destination$iv$iv$iv5;
                                                        }
                                                        int numArgs$iv13 = 4;
                                                        boolean z15 = false;
                                                        Iterable $this$map$iv$iv14 = RangesKt.step(new IntRange(0, args2.length - 4), 4);
                                                        boolean z16 = false;
                                                        Collection destination$iv$iv$iv6 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv14, 10));
                                                        Iterable $this$mapTo$iv$iv$iv3 = $this$map$iv$iv14;
                                                        Iterator<Integer> it6 = $this$mapTo$iv$iv$iv3.iterator();
                                                        while (it6.hasNext()) {
                                                            int item$iv$iv$iv6 = ((IntIterator) it6).nextInt();
                                                            float[] subArray$iv6 = ArraysKt.copyOfRange(args2, item$iv$iv$iv6, item$iv$iv$iv6 + numArgs$iv13);
                                                            int numArgs$iv14 = numArgs$iv13;
                                                            boolean z17 = z15;
                                                            Iterable $this$map$iv$iv15 = $this$map$iv$iv14;
                                                            boolean z18 = z16;
                                                            Iterable $this$mapTo$iv$iv$iv4 = $this$mapTo$iv$iv$iv3;
                                                            PathNode node$iv6 = new PathNode.RelativeQuadTo(subArray$iv6[0], subArray$iv6[1], subArray$iv6[2], subArray$iv6[3]);
                                                            if ((node$iv6 instanceof PathNode.MoveTo) && item$iv$iv$iv6 > 0) {
                                                                relativeLineTo6 = new PathNode.LineTo(subArray$iv6[0], subArray$iv6[1]);
                                                            } else if ((node$iv6 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv6 > 0) {
                                                                relativeLineTo6 = new PathNode.RelativeLineTo(subArray$iv6[0], subArray$iv6[1]);
                                                            } else {
                                                                relativeLineTo6 = node$iv6;
                                                            }
                                                            destination$iv$iv$iv6.add(relativeLineTo6);
                                                            numArgs$iv13 = numArgs$iv14;
                                                            $this$map$iv$iv14 = $this$map$iv$iv15;
                                                            z15 = z17;
                                                            z16 = z18;
                                                            $this$mapTo$iv$iv$iv3 = $this$mapTo$iv$iv$iv4;
                                                        }
                                                        return (List) destination$iv$iv$iv6;
                                                    }
                                                    int numArgs$iv15 = 4;
                                                    boolean z19 = false;
                                                    Iterable $this$map$iv$iv16 = RangesKt.step(new IntRange(0, args2.length - 4), 4);
                                                    boolean z20 = false;
                                                    Collection destination$iv$iv$iv7 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv16, 10));
                                                    Iterable $this$mapTo$iv$iv$iv5 = $this$map$iv$iv16;
                                                    Iterator<Integer> it7 = $this$mapTo$iv$iv$iv5.iterator();
                                                    while (it7.hasNext()) {
                                                        int item$iv$iv$iv7 = ((IntIterator) it7).nextInt();
                                                        float[] subArray$iv7 = ArraysKt.copyOfRange(args2, item$iv$iv$iv7, item$iv$iv$iv7 + numArgs$iv15);
                                                        int numArgs$iv16 = numArgs$iv15;
                                                        boolean z21 = z19;
                                                        Iterable $this$map$iv$iv17 = $this$map$iv$iv16;
                                                        boolean z22 = z20;
                                                        Iterable $this$mapTo$iv$iv$iv6 = $this$mapTo$iv$iv$iv5;
                                                        PathNode node$iv7 = new PathNode.ReflectiveCurveTo(subArray$iv7[0], subArray$iv7[1], subArray$iv7[2], subArray$iv7[3]);
                                                        if ((node$iv7 instanceof PathNode.MoveTo) && item$iv$iv$iv7 > 0) {
                                                            relativeLineTo7 = new PathNode.LineTo(subArray$iv7[0], subArray$iv7[1]);
                                                        } else if ((node$iv7 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv7 > 0) {
                                                            relativeLineTo7 = new PathNode.RelativeLineTo(subArray$iv7[0], subArray$iv7[1]);
                                                        } else {
                                                            relativeLineTo7 = node$iv7;
                                                        }
                                                        destination$iv$iv$iv7.add(relativeLineTo7);
                                                        numArgs$iv15 = numArgs$iv16;
                                                        $this$map$iv$iv16 = $this$map$iv$iv17;
                                                        z19 = z21;
                                                        z20 = z22;
                                                        $this$mapTo$iv$iv$iv5 = $this$mapTo$iv$iv$iv6;
                                                    }
                                                    return (List) destination$iv$iv$iv7;
                                                }
                                                int numArgs$iv17 = 4;
                                                boolean z23 = false;
                                                Iterable $this$map$iv$iv18 = RangesKt.step(new IntRange(0, args2.length - 4), 4);
                                                boolean z24 = false;
                                                Collection destination$iv$iv$iv8 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv18, 10));
                                                Iterable $this$mapTo$iv$iv$iv7 = $this$map$iv$iv18;
                                                Iterator<Integer> it8 = $this$mapTo$iv$iv$iv7.iterator();
                                                while (it8.hasNext()) {
                                                    int item$iv$iv$iv8 = ((IntIterator) it8).nextInt();
                                                    float[] subArray$iv8 = ArraysKt.copyOfRange(args2, item$iv$iv$iv8, item$iv$iv$iv8 + numArgs$iv17);
                                                    int numArgs$iv18 = numArgs$iv17;
                                                    boolean z25 = z23;
                                                    Iterable $this$map$iv$iv19 = $this$map$iv$iv18;
                                                    boolean z26 = z24;
                                                    Iterable $this$mapTo$iv$iv$iv8 = $this$mapTo$iv$iv$iv7;
                                                    PathNode node$iv8 = new PathNode.RelativeReflectiveCurveTo(subArray$iv8[0], subArray$iv8[1], subArray$iv8[2], subArray$iv8[3]);
                                                    if ((node$iv8 instanceof PathNode.MoveTo) && item$iv$iv$iv8 > 0) {
                                                        relativeLineTo8 = new PathNode.LineTo(subArray$iv8[0], subArray$iv8[1]);
                                                    } else if ((node$iv8 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv8 > 0) {
                                                        relativeLineTo8 = new PathNode.RelativeLineTo(subArray$iv8[0], subArray$iv8[1]);
                                                    } else {
                                                        relativeLineTo8 = node$iv8;
                                                    }
                                                    destination$iv$iv$iv8.add(relativeLineTo8);
                                                    numArgs$iv17 = numArgs$iv18;
                                                    $this$map$iv$iv18 = $this$map$iv$iv19;
                                                    z23 = z25;
                                                    z24 = z26;
                                                    $this$mapTo$iv$iv$iv7 = $this$mapTo$iv$iv$iv8;
                                                }
                                                return (List) destination$iv$iv$iv8;
                                            }
                                            int numArgs$iv19 = 6;
                                            boolean z27 = false;
                                            Iterable $this$map$iv$iv20 = RangesKt.step(new IntRange(0, args2.length - 6), 6);
                                            Collection destination$iv$iv$iv9 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv20, 10));
                                            Iterator<Integer> it9 = $this$map$iv$iv20.iterator();
                                            while (it9.hasNext()) {
                                                int item$iv$iv$iv9 = ((IntIterator) it9).nextInt();
                                                float[] subArray$iv9 = ArraysKt.copyOfRange(args2, item$iv$iv$iv9, item$iv$iv$iv9 + numArgs$iv19);
                                                PathNode node$iv9 = new PathNode.CurveTo(subArray$iv9[0], subArray$iv9[1], subArray$iv9[2], subArray$iv9[3], subArray$iv9[4], subArray$iv9[5]);
                                                if (!(node$iv9 instanceof PathNode.MoveTo) || item$iv$iv$iv9 <= 0) {
                                                    numArgs$iv = numArgs$iv19;
                                                    z2 = z27;
                                                    if (!(node$iv9 instanceof PathNode.RelativeMoveTo) || item$iv$iv$iv9 <= 0) {
                                                        $this$map$iv$iv = $this$map$iv$iv20;
                                                        relativeLineTo9 = node$iv9;
                                                    } else {
                                                        $this$map$iv$iv = $this$map$iv$iv20;
                                                        relativeLineTo9 = new PathNode.RelativeLineTo(subArray$iv9[0], subArray$iv9[1]);
                                                    }
                                                } else {
                                                    numArgs$iv = numArgs$iv19;
                                                    z2 = z27;
                                                    relativeLineTo9 = new PathNode.LineTo(subArray$iv9[0], subArray$iv9[1]);
                                                    $this$map$iv$iv = $this$map$iv$iv20;
                                                }
                                                destination$iv$iv$iv9.add(relativeLineTo9);
                                                $this$map$iv$iv20 = $this$map$iv$iv;
                                                numArgs$iv19 = numArgs$iv;
                                                z27 = z2;
                                            }
                                            return (List) destination$iv$iv$iv9;
                                        }
                                        int numArgs$iv20 = 6;
                                        Iterable $this$map$iv$iv21 = RangesKt.step(new IntRange(0, args2.length - 6), 6);
                                        Collection destination$iv$iv$iv10 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv21, 10));
                                        Iterator<Integer> it10 = $this$map$iv$iv21.iterator();
                                        while (it10.hasNext()) {
                                            int item$iv$iv$iv10 = ((IntIterator) it10).nextInt();
                                            float[] subArray$iv10 = ArraysKt.copyOfRange(args2, item$iv$iv$iv10, item$iv$iv$iv10 + numArgs$iv20);
                                            PathNode node$iv10 = new PathNode.RelativeCurveTo(subArray$iv10[0], subArray$iv10[1], subArray$iv10[c4], subArray$iv10[c3], subArray$iv10[c2], subArray$iv10[5]);
                                            if (!(node$iv10 instanceof PathNode.MoveTo) || item$iv$iv$iv10 <= 0) {
                                                numArgs$iv2 = numArgs$iv20;
                                                if ((node$iv10 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv10 > 0) {
                                                    relativeLineTo10 = new PathNode.RelativeLineTo(subArray$iv10[0], subArray$iv10[1]);
                                                } else {
                                                    relativeLineTo10 = node$iv10;
                                                }
                                            } else {
                                                numArgs$iv2 = numArgs$iv20;
                                                relativeLineTo10 = new PathNode.LineTo(subArray$iv10[0], subArray$iv10[1]);
                                            }
                                            destination$iv$iv$iv10.add(relativeLineTo10);
                                            numArgs$iv20 = numArgs$iv2;
                                            c2 = 4;
                                            c3 = 3;
                                            c4 = 2;
                                        }
                                        return (List) destination$iv$iv$iv10;
                                    }
                                    int numArgs$iv21 = 1;
                                    boolean z28 = false;
                                    Iterable $this$map$iv$iv22 = RangesKt.step(new IntRange(0, args2.length - 1), 1);
                                    Collection destination$iv$iv$iv11 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv22, 10));
                                    Iterator<Integer> it11 = $this$map$iv$iv22.iterator();
                                    while (it11.hasNext()) {
                                        int item$iv$iv$iv11 = ((IntIterator) it11).nextInt();
                                        float[] subArray$iv11 = ArraysKt.copyOfRange(args2, item$iv$iv$iv11, item$iv$iv$iv11 + numArgs$iv21);
                                        int numArgs$iv22 = numArgs$iv21;
                                        boolean z29 = z28;
                                        PathNode node$iv11 = new PathNode.VerticalTo(subArray$iv11[0]);
                                        if (!(node$iv11 instanceof PathNode.MoveTo) || item$iv$iv$iv11 <= 0) {
                                            $this$map$iv$iv2 = $this$map$iv$iv22;
                                            if ((node$iv11 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv11 > 0) {
                                                relativeLineTo11 = new PathNode.RelativeLineTo(subArray$iv11[0], subArray$iv11[1]);
                                            } else {
                                                relativeLineTo11 = node$iv11;
                                            }
                                        } else {
                                            $this$map$iv$iv2 = $this$map$iv$iv22;
                                            relativeLineTo11 = new PathNode.LineTo(subArray$iv11[0], subArray$iv11[1]);
                                        }
                                        destination$iv$iv$iv11.add(relativeLineTo11);
                                        numArgs$iv21 = numArgs$iv22;
                                        $this$map$iv$iv22 = $this$map$iv$iv2;
                                        z28 = z29;
                                    }
                                    return (List) destination$iv$iv$iv11;
                                }
                                int numArgs$iv23 = 1;
                                boolean z30 = false;
                                Iterable $this$map$iv$iv23 = RangesKt.step(new IntRange(0, args2.length - 1), 1);
                                Collection destination$iv$iv$iv12 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv23, 10));
                                Iterator<Integer> it12 = $this$map$iv$iv23.iterator();
                                while (it12.hasNext()) {
                                    int item$iv$iv$iv12 = ((IntIterator) it12).nextInt();
                                    float[] subArray$iv12 = ArraysKt.copyOfRange(args2, item$iv$iv$iv12, item$iv$iv$iv12 + numArgs$iv23);
                                    int numArgs$iv24 = numArgs$iv23;
                                    boolean z31 = z30;
                                    PathNode node$iv12 = new PathNode.RelativeVerticalTo(subArray$iv12[0]);
                                    if (!(node$iv12 instanceof PathNode.MoveTo) || item$iv$iv$iv12 <= 0) {
                                        $this$map$iv$iv3 = $this$map$iv$iv23;
                                        if ((node$iv12 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv12 > 0) {
                                            relativeLineTo12 = new PathNode.RelativeLineTo(subArray$iv12[0], subArray$iv12[1]);
                                        } else {
                                            relativeLineTo12 = node$iv12;
                                        }
                                    } else {
                                        $this$map$iv$iv3 = $this$map$iv$iv23;
                                        relativeLineTo12 = new PathNode.LineTo(subArray$iv12[0], subArray$iv12[1]);
                                    }
                                    destination$iv$iv$iv12.add(relativeLineTo12);
                                    numArgs$iv23 = numArgs$iv24;
                                    $this$map$iv$iv23 = $this$map$iv$iv3;
                                    z30 = z31;
                                }
                                return (List) destination$iv$iv$iv12;
                            }
                            int numArgs$iv25 = 1;
                            boolean z32 = false;
                            Iterable $this$map$iv$iv24 = RangesKt.step(new IntRange(0, args2.length - 1), 1);
                            Collection destination$iv$iv$iv13 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv24, 10));
                            Iterator<Integer> it13 = $this$map$iv$iv24.iterator();
                            while (it13.hasNext()) {
                                int item$iv$iv$iv13 = ((IntIterator) it13).nextInt();
                                float[] subArray$iv13 = ArraysKt.copyOfRange(args2, item$iv$iv$iv13, item$iv$iv$iv13 + numArgs$iv25);
                                int numArgs$iv26 = numArgs$iv25;
                                boolean z33 = z32;
                                PathNode node$iv13 = new PathNode.HorizontalTo(subArray$iv13[0]);
                                if (!(node$iv13 instanceof PathNode.MoveTo) || item$iv$iv$iv13 <= 0) {
                                    $this$map$iv$iv4 = $this$map$iv$iv24;
                                    if ((node$iv13 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv13 > 0) {
                                        relativeLineTo13 = new PathNode.RelativeLineTo(subArray$iv13[0], subArray$iv13[1]);
                                    } else {
                                        relativeLineTo13 = node$iv13;
                                    }
                                } else {
                                    $this$map$iv$iv4 = $this$map$iv$iv24;
                                    relativeLineTo13 = new PathNode.LineTo(subArray$iv13[0], subArray$iv13[1]);
                                }
                                destination$iv$iv$iv13.add(relativeLineTo13);
                                numArgs$iv25 = numArgs$iv26;
                                $this$map$iv$iv24 = $this$map$iv$iv4;
                                z32 = z33;
                            }
                            return (List) destination$iv$iv$iv13;
                        }
                        int numArgs$iv27 = 1;
                        boolean z34 = false;
                        Iterable $this$map$iv$iv25 = RangesKt.step(new IntRange(0, args2.length - 1), 1);
                        Collection destination$iv$iv$iv14 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv25, 10));
                        Iterator<Integer> it14 = $this$map$iv$iv25.iterator();
                        while (it14.hasNext()) {
                            int item$iv$iv$iv14 = ((IntIterator) it14).nextInt();
                            float[] subArray$iv14 = ArraysKt.copyOfRange(args2, item$iv$iv$iv14, item$iv$iv$iv14 + numArgs$iv27);
                            int numArgs$iv28 = numArgs$iv27;
                            PathNode node$iv14 = new PathNode.RelativeHorizontalTo(subArray$iv14[0]);
                            if (!(node$iv14 instanceof PathNode.MoveTo) || item$iv$iv$iv14 <= 0) {
                                z3 = z34;
                                $this$map$iv$iv5 = $this$map$iv$iv25;
                                if ((node$iv14 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv14 > 0) {
                                    relativeLineTo14 = new PathNode.RelativeLineTo(subArray$iv14[0], subArray$iv14[1]);
                                } else {
                                    relativeLineTo14 = node$iv14;
                                }
                            } else {
                                z3 = z34;
                                $this$map$iv$iv5 = $this$map$iv$iv25;
                                relativeLineTo14 = new PathNode.LineTo(subArray$iv14[0], subArray$iv14[1]);
                            }
                            destination$iv$iv$iv14.add(relativeLineTo14);
                            z34 = z3;
                            $this$map$iv$iv25 = $this$map$iv$iv5;
                            numArgs$iv27 = numArgs$iv28;
                        }
                        return (List) destination$iv$iv$iv14;
                    }
                    int numArgs$iv29 = 2;
                    boolean z35 = false;
                    Iterable $this$map$iv$iv26 = RangesKt.step(new IntRange(0, args2.length - 2), 2);
                    Collection destination$iv$iv$iv15 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv26, 10));
                    Iterator<Integer> it15 = $this$map$iv$iv26.iterator();
                    while (it15.hasNext()) {
                        int item$iv$iv$iv15 = ((IntIterator) it15).nextInt();
                        float[] subArray$iv15 = ArraysKt.copyOfRange(args2, item$iv$iv$iv15, item$iv$iv$iv15 + numArgs$iv29);
                        int numArgs$iv30 = numArgs$iv29;
                        boolean z36 = z35;
                        Iterable $this$map$iv$iv27 = $this$map$iv$iv26;
                        PathNode node$iv15 = new PathNode.LineTo(subArray$iv15[0], subArray$iv15[1]);
                        if ((node$iv15 instanceof PathNode.MoveTo) && item$iv$iv$iv15 > 0) {
                            relativeLineTo15 = new PathNode.LineTo(subArray$iv15[0], subArray$iv15[1]);
                        } else if ((node$iv15 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv15 > 0) {
                            relativeLineTo15 = new PathNode.RelativeLineTo(subArray$iv15[0], subArray$iv15[1]);
                        } else {
                            relativeLineTo15 = node$iv15;
                        }
                        destination$iv$iv$iv15.add(relativeLineTo15);
                        numArgs$iv29 = numArgs$iv30;
                        $this$map$iv$iv26 = $this$map$iv$iv27;
                        z35 = z36;
                    }
                    return (List) destination$iv$iv$iv15;
                }
                int numArgs$iv31 = 2;
                boolean z37 = false;
                Iterable $this$map$iv$iv28 = RangesKt.step(new IntRange(0, args2.length - 2), 2);
                Collection destination$iv$iv$iv16 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv28, 10));
                Iterator<Integer> it16 = $this$map$iv$iv28.iterator();
                while (it16.hasNext()) {
                    int item$iv$iv$iv16 = ((IntIterator) it16).nextInt();
                    float[] subArray$iv16 = ArraysKt.copyOfRange(args2, item$iv$iv$iv16, item$iv$iv$iv16 + numArgs$iv31);
                    int numArgs$iv32 = numArgs$iv31;
                    boolean z38 = z37;
                    Iterable $this$map$iv$iv29 = $this$map$iv$iv28;
                    PathNode node$iv16 = new PathNode.RelativeLineTo(subArray$iv16[0], subArray$iv16[1]);
                    if ((node$iv16 instanceof PathNode.MoveTo) && item$iv$iv$iv16 > 0) {
                        relativeLineTo16 = new PathNode.LineTo(subArray$iv16[0], subArray$iv16[1]);
                    } else if ((node$iv16 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv16 > 0) {
                        relativeLineTo16 = new PathNode.RelativeLineTo(subArray$iv16[0], subArray$iv16[1]);
                    } else {
                        relativeLineTo16 = node$iv16;
                    }
                    destination$iv$iv$iv16.add(relativeLineTo16);
                    numArgs$iv31 = numArgs$iv32;
                    $this$map$iv$iv28 = $this$map$iv$iv29;
                    z37 = z38;
                }
                return (List) destination$iv$iv$iv16;
            }
            int numArgs$iv33 = 2;
            boolean z39 = false;
            Iterable $this$map$iv$iv30 = RangesKt.step(new IntRange(0, args2.length - 2), 2);
            Collection destination$iv$iv$iv17 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv30, 10));
            Iterator<Integer> it17 = $this$map$iv$iv30.iterator();
            while (it17.hasNext()) {
                int item$iv$iv$iv17 = ((IntIterator) it17).nextInt();
                float[] subArray$iv17 = ArraysKt.copyOfRange(args2, item$iv$iv$iv17, item$iv$iv$iv17 + numArgs$iv33);
                int numArgs$iv34 = numArgs$iv33;
                boolean z40 = z39;
                Iterable $this$map$iv$iv31 = $this$map$iv$iv30;
                PathNode node$iv17 = new PathNode.MoveTo(subArray$iv17[0], subArray$iv17[1]);
                if (item$iv$iv$iv17 > 0) {
                    relativeLineTo17 = new PathNode.LineTo(subArray$iv17[0], subArray$iv17[1]);
                } else if ((node$iv17 instanceof PathNode.RelativeMoveTo) && item$iv$iv$iv17 > 0) {
                    relativeLineTo17 = new PathNode.RelativeLineTo(subArray$iv17[0], subArray$iv17[1]);
                } else {
                    relativeLineTo17 = node$iv17;
                }
                destination$iv$iv$iv17.add(relativeLineTo17);
                numArgs$iv33 = numArgs$iv34;
                z39 = z40;
                $this$map$iv$iv30 = $this$map$iv$iv31;
            }
            return (List) destination$iv$iv$iv17;
        }
        int numArgs$iv35 = 2;
        boolean z41 = false;
        Iterable $this$map$iv$iv32 = RangesKt.step(new IntRange(0, args2.length - 2), 2);
        Collection destination$iv$iv$iv18 = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv$iv32, 10));
        Iterator<Integer> it18 = $this$map$iv$iv32.iterator();
        while (it18.hasNext()) {
            int item$iv$iv$iv18 = ((IntIterator) it18).nextInt();
            float[] subArray$iv18 = ArraysKt.copyOfRange(args2, item$iv$iv$iv18, item$iv$iv$iv18 + numArgs$iv35);
            int numArgs$iv36 = numArgs$iv35;
            boolean z42 = z41;
            PathNode node$iv18 = new PathNode.RelativeMoveTo(subArray$iv18[c], subArray$iv18[1]);
            if ((node$iv18 instanceof PathNode.MoveTo) && item$iv$iv$iv18 > 0) {
                relativeLineTo18 = new PathNode.LineTo(subArray$iv18[0], subArray$iv18[1]);
            } else if (item$iv$iv$iv18 > 0) {
                relativeLineTo18 = new PathNode.RelativeLineTo(subArray$iv18[0], subArray$iv18[1]);
            } else {
                relativeLineTo18 = node$iv18;
            }
            destination$iv$iv$iv18.add(relativeLineTo18);
            numArgs$iv35 = numArgs$iv36;
            z41 = z42;
            c = 0;
        }
        return (List) destination$iv$iv$iv18;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r13v1, types: [float[], java.lang.Object] */
    private static final List<PathNode> pathNodesFromArgs(float[] args, int numArgs, Function1<? super float[], ? extends PathNode> function1) {
        PathNode.RelativeLineTo relativeLineTo;
        float[] fArr = args;
        int i = numArgs;
        Iterable $this$map$iv = RangesKt.step(new IntRange(0, fArr.length - i), i);
        Collection destination$iv$iv = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv, 10));
        Iterator<Integer> it = $this$map$iv.iterator();
        while (it.hasNext()) {
            int item$iv$iv = ((IntIterator) it).nextInt();
            ?? copyOfRange = ArraysKt.copyOfRange(fArr, item$iv$iv, item$iv$iv + i);
            PathNode node = function1.invoke(copyOfRange);
            if ((node instanceof PathNode.MoveTo) && item$iv$iv > 0) {
                relativeLineTo = new PathNode.LineTo(copyOfRange[0], copyOfRange[1]);
            } else if ((node instanceof PathNode.RelativeMoveTo) && item$iv$iv > 0) {
                relativeLineTo = new PathNode.RelativeLineTo(copyOfRange[0], copyOfRange[1]);
            } else {
                relativeLineTo = node;
            }
            destination$iv$iv.add(relativeLineTo);
            fArr = args;
            i = numArgs;
        }
        return (List) destination$iv$iv;
    }
}
