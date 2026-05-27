package androidx.compose.ui.graphics.vector;

import androidx.compose.ui.graphics.AndroidPath_androidKt;
import androidx.compose.ui.graphics.Path;
import androidx.compose.ui.graphics.vector.PathNode;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.ArraysKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: PathParser.kt */
@Metadata(d1 = {"\u0000Þ\u0001\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\f\n\u0000\n\u0002\u0010\u0014\n\u0000\n\u0002\u0010 \n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0006\n\u0002\b\r\n\u0002\u0010\b\n\u0002\b\u0007\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\u0018\u00002\u00020\u0001:\u0002bcB\u0005¢\u0006\u0002\u0010\u0002J\u0018\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\u0010H\u0002J\u0014\u0010\u0011\u001a\u00020\u00002\f\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\b0\u0012JX\u0010\u0013\u001a\u00020\f2\u0006\u0010\u0014\u001a\u00020\u00152\u0006\u0010\u0016\u001a\u00020\u00172\u0006\u0010\u0018\u001a\u00020\u00172\u0006\u0010\u0019\u001a\u00020\u00172\u0006\u0010\u001a\u001a\u00020\u00172\u0006\u0010\u001b\u001a\u00020\u00172\u0006\u0010\u001c\u001a\u00020\u00172\u0006\u0010\u001d\u001a\u00020\u00172\u0006\u0010\u001e\u001a\u00020\u00172\u0006\u0010\u001f\u001a\u00020\u0017H\u0002J\u0006\u0010 \u001a\u00020\fJ\u0010\u0010!\u001a\u00020\f2\u0006\u0010\"\u001a\u00020\u0015H\u0002J \u0010#\u001a\u00020\u00102\u0006\u0010$\u001a\u00020\u00102\u0006\u0010\u001e\u001a\u00020%2\u0006\u0010&\u001a\u00020%H\u0002JX\u0010'\u001a\u00020\f2\u0006\u0010\u0014\u001a\u00020\u00152\u0006\u0010(\u001a\u00020\u00172\u0006\u0010)\u001a\u00020\u00172\u0006\u0010*\u001a\u00020\u00172\u0006\u0010+\u001a\u00020\u00172\u0006\u0010\u0019\u001a\u00020\u00172\u0006\u0010\u001a\u001a\u00020\u00172\u0006\u0010\u001d\u001a\u00020\u00172\u0006\u0010,\u001a\u00020-2\u0006\u0010.\u001a\u00020-H\u0002J \u0010/\u001a\u00020\f2\u0006\u00100\u001a\u0002012\u0006\u0010\u001e\u001a\u00020%2\u0006\u00102\u001a\u000203H\u0002J\u0010\u00104\u001a\u00020\u00102\u0006\u00100\u001a\u000201H\u0002J\u0018\u00105\u001a\u00020%2\u0006\u00100\u001a\u0002012\u0006\u0010&\u001a\u00020%H\u0002J\u000e\u00106\u001a\u00020\u00002\u0006\u00107\u001a\u000201J\f\u00108\u001a\b\u0012\u0004\u0012\u00020\b0\u0012J\u0010\u00109\u001a\u00020\u00152\b\b\u0002\u0010\"\u001a\u00020\u0015J\u0014\u0010:\u001a\u00020\f*\u00020;2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u0014\u0010<\u001a\u00020\f*\u00020=2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u0014\u0010>\u001a\u00020\f*\u00020?2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u0014\u0010@\u001a\u00020\f*\u00020A2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u0014\u0010B\u001a\u00020\f*\u00020C2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u0014\u0010D\u001a\u00020\f*\u00020E2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u001c\u0010F\u001a\u00020\f*\u00020G2\u0006\u0010H\u001a\u00020-2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u001c\u0010I\u001a\u00020\f*\u00020J2\u0006\u0010K\u001a\u00020-2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u0014\u0010L\u001a\u00020\f*\u00020M2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u0014\u0010N\u001a\u00020\f*\u00020O2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u0014\u0010P\u001a\u00020\f*\u00020Q2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u0014\u0010R\u001a\u00020\f*\u00020S2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u0014\u0010T\u001a\u00020\f*\u00020U2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u0014\u0010V\u001a\u00020\f*\u00020W2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u001c\u0010X\u001a\u00020\f*\u00020Y2\u0006\u0010H\u001a\u00020-2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u001c\u0010Z\u001a\u00020\f*\u00020[2\u0006\u0010K\u001a\u00020-2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\u0014\u0010\\\u001a\u00020\f*\u00020]2\u0006\u0010\"\u001a\u00020\u0015H\u0002J\f\u0010^\u001a\u00020\u0017*\u00020\u0017H\u0002J\f\u0010^\u001a\u00020_*\u00020_H\u0002J\u0014\u0010`\u001a\u00020\f*\u00020a2\u0006\u0010\"\u001a\u00020\u0015H\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0004X\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\b0\u0007X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\u0004X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u0004X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006d"}, d2 = {"Landroidx/compose/ui/graphics/vector/PathParser;", "", "()V", "ctrlPoint", "Landroidx/compose/ui/graphics/vector/PathParser$PathPoint;", "currentPoint", "nodes", "", "Landroidx/compose/ui/graphics/vector/PathNode;", "reflectiveCtrlPoint", "segmentPoint", "addNode", "", "cmd", "", "args", "", "addPathNodes", "", "arcToBezier", "p", "Landroidx/compose/ui/graphics/Path;", "cx", "", "cy", "a", "b", "e1x", "e1y", "theta", "start", "sweep", "clear", "close", "target", "copyOfRange", "original", "", "end", "drawArc", "x0", "y0", "x1", "y1", "isMoreThanHalf", "", "isPositiveArc", "extract", "s", "", "result", "Landroidx/compose/ui/graphics/vector/PathParser$ExtractFloatResult;", "getFloats", "nextStart", "parsePathString", "pathData", "toNodes", "toPath", "arcTo", "Landroidx/compose/ui/graphics/vector/PathNode$ArcTo;", "curveTo", "Landroidx/compose/ui/graphics/vector/PathNode$CurveTo;", "horizontalTo", "Landroidx/compose/ui/graphics/vector/PathNode$HorizontalTo;", "lineTo", "Landroidx/compose/ui/graphics/vector/PathNode$LineTo;", "moveTo", "Landroidx/compose/ui/graphics/vector/PathNode$MoveTo;", "quadTo", "Landroidx/compose/ui/graphics/vector/PathNode$QuadTo;", "reflectiveCurveTo", "Landroidx/compose/ui/graphics/vector/PathNode$ReflectiveCurveTo;", "prevIsCurve", "reflectiveQuadTo", "Landroidx/compose/ui/graphics/vector/PathNode$ReflectiveQuadTo;", "prevIsQuad", "relativeArcTo", "Landroidx/compose/ui/graphics/vector/PathNode$RelativeArcTo;", "relativeCurveTo", "Landroidx/compose/ui/graphics/vector/PathNode$RelativeCurveTo;", "relativeHorizontalTo", "Landroidx/compose/ui/graphics/vector/PathNode$RelativeHorizontalTo;", "relativeLineTo", "Landroidx/compose/ui/graphics/vector/PathNode$RelativeLineTo;", "relativeMoveTo", "Landroidx/compose/ui/graphics/vector/PathNode$RelativeMoveTo;", "relativeQuadTo", "Landroidx/compose/ui/graphics/vector/PathNode$RelativeQuadTo;", "relativeReflectiveCurveTo", "Landroidx/compose/ui/graphics/vector/PathNode$RelativeReflectiveCurveTo;", "relativeReflectiveQuadTo", "Landroidx/compose/ui/graphics/vector/PathNode$RelativeReflectiveQuadTo;", "relativeVerticalTo", "Landroidx/compose/ui/graphics/vector/PathNode$RelativeVerticalTo;", "toRadians", "", "verticalTo", "Landroidx/compose/ui/graphics/vector/PathNode$VerticalTo;", "ExtractFloatResult", "PathPoint", "ui-graphics_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class PathParser {
    private final List<PathNode> nodes = new ArrayList();
    private final PathPoint currentPoint = new PathPoint(0.0f, 0.0f, 3, null);
    private final PathPoint ctrlPoint = new PathPoint(0.0f, 0.0f, 3, null);
    private final PathPoint segmentPoint = new PathPoint(0.0f, 0.0f, 3, null);
    private final PathPoint reflectiveCtrlPoint = new PathPoint(0.0f, 0.0f, 3, null);

    /* JADX INFO: Access modifiers changed from: private */
    /* compiled from: PathParser.kt */
    @Metadata(d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0007\n\u0002\b\f\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\b\u0082\b\u0018\u00002\u00020\u0001B\u0019\u0012\b\b\u0002\u0010\u0002\u001a\u00020\u0003\u0012\b\b\u0002\u0010\u0004\u001a\u00020\u0003¢\u0006\u0002\u0010\u0005J\t\u0010\f\u001a\u00020\u0003HÆ\u0003J\t\u0010\r\u001a\u00020\u0003HÆ\u0003J\u001d\u0010\u000e\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u0003HÆ\u0001J\u0013\u0010\u000f\u001a\u00020\u00102\b\u0010\u0011\u001a\u0004\u0018\u00010\u0001HÖ\u0003J\t\u0010\u0012\u001a\u00020\u0013HÖ\u0001J\u0006\u0010\u0014\u001a\u00020\u0015J\t\u0010\u0016\u001a\u00020\u0017HÖ\u0001R\u001a\u0010\u0002\u001a\u00020\u0003X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0006\u0010\u0007\"\u0004\b\b\u0010\tR\u001a\u0010\u0004\u001a\u00020\u0003X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\n\u0010\u0007\"\u0004\b\u000b\u0010\t¨\u0006\u0018"}, d2 = {"Landroidx/compose/ui/graphics/vector/PathParser$PathPoint;", "", "x", "", "y", "(FF)V", "getX", "()F", "setX", "(F)V", "getY", "setY", "component1", "component2", "copy", "equals", "", "other", "hashCode", "", "reset", "", "toString", "", "ui-graphics_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class PathPoint {
        private float x;
        private float y;

        public PathPoint() {
            this(0.0f, 0.0f, 3, null);
        }

        public static /* synthetic */ PathPoint copy$default(PathPoint pathPoint, float f, float f2, int i, Object obj) {
            if ((i & 1) != 0) {
                f = pathPoint.x;
            }
            if ((i & 2) != 0) {
                f2 = pathPoint.y;
            }
            return pathPoint.copy(f, f2);
        }

        public final float component1() {
            return this.x;
        }

        public final float component2() {
            return this.y;
        }

        public final PathPoint copy(float f, float f2) {
            return new PathPoint(f, f2);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof PathPoint) {
                PathPoint pathPoint = (PathPoint) obj;
                return Float.compare(this.x, pathPoint.x) == 0 && Float.compare(this.y, pathPoint.y) == 0;
            }
            return false;
        }

        public int hashCode() {
            return (Float.hashCode(this.x) * 31) + Float.hashCode(this.y);
        }

        public String toString() {
            return "PathPoint(x=" + this.x + ", y=" + this.y + ')';
        }

        public PathPoint(float x, float y) {
            this.x = x;
            this.y = y;
        }

        public /* synthetic */ PathPoint(float f, float f2, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? 0.0f : f, (i & 2) != 0 ? 0.0f : f2);
        }

        public final float getX() {
            return this.x;
        }

        public final float getY() {
            return this.y;
        }

        public final void setX(float f) {
            this.x = f;
        }

        public final void setY(float f) {
            this.y = f;
        }

        public final void reset() {
            this.x = 0.0f;
            this.y = 0.0f;
        }
    }

    public final void clear() {
        this.nodes.clear();
    }

    public final PathParser parsePathString(String pathData) {
        Intrinsics.checkNotNullParameter(pathData, "pathData");
        this.nodes.clear();
        int start = 0;
        int end = 1;
        while (end < pathData.length()) {
            int end2 = nextStart(pathData, end);
            CharSequence $this$trim$iv = pathData.substring(start, end2);
            Intrinsics.checkNotNullExpressionValue($this$trim$iv, "this as java.lang.String…ing(startIndex, endIndex)");
            CharSequence $this$trim$iv$iv = $this$trim$iv;
            int startIndex$iv$iv = 0;
            int endIndex$iv$iv = $this$trim$iv$iv.length() - 1;
            boolean startFound$iv$iv = false;
            while (startIndex$iv$iv <= endIndex$iv$iv) {
                int index$iv$iv = !startFound$iv$iv ? startIndex$iv$iv : endIndex$iv$iv;
                char it = $this$trim$iv$iv.charAt(index$iv$iv);
                boolean match$iv$iv = Intrinsics.compare((int) it, 32) <= 0;
                if (!startFound$iv$iv) {
                    if (match$iv$iv) {
                        startIndex$iv$iv++;
                    } else {
                        startFound$iv$iv = true;
                    }
                } else if (!match$iv$iv) {
                    break;
                } else {
                    endIndex$iv$iv--;
                }
            }
            String $this$trim$iv2 = $this$trim$iv$iv.subSequence(startIndex$iv$iv, endIndex$iv$iv + 1).toString();
            if ($this$trim$iv2.length() > 0) {
                float[] args = getFloats($this$trim$iv2);
                addNode($this$trim$iv2.charAt(0), args);
            }
            start = end2;
            end = end2 + 1;
        }
        if (end - start == 1 && start < pathData.length()) {
            addNode(pathData.charAt(start), new float[0]);
        }
        return this;
    }

    public final PathParser addPathNodes(List<? extends PathNode> nodes) {
        Intrinsics.checkNotNullParameter(nodes, "nodes");
        this.nodes.addAll(nodes);
        return this;
    }

    public final List<PathNode> toNodes() {
        return this.nodes;
    }

    public static /* synthetic */ Path toPath$default(PathParser pathParser, Path path, int i, Object obj) {
        if ((i & 1) != 0) {
            path = AndroidPath_androidKt.Path();
        }
        return pathParser.toPath(path);
    }

    public final Path toPath(Path target) {
        Intrinsics.checkNotNullParameter(target, "target");
        target.reset();
        this.currentPoint.reset();
        this.ctrlPoint.reset();
        this.segmentPoint.reset();
        this.reflectiveCtrlPoint.reset();
        PathNode pathNode = null;
        List $this$fastForEach$iv = this.nodes;
        int size = $this$fastForEach$iv.size();
        for (int index$iv = 0; index$iv < size; index$iv++) {
            Object item$iv = $this$fastForEach$iv.get(index$iv);
            PathNode node = (PathNode) item$iv;
            if (pathNode == null) {
                pathNode = node;
            }
            if (node instanceof PathNode.Close) {
                close(target);
            } else if (node instanceof PathNode.RelativeMoveTo) {
                relativeMoveTo((PathNode.RelativeMoveTo) node, target);
            } else if (node instanceof PathNode.MoveTo) {
                moveTo((PathNode.MoveTo) node, target);
            } else if (node instanceof PathNode.RelativeLineTo) {
                relativeLineTo((PathNode.RelativeLineTo) node, target);
            } else if (node instanceof PathNode.LineTo) {
                lineTo((PathNode.LineTo) node, target);
            } else if (node instanceof PathNode.RelativeHorizontalTo) {
                relativeHorizontalTo((PathNode.RelativeHorizontalTo) node, target);
            } else if (node instanceof PathNode.HorizontalTo) {
                horizontalTo((PathNode.HorizontalTo) node, target);
            } else if (node instanceof PathNode.RelativeVerticalTo) {
                relativeVerticalTo((PathNode.RelativeVerticalTo) node, target);
            } else if (node instanceof PathNode.VerticalTo) {
                verticalTo((PathNode.VerticalTo) node, target);
            } else if (node instanceof PathNode.RelativeCurveTo) {
                relativeCurveTo((PathNode.RelativeCurveTo) node, target);
            } else if (node instanceof PathNode.CurveTo) {
                curveTo((PathNode.CurveTo) node, target);
            } else if (node instanceof PathNode.RelativeReflectiveCurveTo) {
                Intrinsics.checkNotNull(pathNode);
                relativeReflectiveCurveTo((PathNode.RelativeReflectiveCurveTo) node, pathNode.isCurve(), target);
            } else if (node instanceof PathNode.ReflectiveCurveTo) {
                Intrinsics.checkNotNull(pathNode);
                reflectiveCurveTo((PathNode.ReflectiveCurveTo) node, pathNode.isCurve(), target);
            } else if (node instanceof PathNode.RelativeQuadTo) {
                relativeQuadTo((PathNode.RelativeQuadTo) node, target);
            } else if (node instanceof PathNode.QuadTo) {
                quadTo((PathNode.QuadTo) node, target);
            } else if (node instanceof PathNode.RelativeReflectiveQuadTo) {
                Intrinsics.checkNotNull(pathNode);
                relativeReflectiveQuadTo((PathNode.RelativeReflectiveQuadTo) node, pathNode.isQuad(), target);
            } else if (node instanceof PathNode.ReflectiveQuadTo) {
                Intrinsics.checkNotNull(pathNode);
                reflectiveQuadTo((PathNode.ReflectiveQuadTo) node, pathNode.isQuad(), target);
            } else if (node instanceof PathNode.RelativeArcTo) {
                relativeArcTo((PathNode.RelativeArcTo) node, target);
            } else if (node instanceof PathNode.ArcTo) {
                arcTo((PathNode.ArcTo) node, target);
            }
            pathNode = node;
        }
        return target;
    }

    private final void close(Path target) {
        this.currentPoint.setX(this.segmentPoint.getX());
        this.currentPoint.setY(this.segmentPoint.getY());
        this.ctrlPoint.setX(this.segmentPoint.getX());
        this.ctrlPoint.setY(this.segmentPoint.getY());
        target.close();
        target.moveTo(this.currentPoint.getX(), this.currentPoint.getY());
    }

    private final void relativeMoveTo(PathNode.RelativeMoveTo $this$relativeMoveTo, Path target) {
        PathPoint pathPoint = this.currentPoint;
        pathPoint.setX(pathPoint.getX() + $this$relativeMoveTo.getDx());
        PathPoint pathPoint2 = this.currentPoint;
        pathPoint2.setY(pathPoint2.getY() + $this$relativeMoveTo.getDy());
        target.relativeMoveTo($this$relativeMoveTo.getDx(), $this$relativeMoveTo.getDy());
        this.segmentPoint.setX(this.currentPoint.getX());
        this.segmentPoint.setY(this.currentPoint.getY());
    }

    private final void moveTo(PathNode.MoveTo $this$moveTo, Path target) {
        this.currentPoint.setX($this$moveTo.getX());
        this.currentPoint.setY($this$moveTo.getY());
        target.moveTo($this$moveTo.getX(), $this$moveTo.getY());
        this.segmentPoint.setX(this.currentPoint.getX());
        this.segmentPoint.setY(this.currentPoint.getY());
    }

    private final void relativeLineTo(PathNode.RelativeLineTo $this$relativeLineTo, Path target) {
        target.relativeLineTo($this$relativeLineTo.getDx(), $this$relativeLineTo.getDy());
        PathPoint pathPoint = this.currentPoint;
        pathPoint.setX(pathPoint.getX() + $this$relativeLineTo.getDx());
        PathPoint pathPoint2 = this.currentPoint;
        pathPoint2.setY(pathPoint2.getY() + $this$relativeLineTo.getDy());
    }

    private final void lineTo(PathNode.LineTo $this$lineTo, Path target) {
        target.lineTo($this$lineTo.getX(), $this$lineTo.getY());
        this.currentPoint.setX($this$lineTo.getX());
        this.currentPoint.setY($this$lineTo.getY());
    }

    private final void relativeHorizontalTo(PathNode.RelativeHorizontalTo $this$relativeHorizontalTo, Path target) {
        target.relativeLineTo($this$relativeHorizontalTo.getDx(), 0.0f);
        PathPoint pathPoint = this.currentPoint;
        pathPoint.setX(pathPoint.getX() + $this$relativeHorizontalTo.getDx());
    }

    private final void horizontalTo(PathNode.HorizontalTo $this$horizontalTo, Path target) {
        target.lineTo($this$horizontalTo.getX(), this.currentPoint.getY());
        this.currentPoint.setX($this$horizontalTo.getX());
    }

    private final void relativeVerticalTo(PathNode.RelativeVerticalTo $this$relativeVerticalTo, Path target) {
        target.relativeLineTo(0.0f, $this$relativeVerticalTo.getDy());
        PathPoint pathPoint = this.currentPoint;
        pathPoint.setY(pathPoint.getY() + $this$relativeVerticalTo.getDy());
    }

    private final void verticalTo(PathNode.VerticalTo $this$verticalTo, Path target) {
        target.lineTo(this.currentPoint.getX(), $this$verticalTo.getY());
        this.currentPoint.setY($this$verticalTo.getY());
    }

    private final void relativeCurveTo(PathNode.RelativeCurveTo $this$relativeCurveTo, Path target) {
        target.relativeCubicTo($this$relativeCurveTo.getDx1(), $this$relativeCurveTo.getDy1(), $this$relativeCurveTo.getDx2(), $this$relativeCurveTo.getDy2(), $this$relativeCurveTo.getDx3(), $this$relativeCurveTo.getDy3());
        this.ctrlPoint.setX(this.currentPoint.getX() + $this$relativeCurveTo.getDx2());
        this.ctrlPoint.setY(this.currentPoint.getY() + $this$relativeCurveTo.getDy2());
        PathPoint pathPoint = this.currentPoint;
        pathPoint.setX(pathPoint.getX() + $this$relativeCurveTo.getDx3());
        PathPoint pathPoint2 = this.currentPoint;
        pathPoint2.setY(pathPoint2.getY() + $this$relativeCurveTo.getDy3());
    }

    private final void curveTo(PathNode.CurveTo $this$curveTo, Path target) {
        target.cubicTo($this$curveTo.getX1(), $this$curveTo.getY1(), $this$curveTo.getX2(), $this$curveTo.getY2(), $this$curveTo.getX3(), $this$curveTo.getY3());
        this.ctrlPoint.setX($this$curveTo.getX2());
        this.ctrlPoint.setY($this$curveTo.getY2());
        this.currentPoint.setX($this$curveTo.getX3());
        this.currentPoint.setY($this$curveTo.getY3());
    }

    private final void relativeReflectiveCurveTo(PathNode.RelativeReflectiveCurveTo $this$relativeReflectiveCurveTo, boolean prevIsCurve, Path target) {
        if (prevIsCurve) {
            this.reflectiveCtrlPoint.setX(this.currentPoint.getX() - this.ctrlPoint.getX());
            this.reflectiveCtrlPoint.setY(this.currentPoint.getY() - this.ctrlPoint.getY());
        } else {
            this.reflectiveCtrlPoint.reset();
        }
        target.relativeCubicTo(this.reflectiveCtrlPoint.getX(), this.reflectiveCtrlPoint.getY(), $this$relativeReflectiveCurveTo.getDx1(), $this$relativeReflectiveCurveTo.getDy1(), $this$relativeReflectiveCurveTo.getDx2(), $this$relativeReflectiveCurveTo.getDy2());
        this.ctrlPoint.setX(this.currentPoint.getX() + $this$relativeReflectiveCurveTo.getDx1());
        this.ctrlPoint.setY(this.currentPoint.getY() + $this$relativeReflectiveCurveTo.getDy1());
        PathPoint pathPoint = this.currentPoint;
        pathPoint.setX(pathPoint.getX() + $this$relativeReflectiveCurveTo.getDx2());
        PathPoint pathPoint2 = this.currentPoint;
        pathPoint2.setY(pathPoint2.getY() + $this$relativeReflectiveCurveTo.getDy2());
    }

    private final void reflectiveCurveTo(PathNode.ReflectiveCurveTo $this$reflectiveCurveTo, boolean prevIsCurve, Path target) {
        if (prevIsCurve) {
            float f = 2;
            this.reflectiveCtrlPoint.setX((this.currentPoint.getX() * f) - this.ctrlPoint.getX());
            this.reflectiveCtrlPoint.setY((f * this.currentPoint.getY()) - this.ctrlPoint.getY());
        } else {
            this.reflectiveCtrlPoint.setX(this.currentPoint.getX());
            this.reflectiveCtrlPoint.setY(this.currentPoint.getY());
        }
        target.cubicTo(this.reflectiveCtrlPoint.getX(), this.reflectiveCtrlPoint.getY(), $this$reflectiveCurveTo.getX1(), $this$reflectiveCurveTo.getY1(), $this$reflectiveCurveTo.getX2(), $this$reflectiveCurveTo.getY2());
        this.ctrlPoint.setX($this$reflectiveCurveTo.getX1());
        this.ctrlPoint.setY($this$reflectiveCurveTo.getY1());
        this.currentPoint.setX($this$reflectiveCurveTo.getX2());
        this.currentPoint.setY($this$reflectiveCurveTo.getY2());
    }

    private final void relativeQuadTo(PathNode.RelativeQuadTo $this$relativeQuadTo, Path target) {
        target.relativeQuadraticBezierTo($this$relativeQuadTo.getDx1(), $this$relativeQuadTo.getDy1(), $this$relativeQuadTo.getDx2(), $this$relativeQuadTo.getDy2());
        this.ctrlPoint.setX(this.currentPoint.getX() + $this$relativeQuadTo.getDx1());
        this.ctrlPoint.setY(this.currentPoint.getY() + $this$relativeQuadTo.getDy1());
        PathPoint pathPoint = this.currentPoint;
        pathPoint.setX(pathPoint.getX() + $this$relativeQuadTo.getDx2());
        PathPoint pathPoint2 = this.currentPoint;
        pathPoint2.setY(pathPoint2.getY() + $this$relativeQuadTo.getDy2());
    }

    private final void quadTo(PathNode.QuadTo $this$quadTo, Path target) {
        target.quadraticBezierTo($this$quadTo.getX1(), $this$quadTo.getY1(), $this$quadTo.getX2(), $this$quadTo.getY2());
        this.ctrlPoint.setX($this$quadTo.getX1());
        this.ctrlPoint.setY($this$quadTo.getY1());
        this.currentPoint.setX($this$quadTo.getX2());
        this.currentPoint.setY($this$quadTo.getY2());
    }

    private final void relativeReflectiveQuadTo(PathNode.RelativeReflectiveQuadTo $this$relativeReflectiveQuadTo, boolean prevIsQuad, Path target) {
        if (prevIsQuad) {
            this.reflectiveCtrlPoint.setX(this.currentPoint.getX() - this.ctrlPoint.getX());
            this.reflectiveCtrlPoint.setY(this.currentPoint.getY() - this.ctrlPoint.getY());
        } else {
            this.reflectiveCtrlPoint.reset();
        }
        target.relativeQuadraticBezierTo(this.reflectiveCtrlPoint.getX(), this.reflectiveCtrlPoint.getY(), $this$relativeReflectiveQuadTo.getDx(), $this$relativeReflectiveQuadTo.getDy());
        this.ctrlPoint.setX(this.currentPoint.getX() + this.reflectiveCtrlPoint.getX());
        this.ctrlPoint.setY(this.currentPoint.getY() + this.reflectiveCtrlPoint.getY());
        PathPoint pathPoint = this.currentPoint;
        pathPoint.setX(pathPoint.getX() + $this$relativeReflectiveQuadTo.getDx());
        PathPoint pathPoint2 = this.currentPoint;
        pathPoint2.setY(pathPoint2.getY() + $this$relativeReflectiveQuadTo.getDy());
    }

    private final void reflectiveQuadTo(PathNode.ReflectiveQuadTo $this$reflectiveQuadTo, boolean prevIsQuad, Path target) {
        if (prevIsQuad) {
            float f = 2;
            this.reflectiveCtrlPoint.setX((this.currentPoint.getX() * f) - this.ctrlPoint.getX());
            this.reflectiveCtrlPoint.setY((f * this.currentPoint.getY()) - this.ctrlPoint.getY());
        } else {
            this.reflectiveCtrlPoint.setX(this.currentPoint.getX());
            this.reflectiveCtrlPoint.setY(this.currentPoint.getY());
        }
        target.quadraticBezierTo(this.reflectiveCtrlPoint.getX(), this.reflectiveCtrlPoint.getY(), $this$reflectiveQuadTo.getX(), $this$reflectiveQuadTo.getY());
        this.ctrlPoint.setX(this.reflectiveCtrlPoint.getX());
        this.ctrlPoint.setY(this.reflectiveCtrlPoint.getY());
        this.currentPoint.setX($this$reflectiveQuadTo.getX());
        this.currentPoint.setY($this$reflectiveQuadTo.getY());
    }

    private final void relativeArcTo(PathNode.RelativeArcTo $this$relativeArcTo, Path target) {
        float arcStartX = $this$relativeArcTo.getArcStartDx() + this.currentPoint.getX();
        float arcStartY = $this$relativeArcTo.getArcStartDy() + this.currentPoint.getY();
        drawArc(target, this.currentPoint.getX(), this.currentPoint.getY(), arcStartX, arcStartY, $this$relativeArcTo.getHorizontalEllipseRadius(), $this$relativeArcTo.getVerticalEllipseRadius(), $this$relativeArcTo.getTheta(), $this$relativeArcTo.isMoreThanHalf(), $this$relativeArcTo.isPositiveArc());
        this.currentPoint.setX(arcStartX);
        this.currentPoint.setY(arcStartY);
        this.ctrlPoint.setX(this.currentPoint.getX());
        this.ctrlPoint.setY(this.currentPoint.getY());
    }

    private final void arcTo(PathNode.ArcTo $this$arcTo, Path target) {
        drawArc(target, this.currentPoint.getX(), this.currentPoint.getY(), $this$arcTo.getArcStartX(), $this$arcTo.getArcStartY(), $this$arcTo.getHorizontalEllipseRadius(), $this$arcTo.getVerticalEllipseRadius(), $this$arcTo.getTheta(), $this$arcTo.isMoreThanHalf(), $this$arcTo.isPositiveArc());
        this.currentPoint.setX($this$arcTo.getArcStartX());
        this.currentPoint.setY($this$arcTo.getArcStartY());
        this.ctrlPoint.setX(this.currentPoint.getX());
        this.ctrlPoint.setY(this.currentPoint.getY());
    }

    private final void drawArc(Path p, double x0, double y0, double x1, double y1, double a, double b, double theta, boolean isMoreThanHalf, boolean isPositiveArc) {
        double cx;
        double cy;
        double sweep;
        double thetaD = toRadians(theta);
        double cosTheta = Math.cos(thetaD);
        double sinTheta = Math.sin(thetaD);
        double x0p = ((x0 * cosTheta) + (y0 * sinTheta)) / a;
        double y0p = (((-x0) * sinTheta) + (y0 * cosTheta)) / b;
        double x1p = ((x1 * cosTheta) + (y1 * sinTheta)) / a;
        double y1p = (((-x1) * sinTheta) + (y1 * cosTheta)) / b;
        double dx = x0p - x1p;
        double dy = y0p - y1p;
        double d = 2;
        double xm = (x0p + x1p) / d;
        double ym = (y0p + y1p) / d;
        double dsq = (dx * dx) + (dy * dy);
        if (dsq == 0.0d) {
            return;
        }
        double disc = (1.0d / dsq) - 0.25d;
        if (disc < 0.0d) {
            float adjust = (float) (Math.sqrt(dsq) / 1.99999d);
            drawArc(p, x0, y0, x1, y1, a * adjust, b * adjust, theta, isMoreThanHalf, isPositiveArc);
            return;
        }
        double s = Math.sqrt(disc);
        double sdx = s * dx;
        double sdy = s * dy;
        if (isMoreThanHalf == isPositiveArc) {
            cx = xm - sdy;
            cy = ym + sdx;
        } else {
            cx = xm + sdy;
            cy = ym - sdx;
        }
        double eta0 = Math.atan2(y0p - cy, x0p - cx);
        double eta1 = Math.atan2(y1p - cy, x1p - cx);
        double sweep2 = eta1 - eta0;
        if (isPositiveArc == (sweep2 >= 0.0d)) {
            sweep = sweep2;
        } else if (sweep2 > 0.0d) {
            sweep = sweep2 - 6.283185307179586d;
        } else {
            sweep = sweep2 + 6.283185307179586d;
        }
        double cx2 = cx * a;
        double cy2 = cy * b;
        arcToBezier(p, (cx2 * cosTheta) - (cy2 * sinTheta), (cx2 * sinTheta) + (cy2 * cosTheta), a, b, x0, y0, thetaD, eta0, sweep);
    }

    private final void arcToBezier(Path p, double cx, double cy, double a, double b, double e1x, double e1y, double theta, double start, double sweep) {
        double eta1 = a;
        double eta1y = e1y;
        double d = 4;
        int numSegments = (int) Math.ceil(Math.abs((sweep * d) / 3.141592653589793d));
        double eta12 = start;
        double cosTheta = Math.cos(theta);
        double sinTheta = Math.sin(theta);
        double cosEta1 = Math.cos(eta12);
        double sinEta1 = Math.sin(eta12);
        double eta1x = e1x;
        double eta1x2 = -eta1;
        double ep1x = ((eta1x2 * cosTheta) * sinEta1) - ((b * sinTheta) * cosEta1);
        double ep1x2 = ep1x;
        double ep1x3 = -eta1;
        double ep1y = (ep1x3 * sinTheta * sinEta1) + (b * cosTheta * cosEta1);
        double ep1y2 = ep1y;
        double ep1y3 = numSegments;
        double anglePerSegment = sweep / ep1y3;
        int i = 0;
        while (i < numSegments) {
            double eta2 = eta12 + anglePerSegment;
            double sinEta2 = Math.sin(eta2);
            double cosEta2 = Math.cos(eta2);
            double anglePerSegment2 = anglePerSegment;
            double anglePerSegment3 = (cx + ((eta1 * cosTheta) * cosEta2)) - ((b * sinTheta) * sinEta2);
            double e2x = cy + (eta1 * sinTheta * cosEta2) + (b * cosTheta * sinEta2);
            double e2y = -eta1;
            double ep2x = ((e2y * cosTheta) * sinEta2) - ((b * sinTheta) * cosEta2);
            double ep2y = ((-eta1) * sinTheta * sinEta2) + (b * cosTheta * cosEta2);
            double tanDiff2 = Math.tan((eta2 - eta12) / 2);
            double alpha = (Math.sin(eta2 - eta12) * (Math.sqrt(d + ((3.0d * tanDiff2) * tanDiff2)) - 1)) / 3;
            double q1x = eta1x + (alpha * ep1x2);
            double d2 = d;
            double q1y = eta1y + (alpha * ep1y2);
            double eta1y2 = anglePerSegment3 - (alpha * ep2x);
            int numSegments2 = numSegments;
            double q2y = e2x - (alpha * ep2y);
            double e2y2 = cosTheta;
            p.cubicTo((float) q1x, (float) q1y, (float) eta1y2, (float) q2y, (float) anglePerSegment3, (float) e2x);
            eta1x = anglePerSegment3;
            ep1x2 = ep2x;
            ep1y2 = ep2y;
            i++;
            eta1y = e2x;
            numSegments = numSegments2;
            cosTheta = e2y2;
            anglePerSegment = anglePerSegment2;
            d = d2;
            eta12 = eta2;
            eta1 = a;
        }
    }

    private final void addNode(char cmd, float[] args) {
        this.nodes.addAll(PathNodeKt.toPathNodes(cmd, args));
    }

    private final int nextStart(String s, int end) {
        int index = end;
        while (index < s.length()) {
            char c = s.charAt(index);
            if (((c - 'A') * (c - 'Z') <= 0 || (c - 'a') * (c - 'z') <= 0) && c != 'e' && c != 'E') {
                return index;
            }
            index++;
        }
        return index;
    }

    private final float[] getFloats(String s) {
        if (s.charAt(0) == 'z' || s.charAt(0) == 'Z') {
            return new float[0];
        }
        float[] results = new float[s.length()];
        int count = 0;
        int startPosition = 1;
        ExtractFloatResult result = new ExtractFloatResult(0, false, 3, null);
        int totalLength = s.length();
        while (startPosition < totalLength) {
            extract(s, startPosition, result);
            int endPosition = result.getEndPosition();
            if (startPosition < endPosition) {
                String substring = s.substring(startPosition, endPosition);
                Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String…ing(startIndex, endIndex)");
                results[count] = Float.parseFloat(substring);
                count++;
            }
            if (result.getEndWithNegativeOrDot()) {
                startPosition = endPosition;
            } else {
                startPosition = endPosition + 1;
            }
        }
        return copyOfRange(results, 0, count);
    }

    private final float[] copyOfRange(float[] original, int start, int end) {
        if (start > end) {
            throw new IllegalArgumentException();
        }
        int originalLength = original.length;
        if (start < 0 || start > originalLength) {
            throw new IndexOutOfBoundsException();
        }
        int resultLength = end - start;
        int copyLength = Math.min(resultLength, originalLength - start);
        float[] result = new float[resultLength];
        ArraysKt.copyInto(original, result, 0, start, start + copyLength);
        return result;
    }

    private final void extract(String s, int start, ExtractFloatResult result) {
        int currentIndex = start;
        boolean foundSeparator = false;
        result.setEndWithNegativeOrDot(false);
        boolean secondDot = false;
        boolean isExponential = false;
        while (currentIndex < s.length()) {
            boolean isPrevExponential = isExponential;
            isExponential = false;
            char currentChar = s.charAt(currentIndex);
            boolean z = true;
            if (currentChar == ' ' || currentChar == ',') {
                foundSeparator = true;
            } else if (currentChar == '-') {
                if (currentIndex != start && !isPrevExponential) {
                    foundSeparator = true;
                    result.setEndWithNegativeOrDot(true);
                }
            } else if (currentChar == '.') {
                if (!secondDot) {
                    secondDot = true;
                } else {
                    foundSeparator = true;
                    result.setEndWithNegativeOrDot(true);
                }
            } else {
                if (currentChar != 'e' && currentChar != 'E') {
                    z = false;
                }
                if (z) {
                    isExponential = true;
                }
            }
            if (foundSeparator) {
                break;
            }
            currentIndex++;
        }
        result.setEndPosition(currentIndex);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* compiled from: PathParser.kt */
    @Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0010\n\u0002\u0010\u000e\n\u0000\b\u0082\b\u0018\u00002\u00020\u0001B\u0019\u0012\b\b\u0002\u0010\u0002\u001a\u00020\u0003\u0012\b\b\u0002\u0010\u0004\u001a\u00020\u0005¢\u0006\u0002\u0010\u0006J\t\u0010\u000f\u001a\u00020\u0003HÆ\u0003J\t\u0010\u0010\u001a\u00020\u0005HÆ\u0003J\u001d\u0010\u0011\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u0005HÆ\u0001J\u0013\u0010\u0012\u001a\u00020\u00052\b\u0010\u0013\u001a\u0004\u0018\u00010\u0001HÖ\u0003J\t\u0010\u0014\u001a\u00020\u0003HÖ\u0001J\t\u0010\u0015\u001a\u00020\u0016HÖ\u0001R\u001a\u0010\u0002\u001a\u00020\u0003X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0007\u0010\b\"\u0004\b\t\u0010\nR\u001a\u0010\u0004\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000e¨\u0006\u0017"}, d2 = {"Landroidx/compose/ui/graphics/vector/PathParser$ExtractFloatResult;", "", "endPosition", "", "endWithNegativeOrDot", "", "(IZ)V", "getEndPosition", "()I", "setEndPosition", "(I)V", "getEndWithNegativeOrDot", "()Z", "setEndWithNegativeOrDot", "(Z)V", "component1", "component2", "copy", "equals", "other", "hashCode", "toString", "", "ui-graphics_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class ExtractFloatResult {
        private int endPosition;
        private boolean endWithNegativeOrDot;

        public ExtractFloatResult() {
            this(0, false, 3, null);
        }

        public static /* synthetic */ ExtractFloatResult copy$default(ExtractFloatResult extractFloatResult, int i, boolean z, int i2, Object obj) {
            if ((i2 & 1) != 0) {
                i = extractFloatResult.endPosition;
            }
            if ((i2 & 2) != 0) {
                z = extractFloatResult.endWithNegativeOrDot;
            }
            return extractFloatResult.copy(i, z);
        }

        public final int component1() {
            return this.endPosition;
        }

        public final boolean component2() {
            return this.endWithNegativeOrDot;
        }

        public final ExtractFloatResult copy(int i, boolean z) {
            return new ExtractFloatResult(i, z);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof ExtractFloatResult) {
                ExtractFloatResult extractFloatResult = (ExtractFloatResult) obj;
                return this.endPosition == extractFloatResult.endPosition && this.endWithNegativeOrDot == extractFloatResult.endWithNegativeOrDot;
            }
            return false;
        }

        /* JADX WARN: Multi-variable type inference failed */
        public int hashCode() {
            int hashCode = Integer.hashCode(this.endPosition) * 31;
            boolean z = this.endWithNegativeOrDot;
            int i = z;
            if (z != 0) {
                i = 1;
            }
            return hashCode + i;
        }

        public String toString() {
            return "ExtractFloatResult(endPosition=" + this.endPosition + ", endWithNegativeOrDot=" + this.endWithNegativeOrDot + ')';
        }

        public ExtractFloatResult(int endPosition, boolean endWithNegativeOrDot) {
            this.endPosition = endPosition;
            this.endWithNegativeOrDot = endWithNegativeOrDot;
        }

        public /* synthetic */ ExtractFloatResult(int i, boolean z, int i2, DefaultConstructorMarker defaultConstructorMarker) {
            this((i2 & 1) != 0 ? 0 : i, (i2 & 2) != 0 ? false : z);
        }

        public final int getEndPosition() {
            return this.endPosition;
        }

        public final void setEndPosition(int i) {
            this.endPosition = i;
        }

        public final boolean getEndWithNegativeOrDot() {
            return this.endWithNegativeOrDot;
        }

        public final void setEndWithNegativeOrDot(boolean z) {
            this.endWithNegativeOrDot = z;
        }
    }

    private final float toRadians(float $this$toRadians) {
        return ($this$toRadians / 180.0f) * 3.1415927f;
    }

    private final double toRadians(double $this$toRadians) {
        return ($this$toRadians / 180) * 3.141592653589793d;
    }
}
