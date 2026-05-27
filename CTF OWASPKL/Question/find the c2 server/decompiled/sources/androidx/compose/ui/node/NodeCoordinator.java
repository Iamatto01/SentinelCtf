package androidx.compose.ui.node;

import androidx.compose.runtime.snapshots.Snapshot;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.geometry.MutableRect;
import androidx.compose.ui.geometry.MutableRectKt;
import androidx.compose.ui.geometry.Offset;
import androidx.compose.ui.geometry.OffsetKt;
import androidx.compose.ui.geometry.Rect;
import androidx.compose.ui.geometry.Size;
import androidx.compose.ui.geometry.SizeKt;
import androidx.compose.ui.graphics.Canvas;
import androidx.compose.ui.graphics.GraphicsLayerScope;
import androidx.compose.ui.graphics.Matrix;
import androidx.compose.ui.graphics.Paint;
import androidx.compose.ui.graphics.ReusableGraphicsLayerScope;
import androidx.compose.ui.layout.AlignmentLine;
import androidx.compose.ui.layout.LayoutCoordinates;
import androidx.compose.ui.layout.LayoutCoordinatesKt;
import androidx.compose.ui.layout.LookaheadLayoutCoordinatesImpl;
import androidx.compose.ui.layout.LookaheadScope;
import androidx.compose.ui.layout.Measurable;
import androidx.compose.ui.layout.MeasureResult;
import androidx.compose.ui.layout.Placeable;
import androidx.compose.ui.semantics.SemanticsConfiguration;
import androidx.compose.ui.semantics.SemanticsNodeKt;
import androidx.compose.ui.unit.Density;
import androidx.compose.ui.unit.IntOffset;
import androidx.compose.ui.unit.IntOffsetKt;
import androidx.compose.ui.unit.IntSize;
import androidx.compose.ui.unit.IntSizeKt;
import androidx.compose.ui.unit.LayoutDirection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.SetsKt;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Ref;
/* compiled from: NodeCoordinator.kt */
@Metadata(d1 = {"\u0000¢\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010\u0007\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010%\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\u0000\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\"\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0012\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\u0018\n\u0002\u0018\u0002\n\u0002\b\u0014\n\u0002\u0018\u0002\n\u0002\b#\b \u0018\u0000 \u0092\u00022\u00020\u00012\u00020\u00022\u00020\u00032\u00020\u00042\u000e\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u00070\u0005:\u0004\u0092\u0002\u0093\u0002B\r\u0012\u0006\u0010\b\u001a\u00020\t¢\u0006\u0002\u0010\nJ$\u0010\u0084\u0001\u001a\u00020\u00072\u0007\u0010\u0085\u0001\u001a\u00020\u00002\u0007\u0010\u0086\u0001\u001a\u00020\u000e2\u0007\u0010\u0087\u0001\u001a\u00020 H\u0002J,\u0010\u0084\u0001\u001a\u00030\u0088\u00012\u0007\u0010\u0085\u0001\u001a\u00020\u00002\b\u0010\u0089\u0001\u001a\u00030\u0088\u0001H\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b\u008a\u0001\u0010\u008b\u0001J \u0010\u008c\u0001\u001a\u00020O2\u0006\u0010N\u001a\u00020OH\u0004ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b\u008d\u0001\u0010\u008e\u0001J\u0013\u0010\u008f\u0001\u001a\u00020D2\b\u0010\u0090\u0001\u001a\u00030\u0091\u0001H&J*\u0010\u0092\u0001\u001a\u00020\u001a2\b\u0010\u0093\u0001\u001a\u00030\u0088\u00012\u0006\u0010N\u001a\u00020OH\u0004ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b\u0094\u0001\u0010\u0095\u0001J\u0010\u0010\u0096\u0001\u001a\u00020\u00072\u0007\u0010\u0097\u0001\u001a\u00020\u0006J\u001c\u0010\u0098\u0001\u001a\u00020\u00072\u0007\u0010\u0097\u0001\u001a\u00020\u00062\b\u0010\u0099\u0001\u001a\u00030\u009a\u0001H\u0004J\u0012\u0010\u009b\u0001\u001a\u00020\u00072\u0007\u0010\u0097\u0001\u001a\u00020\u0006H\u0002J\u0018\u0010\u009c\u0001\u001a\u00020\u00002\u0007\u0010\u009d\u0001\u001a\u00020\u0000H\u0000¢\u0006\u0003\b\u009e\u0001J\"\u0010\u009f\u0001\u001a\u00030\u0088\u00012\u0007\u0010`\u001a\u00030\u0088\u0001H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b \u0001\u0010\u008e\u0001J\u001b\u0010¡\u0001\u001a\u00020\u00072\u0007\u0010¢\u0001\u001a\u00020\u000e2\u0007\u0010\u0087\u0001\u001a\u00020 H\u0002J$\u0010£\u0001\u001a\u00020 2\f\u0010¤\u0001\u001a\u0007\u0012\u0002\b\u00030¥\u0001ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b¦\u0001\u0010§\u0001J6\u0010¨\u0001\u001a\u0005\u0018\u0001H©\u0001\"\u0007\b\u0000\u0010©\u0001\u0018\u00012\u000f\u0010¤\u0001\u001a\n\u0012\u0005\u0012\u0003H©\u00010¥\u0001H\u0086\bø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\bª\u0001\u0010«\u0001J\u0014\u0010¬\u0001\u001a\u0004\u0018\u00010u2\u0007\u0010\u00ad\u0001\u001a\u00020 H\u0002J1\u0010®\u0001\u001a\u0005\u0018\u0001H©\u0001\"\u0005\b\u0000\u0010©\u00012\u000f\u0010¤\u0001\u001a\n\u0012\u0005\u0012\u0003H©\u00010¥\u0001ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b¯\u0001\u0010«\u0001J`\u0010°\u0001\u001a\u00020\u0007\"\n\b\u0000\u0010©\u0001*\u00030±\u00012\u000f\u0010²\u0001\u001a\n\u0012\u0005\u0012\u0003H©\u00010³\u00012\b\u0010\u0093\u0001\u001a\u00030\u0088\u00012\u000f\u0010´\u0001\u001a\n\u0012\u0005\u0012\u0003H©\u00010µ\u00012\u0007\u0010¶\u0001\u001a\u00020 2\u0007\u0010·\u0001\u001a\u00020 ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b¸\u0001\u0010¹\u0001Jb\u0010º\u0001\u001a\u00020\u0007\"\n\b\u0000\u0010©\u0001*\u00030±\u00012\u000f\u0010²\u0001\u001a\n\u0012\u0005\u0012\u0003H©\u00010³\u00012\b\u0010\u0093\u0001\u001a\u00030\u0088\u00012\u000f\u0010´\u0001\u001a\n\u0012\u0005\u0012\u0003H©\u00010µ\u00012\u0007\u0010¶\u0001\u001a\u00020 2\u0007\u0010·\u0001\u001a\u00020 H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b»\u0001\u0010¹\u0001J\t\u0010¼\u0001\u001a\u00020\u0007H\u0016J\u0013\u0010½\u0001\u001a\u00020\u00072\u0007\u0010\u0097\u0001\u001a\u00020\u0006H\u0096\u0002J\"\u0010¾\u0001\u001a\u00020 2\b\u0010\u0093\u0001\u001a\u00030\u0088\u0001H\u0004ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b¿\u0001\u0010À\u0001J\u0007\u0010Á\u0001\u001a\u00020 J\u001c\u0010Â\u0001\u001a\u00030Ã\u00012\u0007\u0010Ä\u0001\u001a\u00020\u00032\u0007\u0010\u0087\u0001\u001a\u00020 H\u0016J,\u0010Å\u0001\u001a\u00030\u0088\u00012\u0007\u0010Ä\u0001\u001a\u00020\u00032\b\u0010Æ\u0001\u001a\u00030\u0088\u0001H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\bÇ\u0001\u0010È\u0001J#\u0010É\u0001\u001a\u00030\u0088\u00012\b\u0010Ê\u0001\u001a\u00030\u0088\u0001H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\bË\u0001\u0010\u008e\u0001J#\u0010Ì\u0001\u001a\u00030\u0088\u00012\b\u0010Ê\u0001\u001a\u00030\u0088\u0001H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\bÍ\u0001\u0010\u008e\u0001J#\u0010Î\u0001\u001a\u00030\u0088\u00012\b\u0010\u0093\u0001\u001a\u00030\u0088\u0001H\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\bÏ\u0001\u0010\u008e\u0001J/\u0010Ð\u0001\u001a\u00020\u00072\u0019\u00106\u001a\u0015\u0012\u0004\u0012\u000204\u0012\u0004\u0012\u00020\u0007\u0018\u00010\u0005¢\u0006\u0002\b52\t\b\u0002\u0010Ñ\u0001\u001a\u00020 H\u0002J\t\u0010Ò\u0001\u001a\u00020\u0007H\u0016J\u0007\u0010Ó\u0001\u001a\u00020\u0007J\u001b\u0010Ô\u0001\u001a\u00020\u00072\u0007\u0010Õ\u0001\u001a\u00020T2\u0007\u0010Ö\u0001\u001a\u00020TH\u0014J\u0007\u0010×\u0001\u001a\u00020\u0007J\u0007\u0010Ø\u0001\u001a\u00020\u0007J\u0007\u0010Ù\u0001\u001a\u00020\u0007J\u0012\u0010Ú\u0001\u001a\u00020\u00072\u0007\u0010\u0097\u0001\u001a\u00020\u0006H\u0016J6\u0010Û\u0001\u001a\u00030Ü\u00012\u0007\u0010Ý\u0001\u001a\u00020-2\u000e\u0010Þ\u0001\u001a\t\u0012\u0005\u0012\u00030Ü\u00010$H\u0084\bø\u0001\u0003ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\bß\u0001\u0010à\u0001JD\u0010á\u0001\u001a\u00020\u00072\u0006\u0010`\u001a\u00020_2\u0007\u0010\u0080\u0001\u001a\u00020\u001a2\u0019\u00106\u001a\u0015\u0012\u0004\u0012\u000204\u0012\u0004\u0012\u00020\u0007\u0018\u00010\u0005¢\u0006\u0002\b5H\u0014ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\bâ\u0001\u0010ã\u0001J\u001d\u0010ä\u0001\u001a\u00020\u00072\b\u0010\u0086\u0001\u001a\u00030Ã\u0001H\u0096@ø\u0001\u0000¢\u0006\u0003\u0010å\u0001J,\u0010æ\u0001\u001a\u00020\u00072\u0007\u0010¢\u0001\u001a\u00020\u000e2\u0007\u0010\u0087\u0001\u001a\u00020 2\t\b\u0002\u0010ç\u0001\u001a\u00020 H\u0000¢\u0006\u0003\bè\u0001J\u000f\u0010é\u0001\u001a\u00020\u0007H\u0010¢\u0006\u0003\bê\u0001J\u0007\u0010ë\u0001\u001a\u00020 J\"\u0010ì\u0001\u001a\u00030\u0088\u00012\u0007\u0010`\u001a\u00030\u0088\u0001H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\bí\u0001\u0010\u008e\u0001J\b\u0010î\u0001\u001a\u00030Ã\u0001J+\u0010ï\u0001\u001a\u00020\u00072\u0007\u0010Ä\u0001\u001a\u00020\u00032\b\u0010ð\u0001\u001a\u00030ñ\u0001H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\bò\u0001\u0010ó\u0001J+\u0010ô\u0001\u001a\u00020\u00072\u0007\u0010\u0085\u0001\u001a\u00020\u00002\b\u0010ð\u0001\u001a\u00030ñ\u0001H\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\bõ\u0001\u0010ö\u0001J+\u0010÷\u0001\u001a\u00020\u00072\u0007\u0010\u0085\u0001\u001a\u00020\u00002\b\u0010ð\u0001\u001a\u00030ñ\u0001H\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\bø\u0001\u0010ö\u0001J-\u0010ù\u0001\u001a\u00020\u00072\u0019\u00106\u001a\u0015\u0012\u0004\u0012\u000204\u0012\u0004\u0012\u00020\u0007\u0018\u00010\u0005¢\u0006\u0002\b52\t\b\u0002\u0010Ñ\u0001\u001a\u00020 J\t\u0010ú\u0001\u001a\u00020\u0007H\u0002J\u0011\u0010û\u0001\u001a\u00020\u00072\u0006\u0010E\u001a\u00020DH\u0004J\u001b\u0010ü\u0001\u001a\u00020\u00072\n\u0010\u0090\u0001\u001a\u0005\u0018\u00010\u0091\u0001H\u0000¢\u0006\u0003\bý\u0001JL\u0010þ\u0001\u001a\u00020\u0007\"\u0007\b\u0000\u0010©\u0001\u0018\u00012\u000f\u0010¤\u0001\u001a\n\u0012\u0005\u0012\u0003H©\u00010¥\u00012\u0014\u0010Þ\u0001\u001a\u000f\u0012\u0005\u0012\u0003H©\u0001\u0012\u0004\u0012\u00020\u00070\u0005H\u0086\bø\u0001\u0003ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\bÿ\u0001\u0010\u0080\u0002J4\u0010þ\u0001\u001a\u00020\u00072\u0007\u0010\u0081\u0002\u001a\u00020T2\u0007\u0010\u00ad\u0001\u001a\u00020 2\u0013\u0010Þ\u0001\u001a\u000e\u0012\u0004\u0012\u00020u\u0012\u0004\u0012\u00020\u00070\u0005H\u0086\bø\u0001\u0003J#\u0010\u0082\u0002\u001a\u00030\u0088\u00012\b\u0010\u0083\u0002\u001a\u00030\u0088\u0001H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b\u0084\u0002\u0010\u008e\u0001J+\u0010\u0085\u0002\u001a\u00020\u00072\u0007\u0010\u0097\u0001\u001a\u00020\u00062\u0013\u0010Þ\u0001\u001a\u000e\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u00070\u0005H\u0084\bø\u0001\u0003J\"\u0010\u0086\u0002\u001a\u00020 2\b\u0010\u0093\u0001\u001a\u00030\u0088\u0001H\u0004ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b\u0087\u0002\u0010À\u0001Ji\u0010\u0088\u0002\u001a\u00020\u0007\"\n\b\u0000\u0010©\u0001*\u00030±\u0001*\u0005\u0018\u0001H©\u00012\u000f\u0010²\u0001\u001a\n\u0012\u0005\u0012\u0003H©\u00010³\u00012\b\u0010\u0093\u0001\u001a\u00030\u0088\u00012\u000f\u0010´\u0001\u001a\n\u0012\u0005\u0012\u0003H©\u00010µ\u00012\u0007\u0010¶\u0001\u001a\u00020 2\u0007\u0010·\u0001\u001a\u00020 H\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b\u0089\u0002\u0010\u008a\u0002Jr\u0010\u008b\u0002\u001a\u00020\u0007\"\n\b\u0000\u0010©\u0001*\u00030±\u0001*\u0005\u0018\u0001H©\u00012\u000f\u0010²\u0001\u001a\n\u0012\u0005\u0012\u0003H©\u00010³\u00012\b\u0010\u0093\u0001\u001a\u00030\u0088\u00012\u000f\u0010´\u0001\u001a\n\u0012\u0005\u0012\u0003H©\u00010µ\u00012\u0007\u0010¶\u0001\u001a\u00020 2\u0007\u0010·\u0001\u001a\u00020 2\u0007\u0010\u008c\u0002\u001a\u00020\u001aH\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b\u008d\u0002\u0010\u008e\u0002Jr\u0010\u008f\u0002\u001a\u00020\u0007\"\n\b\u0000\u0010©\u0001*\u00030±\u0001*\u0005\u0018\u0001H©\u00012\u000f\u0010²\u0001\u001a\n\u0012\u0005\u0012\u0003H©\u00010³\u00012\b\u0010\u0093\u0001\u001a\u00030\u0088\u00012\u000f\u0010´\u0001\u001a\n\u0012\u0005\u0012\u0003H©\u00010µ\u00012\u0007\u0010¶\u0001\u001a\u00020 2\u0007\u0010·\u0001\u001a\u00020 2\u0007\u0010\u008c\u0002\u001a\u00020\u001aH\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0006\b\u0090\u0002\u0010\u008e\u0002J\r\u0010\u0091\u0002\u001a\u00020\u0000*\u00020\u0003H\u0002R\u0010\u0010\u000b\u001a\u0004\u0018\u00010\fX\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\r\u001a\u0004\u0018\u00010\u000eX\u0082\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\u000f\u001a\u00020\u00108VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0011\u0010\u0012R\u0016\u0010\u0013\u001a\u0004\u0018\u00010\u00018VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0014\u0010\u0015R\u0014\u0010\u0016\u001a\u00020\u00038VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0017\u0010\u0018R\u0014\u0010\u0019\u001a\u00020\u001a8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u001b\u0010\u001cR\u0014\u0010\u001d\u001a\u00020\u001a8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u001e\u0010\u001cR\u0014\u0010\u001f\u001a\u00020 8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b!\u0010\"R\u0014\u0010#\u001a\b\u0012\u0004\u0012\u00020\u00070$X\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010%\u001a\u00020 8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b%\u0010\"R\u000e\u0010&\u001a\u00020 X\u0082\u000e¢\u0006\u0002\n\u0000R\u0014\u0010'\u001a\u00020 8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b'\u0010\"R\u000e\u0010(\u001a\u00020\u001aX\u0082\u000e¢\u0006\u0002\n\u0000R\u001e\u0010*\u001a\u00020 2\u0006\u0010)\u001a\u00020 @BX\u0080\u000e¢\u0006\b\n\u0000\u001a\u0004\b+\u0010\"R\u001d\u0010,\u001a\u00020-8@X\u0080\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0006\u001a\u0004\b.\u0010/R\"\u00101\u001a\u0004\u0018\u0001002\b\u0010)\u001a\u0004\u0018\u000100@BX\u0086\u000e¢\u0006\b\n\u0000\u001a\u0004\b2\u00103RD\u00106\u001a\u0015\u0012\u0004\u0012\u000204\u0012\u0004\u0012\u00020\u0007\u0018\u00010\u0005¢\u0006\u0002\b52\u0019\u0010)\u001a\u0015\u0012\u0004\u0012\u000204\u0012\u0004\u0012\u00020\u0007\u0018\u00010\u0005¢\u0006\u0002\b5@BX\u0084\u000e¢\u0006\b\n\u0000\u001a\u0004\b7\u00108R\u000e\u00109\u001a\u00020:X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010;\u001a\u00020<X\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010=\u001a\u0004\u0018\u00010>X\u0082\u000e¢\u0006\u0002\n\u0000R\u0014\u0010?\u001a\u00020<8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b@\u0010AR\u0014\u0010\b\u001a\u00020\tX\u0096\u0004¢\u0006\b\n\u0000\u001a\u0004\bB\u0010CR\"\u0010E\u001a\u0004\u0018\u00010D2\b\u0010)\u001a\u0004\u0018\u00010D@BX\u0080\u000e¢\u0006\b\n\u0000\u001a\u0004\bF\u0010GR$\u0010I\u001a\u00020\f2\u0006\u0010H\u001a\u00020\f8P@PX\u0090\u000e¢\u0006\f\u001a\u0004\bJ\u0010K\"\u0004\bL\u0010MR\u001a\u0010N\u001a\u00020O8Fø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0006\u001a\u0004\bP\u0010/R\u001c\u0010Q\u001a\u0010\u0012\u0004\u0012\u00020S\u0012\u0004\u0012\u00020T\u0018\u00010RX\u0082\u000e¢\u0006\u0002\n\u0000R\u0016\u0010U\u001a\u0004\u0018\u00010\u00018VX\u0096\u0004¢\u0006\u0006\u001a\u0004\bV\u0010\u0015R\u0013\u0010W\u001a\u0004\u0018\u00010\u00038F¢\u0006\u0006\u001a\u0004\bX\u0010\u0018R\u0016\u0010Y\u001a\u0004\u0018\u00010Z8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b[\u0010\\R\u0013\u0010]\u001a\u0004\u0018\u00010\u00038F¢\u0006\u0006\u001a\u0004\b^\u0010\u0018R/\u0010`\u001a\u00020_2\u0006\u0010)\u001a\u00020_@TX\u0096\u000eø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0010\n\u0002\u0010d\u001a\u0004\ba\u0010/\"\u0004\bb\u0010cR\u001a\u0010e\u001a\b\u0012\u0004\u0012\u00020S0f8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\bg\u0010hR\u0014\u0010i\u001a\u00020\u000e8DX\u0084\u0004¢\u0006\u0006\u001a\u0004\bj\u0010kR\u000e\u0010l\u001a\u00020 X\u0082\u000e¢\u0006\u0002\n\u0000R\u001a\u0010m\u001a\u00020n8Fø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0006\u001a\u0004\bo\u0010/R\u0014\u0010p\u001a\u00020q8BX\u0082\u0004¢\u0006\u0006\u001a\u0004\br\u0010sR\u0012\u0010t\u001a\u00020uX¦\u0004¢\u0006\u0006\u001a\u0004\bv\u0010wR\u001c\u0010x\u001a\u0004\u0018\u00010\u0000X\u0080\u000e¢\u0006\u000e\n\u0000\u001a\u0004\by\u0010z\"\u0004\b{\u0010|R\u001c\u0010}\u001a\u0004\u0018\u00010\u0000X\u0080\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b~\u0010z\"\u0004\b\u007f\u0010|R(\u0010\u0080\u0001\u001a\u00020\u001a2\u0006\u0010)\u001a\u00020\u001a@DX\u0086\u000e¢\u0006\u0011\n\u0000\u001a\u0005\b\u0081\u0001\u0010\u001c\"\u0006\b\u0082\u0001\u0010\u0083\u0001\u0082\u0002\u0016\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!\n\u0005\b\u009920\u0001¨\u0006\u0094\u0002"}, d2 = {"Landroidx/compose/ui/node/NodeCoordinator;", "Landroidx/compose/ui/node/LookaheadCapablePlaceable;", "Landroidx/compose/ui/layout/Measurable;", "Landroidx/compose/ui/layout/LayoutCoordinates;", "Landroidx/compose/ui/node/OwnerScope;", "Lkotlin/Function1;", "Landroidx/compose/ui/graphics/Canvas;", "", "layoutNode", "Landroidx/compose/ui/node/LayoutNode;", "(Landroidx/compose/ui/node/LayoutNode;)V", "_measureResult", "Landroidx/compose/ui/layout/MeasureResult;", "_rectCache", "Landroidx/compose/ui/geometry/MutableRect;", "alignmentLinesOwner", "Landroidx/compose/ui/node/AlignmentLinesOwner;", "getAlignmentLinesOwner", "()Landroidx/compose/ui/node/AlignmentLinesOwner;", "child", "getChild", "()Landroidx/compose/ui/node/LookaheadCapablePlaceable;", "coordinates", "getCoordinates", "()Landroidx/compose/ui/layout/LayoutCoordinates;", "density", "", "getDensity", "()F", "fontScale", "getFontScale", "hasMeasureResult", "", "getHasMeasureResult", "()Z", "invalidateParentLayer", "Lkotlin/Function0;", "isAttached", "isClipping", "isValidOwnerScope", "lastLayerAlpha", "<set-?>", "lastLayerDrawingWasSkipped", "getLastLayerDrawingWasSkipped$ui_release", "lastMeasurementConstraints", "Landroidx/compose/ui/unit/Constraints;", "getLastMeasurementConstraints-msEJaDk$ui_release", "()J", "Landroidx/compose/ui/node/OwnedLayer;", "layer", "getLayer", "()Landroidx/compose/ui/node/OwnedLayer;", "Landroidx/compose/ui/graphics/GraphicsLayerScope;", "Lkotlin/ExtensionFunctionType;", "layerBlock", "getLayerBlock", "()Lkotlin/jvm/functions/Function1;", "layerDensity", "Landroidx/compose/ui/unit/Density;", "layerLayoutDirection", "Landroidx/compose/ui/unit/LayoutDirection;", "layerPositionalProperties", "Landroidx/compose/ui/node/LayerPositionalProperties;", "layoutDirection", "getLayoutDirection", "()Landroidx/compose/ui/unit/LayoutDirection;", "getLayoutNode", "()Landroidx/compose/ui/node/LayoutNode;", "Landroidx/compose/ui/node/LookaheadDelegate;", "lookaheadDelegate", "getLookaheadDelegate$ui_release", "()Landroidx/compose/ui/node/LookaheadDelegate;", "value", "measureResult", "getMeasureResult$ui_release", "()Landroidx/compose/ui/layout/MeasureResult;", "setMeasureResult$ui_release", "(Landroidx/compose/ui/layout/MeasureResult;)V", "minimumTouchTargetSize", "Landroidx/compose/ui/geometry/Size;", "getMinimumTouchTargetSize-NH-jbRc", "oldAlignmentLines", "", "Landroidx/compose/ui/layout/AlignmentLine;", "", "parent", "getParent", "parentCoordinates", "getParentCoordinates", "parentData", "", "getParentData", "()Ljava/lang/Object;", "parentLayoutCoordinates", "getParentLayoutCoordinates", "Landroidx/compose/ui/unit/IntOffset;", "position", "getPosition-nOcc-ac", "setPosition--gyyYBs", "(J)V", "J", "providedAlignmentLines", "", "getProvidedAlignmentLines", "()Ljava/util/Set;", "rectCache", "getRectCache", "()Landroidx/compose/ui/geometry/MutableRect;", "released", "size", "Landroidx/compose/ui/unit/IntSize;", "getSize-YbymL2g", "snapshotObserver", "Landroidx/compose/ui/node/OwnerSnapshotObserver;", "getSnapshotObserver", "()Landroidx/compose/ui/node/OwnerSnapshotObserver;", "tail", "Landroidx/compose/ui/Modifier$Node;", "getTail", "()Landroidx/compose/ui/Modifier$Node;", "wrapped", "getWrapped$ui_release", "()Landroidx/compose/ui/node/NodeCoordinator;", "setWrapped$ui_release", "(Landroidx/compose/ui/node/NodeCoordinator;)V", "wrappedBy", "getWrappedBy$ui_release", "setWrappedBy$ui_release", "zIndex", "getZIndex", "setZIndex", "(F)V", "ancestorToLocal", "ancestor", "rect", "clipBounds", "Landroidx/compose/ui/geometry/Offset;", "offset", "ancestorToLocal-R5De75A", "(Landroidx/compose/ui/node/NodeCoordinator;J)J", "calculateMinimumTouchTargetPadding", "calculateMinimumTouchTargetPadding-E7KxVPU", "(J)J", "createLookaheadDelegate", "scope", "Landroidx/compose/ui/layout/LookaheadScope;", "distanceInMinimumTouchTarget", "pointerPosition", "distanceInMinimumTouchTarget-tz77jQw", "(JJ)F", "draw", "canvas", "drawBorder", "paint", "Landroidx/compose/ui/graphics/Paint;", "drawContainedDrawModifiers", "findCommonAncestor", "other", "findCommonAncestor$ui_release", "fromParentPosition", "fromParentPosition-MK-Hz9U", "fromParentRect", "bounds", "hasNode", "type", "Landroidx/compose/ui/node/NodeKind;", "hasNode-H91voCI", "(I)Z", "head", "T", "head-H91voCI", "(I)Ljava/lang/Object;", "headNode", "includeTail", "headUnchecked", "headUnchecked-H91voCI", "hitTest", "Landroidx/compose/ui/node/DelegatableNode;", "hitTestSource", "Landroidx/compose/ui/node/NodeCoordinator$HitTestSource;", "hitTestResult", "Landroidx/compose/ui/node/HitTestResult;", "isTouchEvent", "isInLayer", "hitTest-YqVAtuI", "(Landroidx/compose/ui/node/NodeCoordinator$HitTestSource;JLandroidx/compose/ui/node/HitTestResult;ZZ)V", "hitTestChild", "hitTestChild-YqVAtuI", "invalidateLayer", "invoke", "isPointerInBounds", "isPointerInBounds-k-4lQ0M", "(J)Z", "isTransparent", "localBoundingBoxOf", "Landroidx/compose/ui/geometry/Rect;", "sourceCoordinates", "localPositionOf", "relativeToSource", "localPositionOf-R5De75A", "(Landroidx/compose/ui/layout/LayoutCoordinates;J)J", "localToRoot", "relativeToLocal", "localToRoot-MK-Hz9U", "localToWindow", "localToWindow-MK-Hz9U", "offsetFromEdge", "offsetFromEdge-MK-Hz9U", "onLayerBlockUpdated", "forceLayerInvalidated", "onLayoutModifierNodeChanged", "onLayoutNodeAttach", "onMeasureResultChanged", "width", "height", "onMeasured", "onPlaced", "onRelease", "performDraw", "performingMeasure", "Landroidx/compose/ui/layout/Placeable;", "constraints", "block", "performingMeasure-K40F9xA", "(JLkotlin/jvm/functions/Function0;)Landroidx/compose/ui/layout/Placeable;", "placeAt", "placeAt-f8xVGno", "(JFLkotlin/jvm/functions/Function1;)V", "propagateRelocationRequest", "(Landroidx/compose/ui/geometry/Rect;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "rectInParent", "clipToMinimumTouchTargetSize", "rectInParent$ui_release", "replace", "replace$ui_release", "shouldSharePointerInputWithSiblings", "toParentPosition", "toParentPosition-MK-Hz9U", "touchBoundsInRoot", "transformFrom", "matrix", "Landroidx/compose/ui/graphics/Matrix;", "transformFrom-EL8BTi8", "(Landroidx/compose/ui/layout/LayoutCoordinates;[F)V", "transformFromAncestor", "transformFromAncestor-EL8BTi8", "(Landroidx/compose/ui/node/NodeCoordinator;[F)V", "transformToAncestor", "transformToAncestor-EL8BTi8", "updateLayerBlock", "updateLayerParameters", "updateLookaheadDelegate", "updateLookaheadScope", "updateLookaheadScope$ui_release", "visitNodes", "visitNodes-aLcG6gQ", "(ILkotlin/jvm/functions/Function1;)V", "mask", "windowToLocal", "relativeToWindow", "windowToLocal-MK-Hz9U", "withPositionTranslation", "withinLayerBounds", "withinLayerBounds-k-4lQ0M", "hit", "hit-1hIXUjU", "(Landroidx/compose/ui/node/DelegatableNode;Landroidx/compose/ui/node/NodeCoordinator$HitTestSource;JLandroidx/compose/ui/node/HitTestResult;ZZ)V", "hitNear", "distanceFromEdge", "hitNear-JHbHoSQ", "(Landroidx/compose/ui/node/DelegatableNode;Landroidx/compose/ui/node/NodeCoordinator$HitTestSource;JLandroidx/compose/ui/node/HitTestResult;ZZF)V", "speculativeHit", "speculativeHit-JHbHoSQ", "toCoordinator", "Companion", "HitTestSource", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public abstract class NodeCoordinator extends LookaheadCapablePlaceable implements Measurable, LayoutCoordinates, OwnerScope, Function1<Canvas, Unit> {
    public static final String ExpectAttachedLayoutCoordinates = "LayoutCoordinate operations are only valid when isAttached is true";
    public static final String UnmeasuredError = "Asking for measurement result of unmeasured layout modifier";
    private MeasureResult _measureResult;
    private MutableRect _rectCache;
    private final Function0<Unit> invalidateParentLayer;
    private boolean isClipping;
    private float lastLayerAlpha;
    private boolean lastLayerDrawingWasSkipped;
    private OwnedLayer layer;
    private Function1<? super GraphicsLayerScope, Unit> layerBlock;
    private Density layerDensity;
    private LayoutDirection layerLayoutDirection;
    private LayerPositionalProperties layerPositionalProperties;
    private final LayoutNode layoutNode;
    private LookaheadDelegate lookaheadDelegate;
    private Map<AlignmentLine, Integer> oldAlignmentLines;
    private long position;
    private boolean released;
    private NodeCoordinator wrapped;
    private NodeCoordinator wrappedBy;
    private float zIndex;
    public static final Companion Companion = new Companion(null);
    private static final Function1<NodeCoordinator, Unit> onCommitAffectingLayerParams = new Function1<NodeCoordinator, Unit>() { // from class: androidx.compose.ui.node.NodeCoordinator$Companion$onCommitAffectingLayerParams$1
        @Override // kotlin.jvm.functions.Function1
        public /* bridge */ /* synthetic */ Unit invoke(NodeCoordinator nodeCoordinator) {
            invoke2(nodeCoordinator);
            return Unit.INSTANCE;
        }

        /* renamed from: invoke  reason: avoid collision after fix types in other method */
        public final void invoke2(NodeCoordinator coordinator) {
            LayerPositionalProperties layerPositionalProperties;
            LayerPositionalProperties layerPositionalProperties2;
            LayerPositionalProperties layerPositionalProperties3;
            Intrinsics.checkNotNullParameter(coordinator, "coordinator");
            if (coordinator.isValidOwnerScope()) {
                layerPositionalProperties = coordinator.layerPositionalProperties;
                if (layerPositionalProperties == null) {
                    coordinator.updateLayerParameters();
                    return;
                }
                layerPositionalProperties2 = NodeCoordinator.tmpLayerPositionalProperties;
                layerPositionalProperties2.copyFrom(layerPositionalProperties);
                coordinator.updateLayerParameters();
                layerPositionalProperties3 = NodeCoordinator.tmpLayerPositionalProperties;
                if (!layerPositionalProperties3.hasSameValuesAs(layerPositionalProperties)) {
                    LayoutNode layoutNode = coordinator.getLayoutNode();
                    LayoutNodeLayoutDelegate layoutDelegate = layoutNode.getLayoutDelegate$ui_release();
                    if (layoutDelegate.getChildrenAccessingCoordinatesDuringPlacement() > 0) {
                        if (layoutDelegate.getCoordinatesAccessedDuringPlacement()) {
                            LayoutNode.requestRelayout$ui_release$default(layoutNode, false, 1, null);
                        }
                        layoutDelegate.getMeasurePassDelegate$ui_release().notifyChildrenUsingCoordinatesWhilePlacing();
                    }
                    Owner owner$ui_release = layoutNode.getOwner$ui_release();
                    if (owner$ui_release != null) {
                        owner$ui_release.requestOnPositionedCallback(layoutNode);
                    }
                }
            }
        }
    };
    private static final Function1<NodeCoordinator, Unit> onCommitAffectingLayer = new Function1<NodeCoordinator, Unit>() { // from class: androidx.compose.ui.node.NodeCoordinator$Companion$onCommitAffectingLayer$1
        @Override // kotlin.jvm.functions.Function1
        public /* bridge */ /* synthetic */ Unit invoke(NodeCoordinator nodeCoordinator) {
            invoke2(nodeCoordinator);
            return Unit.INSTANCE;
        }

        /* renamed from: invoke  reason: avoid collision after fix types in other method */
        public final void invoke2(NodeCoordinator coordinator) {
            Intrinsics.checkNotNullParameter(coordinator, "coordinator");
            OwnedLayer layer = coordinator.getLayer();
            if (layer != null) {
                layer.invalidate();
            }
        }
    };
    private static final ReusableGraphicsLayerScope graphicsLayerScope = new ReusableGraphicsLayerScope();
    private static final LayerPositionalProperties tmpLayerPositionalProperties = new LayerPositionalProperties();
    private static final float[] tmpMatrix = Matrix.m2830constructorimpl$default(null, 1, null);
    private static final HitTestSource<PointerInputModifierNode> PointerInputSource = new HitTestSource<PointerInputModifierNode>() { // from class: androidx.compose.ui.node.NodeCoordinator$Companion$PointerInputSource$1
        @Override // androidx.compose.ui.node.NodeCoordinator.HitTestSource
        /* renamed from: entityType-OLwlOKw  reason: not valid java name */
        public int mo4323entityTypeOLwlOKw() {
            return NodeKind.m4327constructorimpl(16);
        }

        @Override // androidx.compose.ui.node.NodeCoordinator.HitTestSource
        public boolean interceptOutOfBoundsChildEvents(PointerInputModifierNode node) {
            Intrinsics.checkNotNullParameter(node, "node");
            return node.interceptOutOfBoundsChildEvents();
        }

        @Override // androidx.compose.ui.node.NodeCoordinator.HitTestSource
        public boolean shouldHitTestChildren(LayoutNode parentLayoutNode) {
            Intrinsics.checkNotNullParameter(parentLayoutNode, "parentLayoutNode");
            return true;
        }

        @Override // androidx.compose.ui.node.NodeCoordinator.HitTestSource
        /* renamed from: childHitTest-YqVAtuI  reason: not valid java name */
        public void mo4322childHitTestYqVAtuI(LayoutNode layoutNode, long pointerPosition, HitTestResult<PointerInputModifierNode> hitTestResult, boolean isTouchEvent, boolean isInLayer) {
            Intrinsics.checkNotNullParameter(layoutNode, "layoutNode");
            Intrinsics.checkNotNullParameter(hitTestResult, "hitTestResult");
            layoutNode.m4254hitTestM_7yMNQ$ui_release(pointerPosition, hitTestResult, isTouchEvent, isInLayer);
        }
    };
    private static final HitTestSource<SemanticsModifierNode> SemanticsSource = new HitTestSource<SemanticsModifierNode>() { // from class: androidx.compose.ui.node.NodeCoordinator$Companion$SemanticsSource$1
        @Override // androidx.compose.ui.node.NodeCoordinator.HitTestSource
        /* renamed from: entityType-OLwlOKw */
        public int mo4323entityTypeOLwlOKw() {
            return NodeKind.m4327constructorimpl(8);
        }

        @Override // androidx.compose.ui.node.NodeCoordinator.HitTestSource
        public boolean interceptOutOfBoundsChildEvents(SemanticsModifierNode node) {
            Intrinsics.checkNotNullParameter(node, "node");
            return false;
        }

        @Override // androidx.compose.ui.node.NodeCoordinator.HitTestSource
        public boolean shouldHitTestChildren(LayoutNode parentLayoutNode) {
            SemanticsConfiguration collapsedSemanticsConfiguration;
            Intrinsics.checkNotNullParameter(parentLayoutNode, "parentLayoutNode");
            SemanticsModifierNode outerSemantics = SemanticsNodeKt.getOuterSemantics(parentLayoutNode);
            boolean z = false;
            if (outerSemantics != null && (collapsedSemanticsConfiguration = SemanticsModifierNodeKt.collapsedSemanticsConfiguration(outerSemantics)) != null && collapsedSemanticsConfiguration.isClearingSemantics()) {
                z = true;
            }
            return !z;
        }

        @Override // androidx.compose.ui.node.NodeCoordinator.HitTestSource
        /* renamed from: childHitTest-YqVAtuI */
        public void mo4322childHitTestYqVAtuI(LayoutNode layoutNode, long pointerPosition, HitTestResult<SemanticsModifierNode> hitTestResult, boolean isTouchEvent, boolean isInLayer) {
            Intrinsics.checkNotNullParameter(layoutNode, "layoutNode");
            Intrinsics.checkNotNullParameter(hitTestResult, "hitTestResult");
            layoutNode.m4255hitTestSemanticsM_7yMNQ$ui_release(pointerPosition, hitTestResult, isTouchEvent, isInLayer);
        }
    };

    /* compiled from: NodeCoordinator.kt */
    @Metadata(d1 = {"\u00008\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\b\b`\u0018\u0000*\b\b\u0000\u0010\u0001*\u00020\u00022\u00020\u0003JC\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\f\u0010\n\u001a\b\u0012\u0004\u0012\u00028\u00000\u000b2\u0006\u0010\f\u001a\u00020\r2\u0006\u0010\u000e\u001a\u00020\rH&ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u000f\u0010\u0010J\u001e\u0010\u0011\u001a\b\u0012\u0004\u0012\u00028\u00000\u0012H&ø\u0001\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0013\u0010\u0014J\u0015\u0010\u0015\u001a\u00020\r2\u0006\u0010\u0016\u001a\u00028\u0000H&¢\u0006\u0002\u0010\u0017J\u0010\u0010\u0018\u001a\u00020\r2\u0006\u0010\u0019\u001a\u00020\u0007H&ø\u0001\u0003\u0082\u0002\u0015\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019\n\u0002\b!\n\u0004\b!0\u0001¨\u0006\u001aÀ\u0006\u0001"}, d2 = {"Landroidx/compose/ui/node/NodeCoordinator$HitTestSource;", "N", "Landroidx/compose/ui/node/DelegatableNode;", "", "childHitTest", "", "layoutNode", "Landroidx/compose/ui/node/LayoutNode;", "pointerPosition", "Landroidx/compose/ui/geometry/Offset;", "hitTestResult", "Landroidx/compose/ui/node/HitTestResult;", "isTouchEvent", "", "isInLayer", "childHitTest-YqVAtuI", "(Landroidx/compose/ui/node/LayoutNode;JLandroidx/compose/ui/node/HitTestResult;ZZ)V", "entityType", "Landroidx/compose/ui/node/NodeKind;", "entityType-OLwlOKw", "()I", "interceptOutOfBoundsChildEvents", "node", "(Landroidx/compose/ui/node/DelegatableNode;)Z", "shouldHitTestChildren", "parentLayoutNode", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public interface HitTestSource<N extends DelegatableNode> {
        /* renamed from: childHitTest-YqVAtuI */
        void mo4322childHitTestYqVAtuI(LayoutNode layoutNode, long j, HitTestResult<N> hitTestResult, boolean z, boolean z2);

        /* renamed from: entityType-OLwlOKw */
        int mo4323entityTypeOLwlOKw();

        boolean interceptOutOfBoundsChildEvents(N n);

        boolean shouldHitTestChildren(LayoutNode layoutNode);
    }

    public abstract LookaheadDelegate createLookaheadDelegate(LookaheadScope lookaheadScope);

    public abstract Modifier.Node getTail();

    public Object propagateRelocationRequest(Rect rect, Continuation<? super Unit> continuation) {
        return propagateRelocationRequest$suspendImpl(this, rect, continuation);
    }

    @Override // kotlin.jvm.functions.Function1
    public /* bridge */ /* synthetic */ Unit invoke(Canvas canvas) {
        invoke2(canvas);
        return Unit.INSTANCE;
    }

    @Override // androidx.compose.ui.node.LookaheadCapablePlaceable, androidx.compose.ui.node.MeasureScopeWithLayoutNode
    public LayoutNode getLayoutNode() {
        return this.layoutNode;
    }

    public NodeCoordinator(LayoutNode layoutNode) {
        Intrinsics.checkNotNullParameter(layoutNode, "layoutNode");
        this.layoutNode = layoutNode;
        this.layerDensity = getLayoutNode().getDensity();
        this.layerLayoutDirection = getLayoutNode().getLayoutDirection();
        this.lastLayerAlpha = 0.8f;
        this.position = IntOffset.Companion.m5250getZeronOccac();
        this.invalidateParentLayer = new Function0<Unit>() { // from class: androidx.compose.ui.node.NodeCoordinator$invalidateParentLayer$1
            /* JADX INFO: Access modifiers changed from: package-private */
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke  reason: avoid collision after fix types in other method */
            public final void invoke2() {
                NodeCoordinator wrappedBy$ui_release = NodeCoordinator.this.getWrappedBy$ui_release();
                if (wrappedBy$ui_release != null) {
                    wrappedBy$ui_release.invalidateLayer();
                }
            }
        };
    }

    public final NodeCoordinator getWrapped$ui_release() {
        return this.wrapped;
    }

    public final void setWrapped$ui_release(NodeCoordinator nodeCoordinator) {
        this.wrapped = nodeCoordinator;
    }

    public final NodeCoordinator getWrappedBy$ui_release() {
        return this.wrappedBy;
    }

    public final void setWrappedBy$ui_release(NodeCoordinator nodeCoordinator) {
        this.wrappedBy = nodeCoordinator;
    }

    @Override // androidx.compose.ui.layout.IntrinsicMeasureScope
    public LayoutDirection getLayoutDirection() {
        return getLayoutNode().getLayoutDirection();
    }

    @Override // androidx.compose.ui.unit.Density
    public float getDensity() {
        return getLayoutNode().getDensity().getDensity();
    }

    @Override // androidx.compose.ui.unit.Density
    public float getFontScale() {
        return getLayoutNode().getDensity().getFontScale();
    }

    @Override // androidx.compose.ui.node.LookaheadCapablePlaceable
    public LookaheadCapablePlaceable getParent() {
        return this.wrappedBy;
    }

    @Override // androidx.compose.ui.node.LookaheadCapablePlaceable
    public LayoutCoordinates getCoordinates() {
        return this;
    }

    public final Modifier.Node headNode(boolean includeTail) {
        Modifier.Node tail;
        if (getLayoutNode().getOuterCoordinator$ui_release() == this) {
            return getLayoutNode().getNodes$ui_release().getHead$ui_release();
        }
        if (includeTail) {
            NodeCoordinator nodeCoordinator = this.wrappedBy;
            if (nodeCoordinator == null || (tail = nodeCoordinator.getTail()) == null) {
                return null;
            }
            return tail.getChild$ui_release();
        }
        NodeCoordinator nodeCoordinator2 = this.wrappedBy;
        if (nodeCoordinator2 != null) {
            return nodeCoordinator2.getTail();
        }
        return null;
    }

    public final void visitNodes(int mask, boolean includeTail, Function1<? super Modifier.Node, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        Modifier.Node stopNode = getTail();
        if (!includeTail && (stopNode = stopNode.getParent$ui_release()) == null) {
            return;
        }
        for (Modifier.Node node = headNode(includeTail); node != null && (node.getAggregateChildKindSet$ui_release() & mask) != 0; node = node.getChild$ui_release()) {
            if ((node.getKindSet$ui_release() & mask) != 0) {
                block.invoke(node);
            }
            if (node == stopNode) {
                return;
            }
        }
    }

    /* renamed from: visitNodes-aLcG6gQ */
    public final /* synthetic */ <T> void m4320visitNodesaLcG6gQ(int type, Function1<? super T, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        boolean includeTail$iv = NodeKindKt.m4335getIncludeSelfInTraversalH91voCI(type);
        Modifier.Node stopNode$iv = getTail();
        if (includeTail$iv || (stopNode$iv = stopNode$iv.getParent$ui_release()) != null) {
            for (Modifier.Node node$iv = headNode(includeTail$iv); node$iv != null && (node$iv.getAggregateChildKindSet$ui_release() & type) != 0; node$iv = node$iv.getChild$ui_release()) {
                if ((node$iv.getKindSet$ui_release() & type) != 0) {
                    Modifier.Node it = node$iv;
                    Intrinsics.reifiedOperationMarker(3, "T");
                    if (it instanceof Object) {
                        block.invoke(it);
                    }
                }
                if (node$iv == stopNode$iv) {
                    return;
                }
            }
        }
    }

    /* renamed from: hasNode-H91voCI */
    public final boolean m4312hasNodeH91voCI(int type) {
        Modifier.Node headNode = headNode(NodeKindKt.m4335getIncludeSelfInTraversalH91voCI(type));
        return headNode != null && DelegatableNodeKt.m4227has64DMado(headNode, type);
    }

    /* renamed from: head-H91voCI */
    public final /* synthetic */ <T> T m4313headH91voCI(int type) {
        boolean includeTail$iv = NodeKindKt.m4335getIncludeSelfInTraversalH91voCI(type);
        Modifier.Node stopNode$iv = getTail();
        if (includeTail$iv || (stopNode$iv = stopNode$iv.getParent$ui_release()) != null) {
            for (Modifier.Node node$iv = headNode(includeTail$iv); node$iv != null && (node$iv.getAggregateChildKindSet$ui_release() & type) != 0; node$iv = node$iv.getChild$ui_release()) {
                if ((node$iv.getKindSet$ui_release() & type) != 0) {
                    Modifier.Node it = node$iv;
                    Intrinsics.reifiedOperationMarker(2, "T");
                    return (T) it;
                } else if (node$iv == stopNode$iv) {
                    return null;
                }
            }
            return null;
        }
        return null;
    }

    /* renamed from: headUnchecked-H91voCI */
    public final <T> T m4314headUncheckedH91voCI(int type) {
        boolean includeTail$iv = NodeKindKt.m4335getIncludeSelfInTraversalH91voCI(type);
        Modifier.Node stopNode$iv = getTail();
        if (includeTail$iv || (stopNode$iv = stopNode$iv.getParent$ui_release()) != null) {
            for (Modifier.Node node$iv = headNode(includeTail$iv); node$iv != null && (node$iv.getAggregateChildKindSet$ui_release() & type) != 0; node$iv = node$iv.getChild$ui_release()) {
                if ((node$iv.getKindSet$ui_release() & type) != 0) {
                    Modifier.Node it = node$iv;
                    return (T) it;
                } else if (node$iv == stopNode$iv) {
                    return null;
                }
            }
            return null;
        }
        return null;
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    /* renamed from: getSize-YbymL2g */
    public final long mo4130getSizeYbymL2g() {
        return m4169getMeasuredSizeYbymL2g();
    }

    protected final Function1<GraphicsLayerScope, Unit> getLayerBlock() {
        return this.layerBlock;
    }

    public final boolean isTransparent() {
        if (this.layer == null || this.lastLayerAlpha > 0.0f) {
            NodeCoordinator nodeCoordinator = this.wrappedBy;
            if (nodeCoordinator != null) {
                return nodeCoordinator.isTransparent();
            }
            return false;
        }
        return true;
    }

    @Override // androidx.compose.ui.node.LookaheadCapablePlaceable
    public AlignmentLinesOwner getAlignmentLinesOwner() {
        return getLayoutNode().getLayoutDelegate$ui_release().getAlignmentLinesOwner$ui_release();
    }

    @Override // androidx.compose.ui.node.LookaheadCapablePlaceable
    public LookaheadCapablePlaceable getChild() {
        return this.wrapped;
    }

    @Override // androidx.compose.ui.node.LookaheadCapablePlaceable
    public void replace$ui_release() {
        mo4126placeAtf8xVGno(mo4276getPositionnOccac(), this.zIndex, this.layerBlock);
    }

    @Override // androidx.compose.ui.node.LookaheadCapablePlaceable
    public boolean getHasMeasureResult() {
        return this._measureResult != null;
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    public boolean isAttached() {
        return !this.released && getLayoutNode().isAttached();
    }

    @Override // androidx.compose.ui.node.LookaheadCapablePlaceable
    public MeasureResult getMeasureResult$ui_release() {
        MeasureResult measureResult = this._measureResult;
        if (measureResult != null) {
            return measureResult;
        }
        throw new IllegalStateException(UnmeasuredError.toString());
    }

    public void setMeasureResult$ui_release(MeasureResult value) {
        Intrinsics.checkNotNullParameter(value, "value");
        MeasureResult old = this._measureResult;
        if (value != old) {
            this._measureResult = value;
            if (old == null || value.getWidth() != old.getWidth() || value.getHeight() != old.getHeight()) {
                onMeasureResultChanged(value.getWidth(), value.getHeight());
            }
            Map<AlignmentLine, Integer> map = this.oldAlignmentLines;
            if ((!(map == null || map.isEmpty()) || (!value.getAlignmentLines().isEmpty())) && !Intrinsics.areEqual(value.getAlignmentLines(), this.oldAlignmentLines)) {
                getAlignmentLinesOwner().getAlignmentLines().onAlignmentsChanged();
                Map it = this.oldAlignmentLines;
                if (it == null) {
                    it = new LinkedHashMap();
                    this.oldAlignmentLines = it;
                }
                it.clear();
                it.putAll(value.getAlignmentLines());
            }
        }
    }

    public final LookaheadDelegate getLookaheadDelegate$ui_release() {
        return this.lookaheadDelegate;
    }

    public final void updateLookaheadScope$ui_release(LookaheadScope scope) {
        LookaheadDelegate lookaheadDelegate = null;
        if (scope != null) {
            LookaheadDelegate lookaheadDelegate2 = this.lookaheadDelegate;
            if (!Intrinsics.areEqual(scope, lookaheadDelegate2 != null ? lookaheadDelegate2.getLookaheadScope() : null)) {
                lookaheadDelegate = createLookaheadDelegate(scope);
            } else {
                lookaheadDelegate = this.lookaheadDelegate;
            }
        }
        this.lookaheadDelegate = lookaheadDelegate;
    }

    public final void updateLookaheadDelegate(LookaheadDelegate lookaheadDelegate) {
        Intrinsics.checkNotNullParameter(lookaheadDelegate, "lookaheadDelegate");
        this.lookaheadDelegate = lookaheadDelegate;
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    public Set<AlignmentLine> getProvidedAlignmentLines() {
        Set set = null;
        for (NodeCoordinator coordinator = this; coordinator != null; coordinator = coordinator.wrapped) {
            MeasureResult measureResult = coordinator._measureResult;
            Map alignmentLines = measureResult != null ? measureResult.getAlignmentLines() : null;
            boolean z = false;
            if (alignmentLines != null && (!alignmentLines.isEmpty())) {
                z = true;
            }
            if (z) {
                if (set == null) {
                    Set set2 = new LinkedHashSet();
                    set = set2;
                }
                set.addAll(alignmentLines.keySet());
            }
        }
        return set == null ? SetsKt.emptySet() : set;
    }

    protected void onMeasureResultChanged(int width, int height) {
        OwnedLayer layer = this.layer;
        if (layer != null) {
            layer.mo4372resizeozmzZPI(IntSizeKt.IntSize(width, height));
        } else {
            NodeCoordinator nodeCoordinator = this.wrappedBy;
            if (nodeCoordinator != null) {
                nodeCoordinator.invalidateLayer();
            }
        }
        Owner owner$ui_release = getLayoutNode().getOwner$ui_release();
        if (owner$ui_release != null) {
            owner$ui_release.onLayoutChange(getLayoutNode());
        }
        m4171setMeasuredSizeozmzZPI(IntSizeKt.IntSize(width, height));
        graphicsLayerScope.m2908setSizeuvyYCjk(IntSizeKt.m5292toSizeozmzZPI(m4169getMeasuredSizeYbymL2g()));
        int m4327constructorimpl = NodeKind.m4327constructorimpl(4);
        boolean includeTail$iv$iv = NodeKindKt.m4335getIncludeSelfInTraversalH91voCI(m4327constructorimpl);
        Modifier.Node stopNode$iv$iv = getTail();
        if (includeTail$iv$iv || (stopNode$iv$iv = stopNode$iv$iv.getParent$ui_release()) != null) {
            for (Modifier.Node node$iv$iv = headNode(includeTail$iv$iv); node$iv$iv != null && (node$iv$iv.getAggregateChildKindSet$ui_release() & m4327constructorimpl) != 0; node$iv$iv = node$iv$iv.getChild$ui_release()) {
                if ((node$iv$iv.getKindSet$ui_release() & m4327constructorimpl) != 0) {
                    Modifier.Node it$iv = node$iv$iv;
                    if (it$iv instanceof DrawModifierNode) {
                        DrawModifierNode it = (DrawModifierNode) it$iv;
                        it.onMeasureResultChanged();
                    }
                }
                if (node$iv$iv == stopNode$iv$iv) {
                    return;
                }
            }
        }
    }

    @Override // androidx.compose.ui.node.LookaheadCapablePlaceable
    /* renamed from: getPosition-nOcc-ac */
    public long mo4276getPositionnOccac() {
        return this.position;
    }

    /* renamed from: setPosition--gyyYBs */
    protected void m4318setPositiongyyYBs(long j) {
        this.position = j;
    }

    public final float getZIndex() {
        return this.zIndex;
    }

    protected final void setZIndex(float f) {
        this.zIndex = f;
    }

    /* JADX WARN: Type inference failed for: r10v5, types: [T, java.lang.Object] */
    @Override // androidx.compose.ui.layout.Measured, androidx.compose.ui.layout.IntrinsicMeasurable
    public Object getParentData() {
        Ref.ObjectRef data = new Ref.ObjectRef();
        Modifier.Node thisNode = getTail();
        if (getLayoutNode().getNodes$ui_release().m4290hasH91voCI$ui_release(NodeKind.m4327constructorimpl(64))) {
            Density $this$_get_parentData__u24lambda_u248 = getLayoutNode().getDensity();
            NodeChain this_$iv = getLayoutNode().getNodes$ui_release();
            for (Modifier.Node node$iv = this_$iv.getTail$ui_release(); node$iv != null; node$iv = node$iv.getParent$ui_release()) {
                Modifier.Node it = node$iv;
                if (it != thisNode) {
                    if (((it.getKindSet$ui_release() & NodeKind.m4327constructorimpl(64)) != 0) && (it instanceof ParentDataModifierNode)) {
                        Modifier.Node $this$_get_parentData__u24lambda_u248_u24lambda_u247_u24lambda_u246 = it;
                        data.element = ((ParentDataModifierNode) $this$_get_parentData__u24lambda_u248_u24lambda_u247_u24lambda_u246).modifyParentData($this$_get_parentData__u24lambda_u248, data.element);
                    }
                }
            }
        }
        return data.element;
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    public final LayoutCoordinates getParentLayoutCoordinates() {
        if (isAttached()) {
            return getLayoutNode().getOuterCoordinator$ui_release().wrappedBy;
        }
        throw new IllegalStateException(ExpectAttachedLayoutCoordinates.toString());
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    public final LayoutCoordinates getParentCoordinates() {
        if (isAttached()) {
            return this.wrappedBy;
        }
        throw new IllegalStateException(ExpectAttachedLayoutCoordinates.toString());
    }

    protected final MutableRect getRectCache() {
        MutableRect mutableRect = this._rectCache;
        if (mutableRect == null) {
            MutableRect it = new MutableRect(0.0f, 0.0f, 0.0f, 0.0f);
            this._rectCache = it;
            return it;
        }
        return mutableRect;
    }

    private final OwnerSnapshotObserver getSnapshotObserver() {
        return LayoutNodeKt.requireOwner(getLayoutNode()).getSnapshotObserver();
    }

    /* renamed from: getLastMeasurementConstraints-msEJaDk$ui_release */
    public final long m4310getLastMeasurementConstraintsmsEJaDk$ui_release() {
        return m4170getMeasurementConstraintsmsEJaDk();
    }

    /* renamed from: performingMeasure-K40F9xA */
    protected final Placeable m4317performingMeasureK40F9xA(long constraints, Function0<? extends Placeable> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        m4172setMeasurementConstraintsBRTryo0(constraints);
        Placeable result = block.invoke();
        OwnedLayer layer = getLayer();
        if (layer != null) {
            layer.mo4372resizeozmzZPI(m4169getMeasuredSizeYbymL2g());
        }
        return result;
    }

    public final void onMeasured() {
        Snapshot previous$iv$iv;
        Modifier.Node stopNode$iv$iv;
        int type$iv;
        Snapshot.Companion this_$iv;
        boolean z;
        if (m4312hasNodeH91voCI(NodeKind.m4327constructorimpl(128))) {
            Snapshot.Companion this_$iv2 = Snapshot.Companion;
            boolean z2 = false;
            Snapshot snapshot$iv = this_$iv2.createNonObservableSnapshot();
            try {
                previous$iv$iv = snapshot$iv.makeCurrent();
            } catch (Throwable th) {
                th = th;
            }
            try {
                try {
                    int type$iv2 = NodeKind.m4327constructorimpl(128);
                    boolean includeTail$iv$iv = NodeKindKt.m4335getIncludeSelfInTraversalH91voCI(type$iv2);
                    if (includeTail$iv$iv) {
                        try {
                            stopNode$iv$iv = getTail();
                        } catch (Throwable th2) {
                            th = th2;
                            snapshot$iv.restoreCurrent(previous$iv$iv);
                            throw th;
                        }
                    } else {
                        stopNode$iv$iv = getTail().getParent$ui_release();
                        if (stopNode$iv$iv == null) {
                            Unit unit = Unit.INSTANCE;
                            snapshot$iv.restoreCurrent(previous$iv$iv);
                            snapshot$iv.dispose();
                        }
                    }
                    Modifier.Node node$iv$iv = headNode(includeTail$iv$iv);
                    while (node$iv$iv != null) {
                        if ((node$iv$iv.getAggregateChildKindSet$ui_release() & type$iv2) != 0) {
                            if ((node$iv$iv.getKindSet$ui_release() & type$iv2) == 0) {
                                type$iv = type$iv2;
                                this_$iv = this_$iv2;
                                z = z2;
                            } else {
                                Modifier.Node it$iv = node$iv$iv;
                                type$iv = type$iv2;
                                if (it$iv instanceof LayoutAwareModifierNode) {
                                    LayoutAwareModifierNode it = (LayoutAwareModifierNode) it$iv;
                                    this_$iv = this_$iv2;
                                    z = z2;
                                    try {
                                        it.mo4213onRemeasuredozmzZPI(m4169getMeasuredSizeYbymL2g());
                                    } catch (Throwable th3) {
                                        th = th3;
                                        snapshot$iv.restoreCurrent(previous$iv$iv);
                                        throw th;
                                    }
                                } else {
                                    this_$iv = this_$iv2;
                                    z = z2;
                                }
                            }
                            if (node$iv$iv == stopNode$iv$iv) {
                                break;
                            }
                            node$iv$iv = node$iv$iv.getChild$ui_release();
                            type$iv2 = type$iv;
                            this_$iv2 = this_$iv;
                            z2 = z;
                        } else {
                            break;
                        }
                    }
                    Unit unit2 = Unit.INSTANCE;
                    snapshot$iv.restoreCurrent(previous$iv$iv);
                    snapshot$iv.dispose();
                } catch (Throwable th4) {
                    th = th4;
                }
            } catch (Throwable th5) {
                th = th5;
                snapshot$iv.dispose();
                throw th;
            }
        }
    }

    @Override // androidx.compose.ui.layout.Placeable
    /* renamed from: placeAt-f8xVGno */
    public void mo4126placeAtf8xVGno(long position, float zIndex, Function1<? super GraphicsLayerScope, Unit> function1) {
        onLayerBlockUpdated$default(this, function1, false, 2, null);
        if (!IntOffset.m5239equalsimpl0(mo4276getPositionnOccac(), position)) {
            m4318setPositiongyyYBs(position);
            getLayoutNode().getLayoutDelegate$ui_release().getMeasurePassDelegate$ui_release().notifyChildrenUsingCoordinatesWhilePlacing();
            OwnedLayer layer = this.layer;
            if (layer != null) {
                layer.mo4371movegyyYBs(position);
            } else {
                NodeCoordinator nodeCoordinator = this.wrappedBy;
                if (nodeCoordinator != null) {
                    nodeCoordinator.invalidateLayer();
                }
            }
            invalidateAlignmentLinesFromPositionChange(this);
            Owner owner$ui_release = getLayoutNode().getOwner$ui_release();
            if (owner$ui_release != null) {
                owner$ui_release.onLayoutChange(getLayoutNode());
            }
        }
        this.zIndex = zIndex;
    }

    public final void draw(Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        OwnedLayer layer = this.layer;
        if (layer != null) {
            layer.drawLayer(canvas);
            return;
        }
        float x = IntOffset.m5240getXimpl(mo4276getPositionnOccac());
        float y = IntOffset.m5241getYimpl(mo4276getPositionnOccac());
        canvas.translate(x, y);
        drawContainedDrawModifiers(canvas);
        canvas.translate(-x, -y);
    }

    public final void drawContainedDrawModifiers(Canvas canvas) {
        int m4327constructorimpl = NodeKind.m4327constructorimpl(4);
        boolean includeTail$iv$iv = NodeKindKt.m4335getIncludeSelfInTraversalH91voCI(m4327constructorimpl);
        Modifier.Node stopNode$iv$iv = getTail();
        if (includeTail$iv$iv || (stopNode$iv$iv = stopNode$iv$iv.getParent$ui_release()) != null) {
            Modifier.Node node$iv$iv = headNode(includeTail$iv$iv);
            while (true) {
                if (node$iv$iv != null && (node$iv$iv.getAggregateChildKindSet$ui_release() & m4327constructorimpl) != 0) {
                    if ((node$iv$iv.getKindSet$ui_release() & m4327constructorimpl) != 0) {
                        DrawModifierNode drawModifierNode = node$iv$iv;
                        r7 = drawModifierNode instanceof DrawModifierNode ? drawModifierNode : null;
                    } else if (node$iv$iv == stopNode$iv$iv) {
                        break;
                    } else {
                        node$iv$iv = node$iv$iv.getChild$ui_release();
                    }
                } else {
                    break;
                }
            }
        }
        DrawModifierNode head = r7;
        if (head == null) {
            performDraw(canvas);
            return;
        }
        LayoutNodeDrawScope drawScope = getLayoutNode().getMDrawScope$ui_release();
        drawScope.m4264drawx_KDEd0$ui_release(canvas, IntSizeKt.m5292toSizeozmzZPI(mo4130getSizeYbymL2g()), this, head);
    }

    public void performDraw(Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        NodeCoordinator nodeCoordinator = this.wrapped;
        if (nodeCoordinator != null) {
            nodeCoordinator.draw(canvas);
        }
    }

    public final void onPlaced() {
        LookaheadDelegate lookahead = this.lookaheadDelegate;
        if (lookahead != null) {
            int m4327constructorimpl = NodeKind.m4327constructorimpl(128);
            boolean includeTail$iv$iv = NodeKindKt.m4335getIncludeSelfInTraversalH91voCI(m4327constructorimpl);
            Modifier.Node stopNode$iv$iv = getTail();
            if (includeTail$iv$iv || (stopNode$iv$iv = stopNode$iv$iv.getParent$ui_release()) != null) {
                for (Modifier.Node node$iv$iv = headNode(includeTail$iv$iv); node$iv$iv != null && (node$iv$iv.getAggregateChildKindSet$ui_release() & m4327constructorimpl) != 0; node$iv$iv = node$iv$iv.getChild$ui_release()) {
                    if ((node$iv$iv.getKindSet$ui_release() & m4327constructorimpl) != 0) {
                        Modifier.Node it$iv = node$iv$iv;
                        if (it$iv instanceof LayoutAwareModifierNode) {
                            LayoutAwareModifierNode it = (LayoutAwareModifierNode) it$iv;
                            it.onLookaheadPlaced(lookahead.getLookaheadLayoutCoordinates());
                        }
                    }
                    if (node$iv$iv == stopNode$iv$iv) {
                        break;
                    }
                }
            }
        }
        int m4327constructorimpl2 = NodeKind.m4327constructorimpl(128);
        boolean includeTail$iv$iv2 = NodeKindKt.m4335getIncludeSelfInTraversalH91voCI(m4327constructorimpl2);
        Modifier.Node stopNode$iv$iv2 = getTail();
        if (includeTail$iv$iv2 || (stopNode$iv$iv2 = stopNode$iv$iv2.getParent$ui_release()) != null) {
            for (Modifier.Node node$iv$iv2 = headNode(includeTail$iv$iv2); node$iv$iv2 != null && (node$iv$iv2.getAggregateChildKindSet$ui_release() & m4327constructorimpl2) != 0; node$iv$iv2 = node$iv$iv2.getChild$ui_release()) {
                if ((node$iv$iv2.getKindSet$ui_release() & m4327constructorimpl2) != 0) {
                    Modifier.Node it$iv2 = node$iv$iv2;
                    if (it$iv2 instanceof LayoutAwareModifierNode) {
                        LayoutAwareModifierNode it2 = (LayoutAwareModifierNode) it$iv2;
                        it2.onPlaced(this);
                    }
                }
                if (node$iv$iv2 == stopNode$iv$iv2) {
                    return;
                }
            }
        }
    }

    /* renamed from: invoke */
    public void invoke2(final Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        if (getLayoutNode().isPlaced()) {
            getSnapshotObserver().observeReads$ui_release(this, onCommitAffectingLayer, new Function0<Unit>() { // from class: androidx.compose.ui.node.NodeCoordinator$invoke$1
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2() {
                    NodeCoordinator.this.drawContainedDrawModifiers(canvas);
                }
            });
            this.lastLayerDrawingWasSkipped = false;
            return;
        }
        this.lastLayerDrawingWasSkipped = true;
    }

    public static /* synthetic */ void updateLayerBlock$default(NodeCoordinator nodeCoordinator, Function1 function1, boolean z, int i, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateLayerBlock");
        }
        if ((i & 2) != 0) {
            z = false;
        }
        nodeCoordinator.updateLayerBlock(function1, z);
    }

    public final void updateLayerBlock(Function1<? super GraphicsLayerScope, Unit> function1, boolean forceLayerInvalidated) {
        boolean layerInvalidated = this.layerBlock != function1 || forceLayerInvalidated;
        this.layerBlock = function1;
        onLayerBlockUpdated(function1, layerInvalidated);
    }

    static /* synthetic */ void onLayerBlockUpdated$default(NodeCoordinator nodeCoordinator, Function1 function1, boolean z, int i, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: onLayerBlockUpdated");
        }
        if ((i & 2) != 0) {
            z = false;
        }
        nodeCoordinator.onLayerBlockUpdated(function1, z);
    }

    private final void onLayerBlockUpdated(Function1<? super GraphicsLayerScope, Unit> function1, boolean forceLayerInvalidated) {
        Owner owner$ui_release;
        boolean layerInvalidated = (this.layerBlock == function1 && Intrinsics.areEqual(this.layerDensity, getLayoutNode().getDensity()) && this.layerLayoutDirection == getLayoutNode().getLayoutDirection() && !forceLayerInvalidated) ? false : true;
        this.layerBlock = function1;
        this.layerDensity = getLayoutNode().getDensity();
        this.layerLayoutDirection = getLayoutNode().getLayoutDirection();
        if (isAttached() && function1 != null) {
            if (this.layer == null) {
                OwnedLayer $this$onLayerBlockUpdated_u24lambda_u2416 = LayoutNodeKt.requireOwner(getLayoutNode()).createLayer(this, this.invalidateParentLayer);
                $this$onLayerBlockUpdated_u24lambda_u2416.mo4372resizeozmzZPI(m4169getMeasuredSizeYbymL2g());
                $this$onLayerBlockUpdated_u24lambda_u2416.mo4371movegyyYBs(mo4276getPositionnOccac());
                this.layer = $this$onLayerBlockUpdated_u24lambda_u2416;
                updateLayerParameters();
                getLayoutNode().setInnerLayerCoordinatorIsDirty$ui_release(true);
                this.invalidateParentLayer.invoke();
                return;
            } else if (layerInvalidated) {
                updateLayerParameters();
                return;
            } else {
                return;
            }
        }
        OwnedLayer it = this.layer;
        if (it != null) {
            it.destroy();
            getLayoutNode().setInnerLayerCoordinatorIsDirty$ui_release(true);
            this.invalidateParentLayer.invoke();
            if (isAttached() && (owner$ui_release = getLayoutNode().getOwner$ui_release()) != null) {
                owner$ui_release.onLayoutChange(getLayoutNode());
            }
        }
        this.layer = null;
        this.lastLayerDrawingWasSkipped = false;
    }

    public final void updateLayerParameters() {
        OwnedLayer layer = this.layer;
        if (layer == null) {
            if (!(this.layerBlock == null)) {
                throw new IllegalArgumentException("Failed requirement.".toString());
            }
        } else {
            final Function1 layerBlock = this.layerBlock;
            if (layerBlock == null) {
                throw new IllegalArgumentException("Required value was null.".toString());
            }
            ReusableGraphicsLayerScope reusableGraphicsLayerScope = graphicsLayerScope;
            reusableGraphicsLayerScope.reset();
            reusableGraphicsLayerScope.setGraphicsDensity$ui_release(getLayoutNode().getDensity());
            reusableGraphicsLayerScope.m2908setSizeuvyYCjk(IntSizeKt.m5292toSizeozmzZPI(mo4130getSizeYbymL2g()));
            getSnapshotObserver().observeReads$ui_release(this, onCommitAffectingLayerParams, new Function0<Unit>() { // from class: androidx.compose.ui.node.NodeCoordinator$updateLayerParameters$1
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                /* JADX WARN: Multi-variable type inference failed */
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2() {
                    ReusableGraphicsLayerScope reusableGraphicsLayerScope2;
                    Function1<GraphicsLayerScope, Unit> function1 = layerBlock;
                    reusableGraphicsLayerScope2 = NodeCoordinator.graphicsLayerScope;
                    function1.invoke(reusableGraphicsLayerScope2);
                }
            });
            LayerPositionalProperties it = this.layerPositionalProperties;
            if (it == null) {
                it = new LayerPositionalProperties();
                this.layerPositionalProperties = it;
            }
            LayerPositionalProperties layerPositionalProperties = it;
            layerPositionalProperties.copyFrom(reusableGraphicsLayerScope);
            layer.mo4374updateLayerPropertiesdDxrwY(reusableGraphicsLayerScope.getScaleX(), reusableGraphicsLayerScope.getScaleY(), reusableGraphicsLayerScope.getAlpha(), reusableGraphicsLayerScope.getTranslationX(), reusableGraphicsLayerScope.getTranslationY(), reusableGraphicsLayerScope.getShadowElevation(), reusableGraphicsLayerScope.getRotationX(), reusableGraphicsLayerScope.getRotationY(), reusableGraphicsLayerScope.getRotationZ(), reusableGraphicsLayerScope.getCameraDistance(), reusableGraphicsLayerScope.mo2790getTransformOriginSzJe1aQ(), reusableGraphicsLayerScope.getShape(), reusableGraphicsLayerScope.getClip(), reusableGraphicsLayerScope.getRenderEffect(), reusableGraphicsLayerScope.mo2786getAmbientShadowColor0d7_KjU(), reusableGraphicsLayerScope.mo2789getSpotShadowColor0d7_KjU(), reusableGraphicsLayerScope.mo2787getCompositingStrategyNrFUSI(), getLayoutNode().getLayoutDirection(), getLayoutNode().getDensity());
            this.isClipping = reusableGraphicsLayerScope.getClip();
        }
        this.lastLayerAlpha = graphicsLayerScope.getAlpha();
        Owner owner$ui_release = getLayoutNode().getOwner$ui_release();
        if (owner$ui_release != null) {
            owner$ui_release.onLayoutChange(getLayoutNode());
        }
    }

    public final boolean getLastLayerDrawingWasSkipped$ui_release() {
        return this.lastLayerDrawingWasSkipped;
    }

    public final OwnedLayer getLayer() {
        return this.layer;
    }

    @Override // androidx.compose.ui.node.OwnerScope
    public boolean isValidOwnerScope() {
        return this.layer != null && isAttached();
    }

    /* renamed from: getMinimumTouchTargetSize-NH-jbRc */
    public final long m4311getMinimumTouchTargetSizeNHjbRc() {
        Density $this$getMinimumTouchTargetSize_NH_jbRc_u24lambda_u2419 = this.layerDensity;
        return $this$getMinimumTouchTargetSize_NH_jbRc_u24lambda_u2419.mo302toSizeXkaWNTQ(getLayoutNode().getViewConfiguration().mo4258getMinimumTouchTargetSizeMYxV2XQ());
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: hitTest-YqVAtuI */
    public final <T extends DelegatableNode> void m4315hitTestYqVAtuI(HitTestSource<T> hitTestSource, long pointerPosition, HitTestResult<T> hitTestResult, boolean isTouchEvent, boolean isInLayer) {
        Intrinsics.checkNotNullParameter(hitTestSource, "hitTestSource");
        Intrinsics.checkNotNullParameter(hitTestResult, "hitTestResult");
        DelegatableNode head = (DelegatableNode) m4314headUncheckedH91voCI(hitTestSource.mo4323entityTypeOLwlOKw());
        boolean z = true;
        if (!m4321withinLayerBoundsk4lQ0M(pointerPosition)) {
            if (isTouchEvent) {
                float distanceFromEdge = m4308distanceInMinimumTouchTargettz77jQw(pointerPosition, m4311getMinimumTouchTargetSizeNHjbRc());
                if (Float.isInfinite(distanceFromEdge) || Float.isNaN(distanceFromEdge)) {
                    z = false;
                }
                if (z && hitTestResult.isHitInMinimumTouchTargetBetter(distanceFromEdge, false)) {
                    m4302hitNearJHbHoSQ(head, hitTestSource, pointerPosition, hitTestResult, isTouchEvent, false, distanceFromEdge);
                }
            }
        } else if (head == null) {
            mo4249hitTestChildYqVAtuI(hitTestSource, pointerPosition, hitTestResult, isTouchEvent, isInLayer);
        } else if (m4316isPointerInBoundsk4lQ0M(pointerPosition)) {
            m4301hit1hIXUjU(head, hitTestSource, pointerPosition, hitTestResult, isTouchEvent, isInLayer);
        } else {
            float distanceFromEdge2 = !isTouchEvent ? Float.POSITIVE_INFINITY : m4308distanceInMinimumTouchTargettz77jQw(pointerPosition, m4311getMinimumTouchTargetSizeNHjbRc());
            if (Float.isInfinite(distanceFromEdge2) || Float.isNaN(distanceFromEdge2)) {
                z = false;
            }
            if (z && hitTestResult.isHitInMinimumTouchTargetBetter(distanceFromEdge2, isInLayer)) {
                m4302hitNearJHbHoSQ(head, hitTestSource, pointerPosition, hitTestResult, isTouchEvent, isInLayer, distanceFromEdge2);
            } else {
                m4304speculativeHitJHbHoSQ(head, hitTestSource, pointerPosition, hitTestResult, isTouchEvent, isInLayer, distanceFromEdge2);
            }
        }
    }

    /* renamed from: hit-1hIXUjU */
    public final <T extends DelegatableNode> void m4301hit1hIXUjU(final T t, final HitTestSource<T> hitTestSource, final long pointerPosition, final HitTestResult<T> hitTestResult, final boolean isTouchEvent, final boolean isInLayer) {
        if (t == null) {
            mo4249hitTestChildYqVAtuI(hitTestSource, pointerPosition, hitTestResult, isTouchEvent, isInLayer);
        } else {
            hitTestResult.hit(t, isInLayer, new Function0<Unit>() { // from class: androidx.compose.ui.node.NodeCoordinator$hit$1
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                /* JADX WARN: Incorrect types in method signature: (Landroidx/compose/ui/node/NodeCoordinator;TT;Landroidx/compose/ui/node/NodeCoordinator$HitTestSource<TT;>;JLandroidx/compose/ui/node/HitTestResult<TT;>;ZZ)V */
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2() {
                    Object m4325nextUncheckedUntilhw7D004;
                    NodeCoordinator nodeCoordinator = NodeCoordinator.this;
                    m4325nextUncheckedUntilhw7D004 = NodeCoordinatorKt.m4325nextUncheckedUntilhw7D004(t, hitTestSource.mo4323entityTypeOLwlOKw(), NodeKind.m4327constructorimpl(2));
                    nodeCoordinator.m4301hit1hIXUjU((DelegatableNode) m4325nextUncheckedUntilhw7D004, hitTestSource, pointerPosition, hitTestResult, isTouchEvent, isInLayer);
                }
            });
        }
    }

    /* renamed from: hitNear-JHbHoSQ */
    public final <T extends DelegatableNode> void m4302hitNearJHbHoSQ(final T t, final HitTestSource<T> hitTestSource, final long pointerPosition, final HitTestResult<T> hitTestResult, final boolean isTouchEvent, final boolean isInLayer, final float distanceFromEdge) {
        if (t == null) {
            mo4249hitTestChildYqVAtuI(hitTestSource, pointerPosition, hitTestResult, isTouchEvent, isInLayer);
        } else {
            hitTestResult.hitInMinimumTouchTarget(t, distanceFromEdge, isInLayer, new Function0<Unit>() { // from class: androidx.compose.ui.node.NodeCoordinator$hitNear$1
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                /* JADX WARN: Incorrect types in method signature: (Landroidx/compose/ui/node/NodeCoordinator;TT;Landroidx/compose/ui/node/NodeCoordinator$HitTestSource<TT;>;JLandroidx/compose/ui/node/HitTestResult<TT;>;ZZF)V */
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2() {
                    Object m4325nextUncheckedUntilhw7D004;
                    NodeCoordinator nodeCoordinator = NodeCoordinator.this;
                    m4325nextUncheckedUntilhw7D004 = NodeCoordinatorKt.m4325nextUncheckedUntilhw7D004(t, hitTestSource.mo4323entityTypeOLwlOKw(), NodeKind.m4327constructorimpl(2));
                    nodeCoordinator.m4302hitNearJHbHoSQ((DelegatableNode) m4325nextUncheckedUntilhw7D004, hitTestSource, pointerPosition, hitTestResult, isTouchEvent, isInLayer, distanceFromEdge);
                }
            });
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: speculativeHit-JHbHoSQ */
    public final <T extends DelegatableNode> void m4304speculativeHitJHbHoSQ(final T t, final HitTestSource<T> hitTestSource, final long pointerPosition, final HitTestResult<T> hitTestResult, final boolean isTouchEvent, final boolean isInLayer, final float distanceFromEdge) {
        Object m4325nextUncheckedUntilhw7D004;
        if (t != null) {
            if (!hitTestSource.interceptOutOfBoundsChildEvents(t)) {
                m4325nextUncheckedUntilhw7D004 = NodeCoordinatorKt.m4325nextUncheckedUntilhw7D004(t, hitTestSource.mo4323entityTypeOLwlOKw(), NodeKind.m4327constructorimpl(2));
                m4304speculativeHitJHbHoSQ((DelegatableNode) m4325nextUncheckedUntilhw7D004, hitTestSource, pointerPosition, hitTestResult, isTouchEvent, isInLayer, distanceFromEdge);
                return;
            }
            hitTestResult.speculativeHit(t, distanceFromEdge, isInLayer, new Function0<Unit>() { // from class: androidx.compose.ui.node.NodeCoordinator$speculativeHit$1
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                /* JADX WARN: Incorrect types in method signature: (Landroidx/compose/ui/node/NodeCoordinator;TT;Landroidx/compose/ui/node/NodeCoordinator$HitTestSource<TT;>;JLandroidx/compose/ui/node/HitTestResult<TT;>;ZZF)V */
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2() {
                    Object m4325nextUncheckedUntilhw7D0042;
                    NodeCoordinator nodeCoordinator = NodeCoordinator.this;
                    m4325nextUncheckedUntilhw7D0042 = NodeCoordinatorKt.m4325nextUncheckedUntilhw7D004(t, hitTestSource.mo4323entityTypeOLwlOKw(), NodeKind.m4327constructorimpl(2));
                    nodeCoordinator.m4304speculativeHitJHbHoSQ((DelegatableNode) m4325nextUncheckedUntilhw7D0042, hitTestSource, pointerPosition, hitTestResult, isTouchEvent, isInLayer, distanceFromEdge);
                }
            });
            return;
        }
        mo4249hitTestChildYqVAtuI(hitTestSource, pointerPosition, hitTestResult, isTouchEvent, isInLayer);
    }

    /* renamed from: hitTestChild-YqVAtuI */
    public <T extends DelegatableNode> void mo4249hitTestChildYqVAtuI(HitTestSource<T> hitTestSource, long pointerPosition, HitTestResult<T> hitTestResult, boolean isTouchEvent, boolean isInLayer) {
        Intrinsics.checkNotNullParameter(hitTestSource, "hitTestSource");
        Intrinsics.checkNotNullParameter(hitTestResult, "hitTestResult");
        NodeCoordinator wrapped = this.wrapped;
        if (wrapped != null) {
            long positionInWrapped = wrapped.m4309fromParentPositionMKHz9U(pointerPosition);
            wrapped.m4315hitTestYqVAtuI(hitTestSource, positionInWrapped, hitTestResult, isTouchEvent, isInLayer);
        }
    }

    public final Rect touchBoundsInRoot() {
        if (!isAttached()) {
            return Rect.Companion.getZero();
        }
        LayoutCoordinates root = LayoutCoordinatesKt.findRootCoordinates(this);
        MutableRect bounds = getRectCache();
        long padding = m4307calculateMinimumTouchTargetPaddingE7KxVPU(m4311getMinimumTouchTargetSizeNHjbRc());
        bounds.setLeft(-Size.m2437getWidthimpl(padding));
        bounds.setTop(-Size.m2434getHeightimpl(padding));
        bounds.setRight(getMeasuredWidth() + Size.m2437getWidthimpl(padding));
        bounds.setBottom(getMeasuredHeight() + Size.m2434getHeightimpl(padding));
        NodeCoordinator coordinator = this;
        while (coordinator != root) {
            coordinator.rectInParent$ui_release(bounds, false, true);
            if (bounds.isEmpty()) {
                return Rect.Companion.getZero();
            }
            NodeCoordinator nodeCoordinator = coordinator.wrappedBy;
            Intrinsics.checkNotNull(nodeCoordinator);
            coordinator = nodeCoordinator;
        }
        return MutableRectKt.toRect(bounds);
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    /* renamed from: windowToLocal-MK-Hz9U */
    public long mo4135windowToLocalMKHz9U(long relativeToWindow) {
        if (isAttached()) {
            LayoutCoordinates root = LayoutCoordinatesKt.findRootCoordinates(this);
            long positionInRoot = Offset.m2372minusMKHz9U(LayoutNodeKt.requireOwner(getLayoutNode()).mo4375calculateLocalPositionMKHz9U(relativeToWindow), LayoutCoordinatesKt.positionInRoot(root));
            return mo4131localPositionOfR5De75A(root, positionInRoot);
        }
        throw new IllegalStateException(ExpectAttachedLayoutCoordinates.toString());
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    /* renamed from: localToWindow-MK-Hz9U */
    public long mo4133localToWindowMKHz9U(long relativeToLocal) {
        long positionInRoot = mo4132localToRootMKHz9U(relativeToLocal);
        Owner owner = LayoutNodeKt.requireOwner(getLayoutNode());
        return owner.mo4376calculatePositionInWindowMKHz9U(positionInRoot);
    }

    private final NodeCoordinator toCoordinator(LayoutCoordinates $this$toCoordinator) {
        NodeCoordinator coordinator;
        LookaheadLayoutCoordinatesImpl lookaheadLayoutCoordinatesImpl = $this$toCoordinator instanceof LookaheadLayoutCoordinatesImpl ? (LookaheadLayoutCoordinatesImpl) $this$toCoordinator : null;
        if (lookaheadLayoutCoordinatesImpl == null || (coordinator = lookaheadLayoutCoordinatesImpl.getCoordinator()) == null) {
            Intrinsics.checkNotNull($this$toCoordinator, "null cannot be cast to non-null type androidx.compose.ui.node.NodeCoordinator");
            return (NodeCoordinator) $this$toCoordinator;
        }
        return coordinator;
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    /* renamed from: localPositionOf-R5De75A */
    public long mo4131localPositionOfR5De75A(LayoutCoordinates sourceCoordinates, long relativeToSource) {
        Intrinsics.checkNotNullParameter(sourceCoordinates, "sourceCoordinates");
        NodeCoordinator nodeCoordinator = toCoordinator(sourceCoordinates);
        NodeCoordinator commonAncestor = findCommonAncestor$ui_release(nodeCoordinator);
        long position = relativeToSource;
        NodeCoordinator coordinator = nodeCoordinator;
        while (coordinator != commonAncestor) {
            position = coordinator.m4319toParentPositionMKHz9U(position);
            NodeCoordinator nodeCoordinator2 = coordinator.wrappedBy;
            Intrinsics.checkNotNull(nodeCoordinator2);
            coordinator = nodeCoordinator2;
        }
        return m4300ancestorToLocalR5De75A(commonAncestor, position);
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    /* renamed from: transformFrom-EL8BTi8 */
    public void mo4134transformFromEL8BTi8(LayoutCoordinates sourceCoordinates, float[] matrix) {
        Intrinsics.checkNotNullParameter(sourceCoordinates, "sourceCoordinates");
        Intrinsics.checkNotNullParameter(matrix, "matrix");
        NodeCoordinator coordinator = toCoordinator(sourceCoordinates);
        NodeCoordinator commonAncestor = findCommonAncestor$ui_release(coordinator);
        Matrix.m2839resetimpl(matrix);
        coordinator.m4306transformToAncestorEL8BTi8(commonAncestor, matrix);
        m4305transformFromAncestorEL8BTi8(commonAncestor, matrix);
    }

    /* renamed from: transformToAncestor-EL8BTi8 */
    private final void m4306transformToAncestorEL8BTi8(NodeCoordinator ancestor, float[] matrix) {
        NodeCoordinator wrapper = this;
        while (!Intrinsics.areEqual(wrapper, ancestor)) {
            OwnedLayer ownedLayer = wrapper.layer;
            if (ownedLayer != null) {
                ownedLayer.mo4373transform58bKbWc(matrix);
            }
            long position = wrapper.mo4276getPositionnOccac();
            if (!IntOffset.m5239equalsimpl0(position, IntOffset.Companion.m5250getZeronOccac())) {
                float[] fArr = tmpMatrix;
                Matrix.m2839resetimpl(fArr);
                Matrix.m2850translateimpl$default(fArr, IntOffset.m5240getXimpl(position), IntOffset.m5241getYimpl(position), 0.0f, 4, null);
                Matrix.m2847timesAssign58bKbWc(matrix, fArr);
            }
            NodeCoordinator nodeCoordinator = wrapper.wrappedBy;
            Intrinsics.checkNotNull(nodeCoordinator);
            wrapper = nodeCoordinator;
        }
    }

    /* renamed from: transformFromAncestor-EL8BTi8 */
    private final void m4305transformFromAncestorEL8BTi8(NodeCoordinator ancestor, float[] matrix) {
        if (!Intrinsics.areEqual(ancestor, this)) {
            NodeCoordinator nodeCoordinator = this.wrappedBy;
            Intrinsics.checkNotNull(nodeCoordinator);
            nodeCoordinator.m4305transformFromAncestorEL8BTi8(ancestor, matrix);
            if (!IntOffset.m5239equalsimpl0(mo4276getPositionnOccac(), IntOffset.Companion.m5250getZeronOccac())) {
                float[] fArr = tmpMatrix;
                Matrix.m2839resetimpl(fArr);
                Matrix.m2850translateimpl$default(fArr, -IntOffset.m5240getXimpl(mo4276getPositionnOccac()), -IntOffset.m5241getYimpl(mo4276getPositionnOccac()), 0.0f, 4, null);
                Matrix.m2847timesAssign58bKbWc(matrix, fArr);
            }
            OwnedLayer ownedLayer = this.layer;
            if (ownedLayer != null) {
                ownedLayer.mo4368inverseTransform58bKbWc(matrix);
            }
        }
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    public Rect localBoundingBoxOf(LayoutCoordinates sourceCoordinates, boolean clipBounds) {
        Intrinsics.checkNotNullParameter(sourceCoordinates, "sourceCoordinates");
        if (isAttached()) {
            if (!sourceCoordinates.isAttached()) {
                throw new IllegalStateException(("LayoutCoordinates " + sourceCoordinates + " is not attached!").toString());
            }
            NodeCoordinator srcCoordinator = toCoordinator(sourceCoordinates);
            NodeCoordinator commonAncestor = findCommonAncestor$ui_release(srcCoordinator);
            MutableRect bounds = getRectCache();
            bounds.setLeft(0.0f);
            bounds.setTop(0.0f);
            bounds.setRight(IntSize.m5282getWidthimpl(sourceCoordinates.mo4130getSizeYbymL2g()));
            bounds.setBottom(IntSize.m5281getHeightimpl(sourceCoordinates.mo4130getSizeYbymL2g()));
            NodeCoordinator coordinator = srcCoordinator;
            while (coordinator != commonAncestor) {
                rectInParent$ui_release$default(coordinator, bounds, clipBounds, false, 4, null);
                if (bounds.isEmpty()) {
                    return Rect.Companion.getZero();
                }
                NodeCoordinator nodeCoordinator = coordinator.wrappedBy;
                Intrinsics.checkNotNull(nodeCoordinator);
                coordinator = nodeCoordinator;
            }
            ancestorToLocal(commonAncestor, bounds, clipBounds);
            return MutableRectKt.toRect(bounds);
        }
        throw new IllegalStateException(ExpectAttachedLayoutCoordinates.toString());
    }

    /* renamed from: ancestorToLocal-R5De75A */
    private final long m4300ancestorToLocalR5De75A(NodeCoordinator ancestor, long offset) {
        if (ancestor == this) {
            return offset;
        }
        NodeCoordinator wrappedBy = this.wrappedBy;
        if (wrappedBy == null || Intrinsics.areEqual(ancestor, wrappedBy)) {
            return m4309fromParentPositionMKHz9U(offset);
        }
        return m4309fromParentPositionMKHz9U(wrappedBy.m4300ancestorToLocalR5De75A(ancestor, offset));
    }

    private final void ancestorToLocal(NodeCoordinator ancestor, MutableRect rect, boolean clipBounds) {
        if (ancestor == this) {
            return;
        }
        NodeCoordinator nodeCoordinator = this.wrappedBy;
        if (nodeCoordinator != null) {
            nodeCoordinator.ancestorToLocal(ancestor, rect, clipBounds);
        }
        fromParentRect(rect, clipBounds);
    }

    @Override // androidx.compose.ui.layout.LayoutCoordinates
    /* renamed from: localToRoot-MK-Hz9U */
    public long mo4132localToRootMKHz9U(long relativeToLocal) {
        if (isAttached()) {
            long position = relativeToLocal;
            for (NodeCoordinator coordinator = this; coordinator != null; coordinator = coordinator.wrappedBy) {
                position = coordinator.m4319toParentPositionMKHz9U(position);
            }
            return position;
        }
        throw new IllegalStateException(ExpectAttachedLayoutCoordinates.toString());
    }

    protected final void withPositionTranslation(Canvas canvas, Function1<? super Canvas, Unit> block) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        Intrinsics.checkNotNullParameter(block, "block");
        float x = IntOffset.m5240getXimpl(mo4276getPositionnOccac());
        float y = IntOffset.m5241getYimpl(mo4276getPositionnOccac());
        canvas.translate(x, y);
        block.invoke(canvas);
        canvas.translate(-x, -y);
    }

    /* renamed from: toParentPosition-MK-Hz9U */
    public long m4319toParentPositionMKHz9U(long position) {
        OwnedLayer layer = this.layer;
        long targetPosition = layer != null ? layer.mo4370mapOffset8S9VItk(position, false) : position;
        return IntOffsetKt.m5254plusNvtHpc(targetPosition, mo4276getPositionnOccac());
    }

    /* renamed from: fromParentPosition-MK-Hz9U */
    public long m4309fromParentPositionMKHz9U(long position) {
        long relativeToPosition = IntOffsetKt.m5252minusNvtHpc(position, mo4276getPositionnOccac());
        OwnedLayer layer = this.layer;
        return layer != null ? layer.mo4370mapOffset8S9VItk(relativeToPosition, true) : relativeToPosition;
    }

    public final void drawBorder(Canvas canvas, Paint paint) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        Intrinsics.checkNotNullParameter(paint, "paint");
        Rect rect = new Rect(0.5f, 0.5f, IntSize.m5282getWidthimpl(m4169getMeasuredSizeYbymL2g()) - 0.5f, IntSize.m5281getHeightimpl(m4169getMeasuredSizeYbymL2g()) - 0.5f);
        canvas.drawRect(rect, paint);
    }

    public final void onLayoutNodeAttach() {
        onLayerBlockUpdated$default(this, this.layerBlock, false, 2, null);
    }

    public final void onRelease() {
        this.released = true;
        if (this.layer != null) {
            onLayerBlockUpdated$default(this, null, false, 2, null);
        }
    }

    public static /* synthetic */ void rectInParent$ui_release$default(NodeCoordinator nodeCoordinator, MutableRect mutableRect, boolean z, boolean z2, int i, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: rectInParent");
        }
        if ((i & 4) != 0) {
            z2 = false;
        }
        nodeCoordinator.rectInParent$ui_release(mutableRect, z, z2);
    }

    public final void rectInParent$ui_release(MutableRect bounds, boolean clipBounds, boolean clipToMinimumTouchTargetSize) {
        Intrinsics.checkNotNullParameter(bounds, "bounds");
        OwnedLayer layer = this.layer;
        if (layer != null) {
            if (this.isClipping) {
                if (clipToMinimumTouchTargetSize) {
                    long minTouch = m4311getMinimumTouchTargetSizeNHjbRc();
                    float horz = Size.m2437getWidthimpl(minTouch) / 2.0f;
                    float vert = Size.m2434getHeightimpl(minTouch) / 2.0f;
                    bounds.intersect(-horz, -vert, IntSize.m5282getWidthimpl(mo4130getSizeYbymL2g()) + horz, IntSize.m5281getHeightimpl(mo4130getSizeYbymL2g()) + vert);
                } else if (clipBounds) {
                    bounds.intersect(0.0f, 0.0f, IntSize.m5282getWidthimpl(mo4130getSizeYbymL2g()), IntSize.m5281getHeightimpl(mo4130getSizeYbymL2g()));
                }
                if (bounds.isEmpty()) {
                    return;
                }
            }
            layer.mapBounds(bounds, false);
        }
        int x = IntOffset.m5240getXimpl(mo4276getPositionnOccac());
        bounds.setLeft(bounds.getLeft() + x);
        bounds.setRight(bounds.getRight() + x);
        int y = IntOffset.m5241getYimpl(mo4276getPositionnOccac());
        bounds.setTop(bounds.getTop() + y);
        bounds.setBottom(bounds.getBottom() + y);
    }

    private final void fromParentRect(MutableRect bounds, boolean clipBounds) {
        int x = IntOffset.m5240getXimpl(mo4276getPositionnOccac());
        bounds.setLeft(bounds.getLeft() - x);
        bounds.setRight(bounds.getRight() - x);
        int y = IntOffset.m5241getYimpl(mo4276getPositionnOccac());
        bounds.setTop(bounds.getTop() - y);
        bounds.setBottom(bounds.getBottom() - y);
        OwnedLayer layer = this.layer;
        if (layer != null) {
            layer.mapBounds(bounds, true);
            if (this.isClipping && clipBounds) {
                bounds.intersect(0.0f, 0.0f, IntSize.m5282getWidthimpl(mo4130getSizeYbymL2g()), IntSize.m5281getHeightimpl(mo4130getSizeYbymL2g()));
                bounds.isEmpty();
            }
        }
    }

    /* renamed from: withinLayerBounds-k-4lQ0M */
    public final boolean m4321withinLayerBoundsk4lQ0M(long pointerPosition) {
        if (OffsetKt.m2385isFinitek4lQ0M(pointerPosition)) {
            OwnedLayer layer = this.layer;
            return layer == null || !this.isClipping || layer.mo4369isInLayerk4lQ0M(pointerPosition);
        }
        return false;
    }

    /* renamed from: isPointerInBounds-k-4lQ0M */
    protected final boolean m4316isPointerInBoundsk4lQ0M(long pointerPosition) {
        float x = Offset.m2368getXimpl(pointerPosition);
        float y = Offset.m2369getYimpl(pointerPosition);
        return x >= 0.0f && y >= 0.0f && x < ((float) getMeasuredWidth()) && y < ((float) getMeasuredHeight());
    }

    public void invalidateLayer() {
        OwnedLayer layer = this.layer;
        if (layer != null) {
            layer.invalidate();
            return;
        }
        NodeCoordinator nodeCoordinator = this.wrappedBy;
        if (nodeCoordinator != null) {
            nodeCoordinator.invalidateLayer();
        }
    }

    static /* synthetic */ Object propagateRelocationRequest$suspendImpl(NodeCoordinator $this, Rect rect, Continuation<? super Unit> continuation) {
        NodeCoordinator parent = $this.wrappedBy;
        if (parent == null) {
            return Unit.INSTANCE;
        }
        Rect boundingBoxInParentCoordinates = parent.localBoundingBoxOf($this, false);
        Rect rectInParentBounds = rect.m2405translatek4lQ0M(boundingBoxInParentCoordinates.m2403getTopLeftF1C5BW0());
        Object propagateRelocationRequest = parent.propagateRelocationRequest(rectInParentBounds, continuation);
        return propagateRelocationRequest == IntrinsicsKt.getCOROUTINE_SUSPENDED() ? propagateRelocationRequest : Unit.INSTANCE;
    }

    public void onLayoutModifierNodeChanged() {
        OwnedLayer ownedLayer = this.layer;
        if (ownedLayer != null) {
            ownedLayer.invalidate();
        }
    }

    public final NodeCoordinator findCommonAncestor$ui_release(NodeCoordinator other) {
        Intrinsics.checkNotNullParameter(other, "other");
        LayoutNode ancestor1 = other.getLayoutNode();
        LayoutNode ancestor2 = getLayoutNode();
        if (ancestor1 == ancestor2) {
            Modifier.Node otherNode = other.getTail();
            DelegatableNode $this$visitLocalParents$iv = getTail();
            int m4327constructorimpl = NodeKind.m4327constructorimpl(2);
            if (!$this$visitLocalParents$iv.getNode().isAttached()) {
                throw new IllegalStateException("Check failed.".toString());
            }
            for (Modifier.Node next$iv = $this$visitLocalParents$iv.getNode().getParent$ui_release(); next$iv != null; next$iv = next$iv.getParent$ui_release()) {
                if ((next$iv.getKindSet$ui_release() & m4327constructorimpl) != 0) {
                    Modifier.Node it = next$iv;
                    if (it == otherNode) {
                        return other;
                    }
                }
            }
            return this;
        }
        while (ancestor1.getDepth$ui_release() > ancestor2.getDepth$ui_release()) {
            LayoutNode parent$ui_release = ancestor1.getParent$ui_release();
            Intrinsics.checkNotNull(parent$ui_release);
            ancestor1 = parent$ui_release;
        }
        while (ancestor2.getDepth$ui_release() > ancestor1.getDepth$ui_release()) {
            LayoutNode parent$ui_release2 = ancestor2.getParent$ui_release();
            Intrinsics.checkNotNull(parent$ui_release2);
            ancestor2 = parent$ui_release2;
        }
        while (ancestor1 != ancestor2) {
            LayoutNode parent1 = ancestor1.getParent$ui_release();
            LayoutNode parent2 = ancestor2.getParent$ui_release();
            if (parent1 == null || parent2 == null) {
                throw new IllegalArgumentException("layouts are not part of the same hierarchy");
            }
            ancestor1 = parent1;
            ancestor2 = parent2;
        }
        return ancestor2 == getLayoutNode() ? this : ancestor1 == other.getLayoutNode() ? other : ancestor1.getInnerCoordinator$ui_release();
    }

    public final boolean shouldSharePointerInputWithSiblings() {
        DelegatableNode start = headNode(NodeKindKt.m4335getIncludeSelfInTraversalH91voCI(NodeKind.m4327constructorimpl(16)));
        if (start == null) {
            return false;
        }
        DelegatableNode $this$visitLocalChildren_u2d6rFNWt0$iv = start;
        int type$iv = NodeKind.m4327constructorimpl(16);
        if (!$this$visitLocalChildren_u2d6rFNWt0$iv.getNode().isAttached()) {
            throw new IllegalStateException("Check failed.".toString());
        }
        Modifier.Node self$iv$iv = $this$visitLocalChildren_u2d6rFNWt0$iv.getNode();
        if ((self$iv$iv.getAggregateChildKindSet$ui_release() & type$iv) != 0) {
            for (Modifier.Node next$iv$iv = self$iv$iv.getChild$ui_release(); next$iv$iv != null; next$iv$iv = next$iv$iv.getChild$ui_release()) {
                if ((next$iv$iv.getKindSet$ui_release() & type$iv) != 0) {
                    Modifier.Node it$iv = next$iv$iv;
                    if (it$iv instanceof PointerInputModifierNode) {
                        PointerInputModifierNode it = (PointerInputModifierNode) it$iv;
                        if (it.sharePointerInputWithSiblings()) {
                            return true;
                        }
                    } else {
                        continue;
                    }
                }
            }
        }
        return false;
    }

    /* renamed from: offsetFromEdge-MK-Hz9U */
    private final long m4303offsetFromEdgeMKHz9U(long pointerPosition) {
        float x = Offset.m2368getXimpl(pointerPosition);
        float horizontal = Math.max(0.0f, x < 0.0f ? -x : x - getMeasuredWidth());
        float y = Offset.m2369getYimpl(pointerPosition);
        float vertical = Math.max(0.0f, y < 0.0f ? -y : y - getMeasuredHeight());
        return OffsetKt.Offset(horizontal, vertical);
    }

    /* renamed from: calculateMinimumTouchTargetPadding-E7KxVPU */
    protected final long m4307calculateMinimumTouchTargetPaddingE7KxVPU(long minimumTouchTargetSize) {
        float widthDiff = Size.m2437getWidthimpl(minimumTouchTargetSize) - getMeasuredWidth();
        float heightDiff = Size.m2434getHeightimpl(minimumTouchTargetSize) - getMeasuredHeight();
        return SizeKt.Size(Math.max(0.0f, widthDiff / 2.0f), Math.max(0.0f, heightDiff / 2.0f));
    }

    /* renamed from: distanceInMinimumTouchTarget-tz77jQw */
    public final float m4308distanceInMinimumTouchTargettz77jQw(long pointerPosition, long minimumTouchTargetSize) {
        if (getMeasuredWidth() < Size.m2437getWidthimpl(minimumTouchTargetSize) || getMeasuredHeight() < Size.m2434getHeightimpl(minimumTouchTargetSize)) {
            long m4307calculateMinimumTouchTargetPaddingE7KxVPU = m4307calculateMinimumTouchTargetPaddingE7KxVPU(minimumTouchTargetSize);
            float width = Size.m2437getWidthimpl(m4307calculateMinimumTouchTargetPaddingE7KxVPU);
            float height = Size.m2434getHeightimpl(m4307calculateMinimumTouchTargetPaddingE7KxVPU);
            long offsetFromEdge = m4303offsetFromEdgeMKHz9U(pointerPosition);
            if ((width > 0.0f || height > 0.0f) && Offset.m2368getXimpl(offsetFromEdge) <= width && Offset.m2369getYimpl(offsetFromEdge) <= height) {
                return Offset.m2367getDistanceSquaredimpl(offsetFromEdge);
            }
            return Float.POSITIVE_INFINITY;
        }
        return Float.POSITIVE_INFINITY;
    }

    /* compiled from: NodeCoordinator.kt */
    @Metadata(d1 = {"\u0000J\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0080\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0086T¢\u0006\u0002\n\u0000R\u001d\u0010\u0005\u001a\b\u0012\u0004\u0012\u00020\u00070\u0006¢\u0006\u000e\n\u0000\u0012\u0004\b\b\u0010\u0002\u001a\u0004\b\t\u0010\nR\u0017\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\f0\u0006¢\u0006\b\n\u0000\u001a\u0004\b\r\u0010\nR\u000e\u0010\u000e\u001a\u00020\u0004X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u000f\u001a\u00020\u0010X\u0082\u0004¢\u0006\u0002\n\u0000R\u001a\u0010\u0011\u001a\u000e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\u00140\u0012X\u0082\u0004¢\u0006\u0002\n\u0000R\u001a\u0010\u0015\u001a\u000e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\u00140\u0012X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0016\u001a\u00020\u0017X\u0082\u0004¢\u0006\u0002\n\u0000R\u0019\u0010\u0018\u001a\u00020\u0019X\u0082\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\n\u0002\u0010\u001a\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u0006\u001b"}, d2 = {"Landroidx/compose/ui/node/NodeCoordinator$Companion;", "", "()V", "ExpectAttachedLayoutCoordinates", "", "PointerInputSource", "Landroidx/compose/ui/node/NodeCoordinator$HitTestSource;", "Landroidx/compose/ui/node/PointerInputModifierNode;", "getPointerInputSource$annotations", "getPointerInputSource", "()Landroidx/compose/ui/node/NodeCoordinator$HitTestSource;", "SemanticsSource", "Landroidx/compose/ui/node/SemanticsModifierNode;", "getSemanticsSource", "UnmeasuredError", "graphicsLayerScope", "Landroidx/compose/ui/graphics/ReusableGraphicsLayerScope;", "onCommitAffectingLayer", "Lkotlin/Function1;", "Landroidx/compose/ui/node/NodeCoordinator;", "", "onCommitAffectingLayerParams", "tmpLayerPositionalProperties", "Landroidx/compose/ui/node/LayerPositionalProperties;", "tmpMatrix", "Landroidx/compose/ui/graphics/Matrix;", "[F", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ void getPointerInputSource$annotations() {
        }

        private Companion() {
        }

        public final HitTestSource<PointerInputModifierNode> getPointerInputSource() {
            return NodeCoordinator.PointerInputSource;
        }

        public final HitTestSource<SemanticsModifierNode> getSemanticsSource() {
            return NodeCoordinator.SemanticsSource;
        }
    }
}
