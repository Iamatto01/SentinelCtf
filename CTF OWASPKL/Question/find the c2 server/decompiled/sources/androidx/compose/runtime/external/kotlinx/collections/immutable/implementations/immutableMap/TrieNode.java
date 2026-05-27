package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

import androidx.autofill.HintConstants;
import androidx.compose.runtime.external.kotlinx.collections.immutable.internal.CommonFunctionsKt;
import androidx.compose.runtime.external.kotlinx.collections.immutable.internal.DeltaCounter;
import androidx.compose.runtime.external.kotlinx.collections.immutable.internal.MutabilityOwnership;
import java.util.Arrays;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function5;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntProgression;
import kotlin.ranges.RangesKt;
/* compiled from: TrieNode.kt */
@Metadata(d1 = {"\u0000X\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0011\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0010\u000b\n\u0002\b*\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b(\b\u0000\u0018\u0000 }*\u0004\b\u0000\u0010\u0001*\u0004\b\u0001\u0010\u00022\u00020\u0003:\u0002}~B'\b\u0016\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u0012\u000e\u0010\u0007\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00030\b¢\u0006\u0002\u0010\tB/\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u0012\u000e\u0010\u0007\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00030\b\u0012\b\u0010\n\u001a\u0004\u0018\u00010\u000b¢\u0006\u0002\u0010\fJ\u0091\u0001\u0010\u0011\u001a\u00020\u00122\u0081\u0001\u0010\u0013\u001a}\u0012\u001f\u0012\u001d\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u0000¢\u0006\f\b\u0015\u0012\b\b\u0016\u0012\u0004\b\b(\u0017\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\u0015\u0012\b\b\u0016\u0012\u0004\b\b(\u0018\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\u0015\u0012\b\b\u0016\u0012\u0004\b\b(\u0019\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\u0015\u0012\b\b\u0016\u0012\u0004\b\b(\u0004\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\u0015\u0012\b\b\u0016\u0012\u0004\b\b(\u0006\u0012\u0004\u0012\u00020\u00120\u0014H\u0000¢\u0006\u0002\b\u001aJ\u009c\u0001\u0010\u0011\u001a\u00020\u00122\u0081\u0001\u0010\u0013\u001a}\u0012\u001f\u0012\u001d\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u0000¢\u0006\f\b\u0015\u0012\b\b\u0016\u0012\u0004\b\b(\u0017\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\u0015\u0012\b\b\u0016\u0012\u0004\b\b(\u0018\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\u0015\u0012\b\b\u0016\u0012\u0004\b\b(\u0019\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\u0015\u0012\b\b\u0016\u0012\u0004\b\b(\u0004\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\u0015\u0012\b\b\u0016\u0012\u0004\b\b(\u0006\u0012\u0004\u0012\u00020\u00120\u00142\u0006\u0010\u0019\u001a\u00020\u00052\u0006\u0010\u0018\u001a\u00020\u0005H\u0002J\u0014\u0010\u001b\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u001cH\u0002J\u0014\u0010\u001d\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u001cH\u0002JO\u0010\u001e\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00030\b2\u0006\u0010\u001f\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\u00052\u0006\u0010!\u001a\u00020\u00052\u0006\u0010\"\u001a\u00028\u00002\u0006\u0010#\u001a\u00028\u00012\u0006\u0010\u0018\u001a\u00020\u00052\b\u0010$\u001a\u0004\u0018\u00010\u000bH\u0002¢\u0006\u0002\u0010%J\b\u0010&\u001a\u00020\u0005H\u0002J\u0015\u0010'\u001a\u00020(2\u0006\u0010)\u001a\u00028\u0000H\u0002¢\u0006\u0002\u0010*J\u0017\u0010+\u001a\u0004\u0018\u00018\u00012\u0006\u0010)\u001a\u00028\u0000H\u0002¢\u0006\u0002\u0010,J+\u0010-\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u001c2\u0006\u0010)\u001a\u00028\u00002\u0006\u0010.\u001a\u00028\u0001H\u0002¢\u0006\u0002\u0010/J#\u00100\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u0010)\u001a\u00028\u0000H\u0002¢\u0006\u0002\u00101J+\u00100\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u0010)\u001a\u00028\u00002\u0006\u0010.\u001a\u00028\u0001H\u0002¢\u0006\u0002\u00102J\u001e\u00103\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u00104\u001a\u00020\u0005H\u0002J#\u00105\u001a\u00020(2\u0006\u00106\u001a\u00020\u00052\u0006\u0010)\u001a\u00028\u00002\u0006\u0010\u0018\u001a\u00020\u0005¢\u0006\u0002\u00107J\u001c\u00108\u001a\u00020(2\u0012\u00109\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u0000H\u0002J\r\u0010:\u001a\u00020\u0005H\u0000¢\u0006\u0002\b;J\u0015\u0010<\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\u0005H\u0000¢\u0006\u0002\b=J%\u0010>\u001a\u0004\u0018\u00018\u00012\u0006\u00106\u001a\u00020\u00052\u0006\u0010)\u001a\u00028\u00002\u0006\u0010\u0018\u001a\u00020\u0005¢\u0006\u0002\u0010?J\u0015\u0010@\u001a\u00020(2\u0006\u0010 \u001a\u00020\u0005H\u0000¢\u0006\u0002\bAJ\u0010\u0010B\u001a\u00020(2\u0006\u0010 \u001a\u00020\u0005H\u0002J1\u0010C\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010 \u001a\u00020\u00052\u0006\u0010)\u001a\u00028\u00002\u0006\u0010.\u001a\u00028\u0001H\u0002¢\u0006\u0002\u0010DJ\u0015\u0010E\u001a\u00028\u00002\u0006\u0010\u001f\u001a\u00020\u0005H\u0002¢\u0006\u0002\u0010FJ[\u0010G\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010H\u001a\u00020\u00052\u0006\u0010I\u001a\u00028\u00002\u0006\u0010J\u001a\u00028\u00012\u0006\u0010K\u001a\u00020\u00052\u0006\u0010L\u001a\u00028\u00002\u0006\u0010M\u001a\u00028\u00012\u0006\u0010\u0018\u001a\u00020\u00052\b\u0010$\u001a\u0004\u0018\u00010\u000bH\u0002¢\u0006\u0002\u0010NJI\u0010O\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010\u001f\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\u00052\u0006\u0010!\u001a\u00020\u00052\u0006\u0010\"\u001a\u00028\u00002\u0006\u0010#\u001a\u00028\u00012\u0006\u0010\u0018\u001a\u00020\u0005H\u0002¢\u0006\u0002\u0010PJ=\u0010Q\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010)\u001a\u00028\u00002\u0006\u0010.\u001a\u00028\u00012\u0012\u0010R\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010SH\u0002¢\u0006\u0002\u0010TJ8\u0010U\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0012\u00109\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010V\u001a\u00020W2\u0006\u0010$\u001a\u00020\u000bH\u0002J?\u0010X\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u0010)\u001a\u00028\u00002\u0006\u0010.\u001a\u00028\u00012\u0012\u0010R\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010SH\u0002¢\u0006\u0002\u0010TJ7\u0010X\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u0010)\u001a\u00028\u00002\u0012\u0010R\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010SH\u0002¢\u0006\u0002\u0010YJ2\u0010Z\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u00104\u001a\u00020\u00052\u0012\u0010R\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010SH\u0002J9\u0010[\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010 \u001a\u00020\u00052\u0006\u0010)\u001a\u00028\u00002\u0006\u0010.\u001a\u00028\u00012\u0006\u0010$\u001a\u00020\u000bH\u0002¢\u0006\u0002\u0010\\JQ\u0010]\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010\u001f\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\u00052\u0006\u0010!\u001a\u00020\u00052\u0006\u0010\"\u001a\u00028\u00002\u0006\u0010#\u001a\u00028\u00012\u0006\u0010\u0018\u001a\u00020\u00052\u0006\u0010$\u001a\u00020\u000bH\u0002¢\u0006\u0002\u0010^JK\u0010_\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u00106\u001a\u00020\u00052\u0006\u0010)\u001a\u00028\u00002\u0006\u0010.\u001a\u00028\u00012\u0006\u0010\u0018\u001a\u00020\u00052\u0012\u0010R\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010S¢\u0006\u0002\u0010`JJ\u0010a\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0012\u00109\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010\u0018\u001a\u00020\u00052\u0006\u0010V\u001a\u00020W2\u0012\u0010R\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010SJT\u0010b\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0012\u00109\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010 \u001a\u00020\u00052\u0006\u0010\u0018\u001a\u00020\u00052\u0006\u0010V\u001a\u00020W2\u0012\u0010R\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010SH\u0002JM\u0010c\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u00106\u001a\u00020\u00052\u0006\u0010)\u001a\u00028\u00002\u0006\u0010.\u001a\u00028\u00012\u0006\u0010\u0018\u001a\u00020\u00052\u0012\u0010R\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010S¢\u0006\u0002\u0010`JE\u0010c\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u00106\u001a\u00020\u00052\u0006\u0010)\u001a\u00028\u00002\u0006\u0010\u0018\u001a\u00020\u00052\u0012\u0010R\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010S¢\u0006\u0002\u0010dJ:\u0010e\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u0010\u001f\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\u00052\u0012\u0010R\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010SH\u0002J.\u0010f\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u0010g\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\u00052\u0006\u0010$\u001a\u00020\u000bH\u0002JX\u0010h\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0012\u0010i\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0014\u0010j\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u0010g\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\u00052\u0006\u0010$\u001a\u00020\u000bH\u0002J8\u0010k\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010g\u001a\u00020\u00052\u0012\u0010j\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010$\u001a\u00020\u000bH\u0002J=\u0010l\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010\u001f\u001a\u00020\u00052\u0006\u0010.\u001a\u00028\u00012\u0012\u0010R\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010SH\u0002¢\u0006\u0002\u0010mJ!\u0010n\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010g\u001a\u00020\u0005H\u0000¢\u0006\u0002\boJ\u0015\u0010g\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\u0005H\u0000¢\u0006\u0002\bpJ9\u0010q\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u001c2\u0006\u00106\u001a\u00020\u00052\u0006\u0010)\u001a\u00028\u00002\u0006\u0010.\u001a\u00028\u00012\u0006\u0010\u0018\u001a\u00020\u0005¢\u0006\u0002\u0010rJ9\u0010s\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u00106\u001a\u00020\u00052\u0006\u0010)\u001a\u00028\u00002\u0006\u0010.\u001a\u00028\u00012\u0006\u0010\u0018\u001a\u00020\u0005¢\u0006\u0002\u0010tJ1\u0010s\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u00106\u001a\u00020\u00052\u0006\u0010)\u001a\u00028\u00002\u0006\u0010\u0018\u001a\u00020\u0005¢\u0006\u0002\u0010uJ&\u0010v\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u0010\u001f\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\u0005H\u0002J&\u0010w\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u0010g\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\u0005H\u0002JP\u0010x\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0012\u0010i\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0014\u0010j\u001a\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00002\u0006\u0010g\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\u0005H\u0002J8\u0010y\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010g\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\u00052\u0012\u0010j\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u0000H\u0002J)\u0010z\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u00002\u0006\u0010\u001f\u001a\u00020\u00052\u0006\u0010.\u001a\u00028\u0001H\u0002¢\u0006\u0002\u0010{J\u0015\u0010|\u001a\u00028\u00012\u0006\u0010\u001f\u001a\u00020\u0005H\u0002¢\u0006\u0002\u0010FR0\u0010\u0007\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00030\b2\u000e\u0010\r\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00030\b@BX\u0080\u000e¢\u0006\n\n\u0002\u0010\u0010\u001a\u0004\b\u000e\u0010\u000fR\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0005X\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\n\u001a\u0004\u0018\u00010\u000bX\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u007f"}, d2 = {"Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "K", "V", "", "dataMap", "", "nodeMap", "buffer", "", "(II[Ljava/lang/Object;)V", "ownedBy", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/internal/MutabilityOwnership;", "(II[Ljava/lang/Object;Landroidx/compose/runtime/external/kotlinx/collections/immutable/internal/MutabilityOwnership;)V", "<set-?>", "getBuffer$runtime_release", "()[Ljava/lang/Object;", "[Ljava/lang/Object;", "accept", "", "visitor", "Lkotlin/Function5;", "Lkotlin/ParameterName;", HintConstants.AUTOFILL_HINT_NAME, "node", "shift", "hash", "accept$runtime_release", "asInsertResult", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode$ModificationResult;", "asUpdateResult", "bufferMoveEntryToNode", "keyIndex", "positionMask", "newKeyHash", "newKey", "newValue", "owner", "(IIILjava/lang/Object;Ljava/lang/Object;ILandroidx/compose/runtime/external/kotlinx/collections/immutable/internal/MutabilityOwnership;)[Ljava/lang/Object;", "calculateSize", "collisionContainsKey", "", "key", "(Ljava/lang/Object;)Z", "collisionGet", "(Ljava/lang/Object;)Ljava/lang/Object;", "collisionPut", "value", "(Ljava/lang/Object;Ljava/lang/Object;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode$ModificationResult;", "collisionRemove", "(Ljava/lang/Object;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "(Ljava/lang/Object;Ljava/lang/Object;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "collisionRemoveEntryAtIndex", "i", "containsKey", "keyHash", "(ILjava/lang/Object;I)Z", "elementsIdentityEquals", "otherNode", "entryCount", "entryCount$runtime_release", "entryKeyIndex", "entryKeyIndex$runtime_release", "get", "(ILjava/lang/Object;I)Ljava/lang/Object;", "hasEntryAt", "hasEntryAt$runtime_release", "hasNodeAt", "insertEntryAt", "(ILjava/lang/Object;Ljava/lang/Object;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "keyAtIndex", "(I)Ljava/lang/Object;", "makeNode", "keyHash1", "key1", "value1", "keyHash2", "key2", "value2", "(ILjava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;Ljava/lang/Object;ILandroidx/compose/runtime/external/kotlinx/collections/immutable/internal/MutabilityOwnership;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "moveEntryToNode", "(IIILjava/lang/Object;Ljava/lang/Object;I)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "mutableCollisionPut", "mutator", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/PersistentHashMapBuilder;", "(Ljava/lang/Object;Ljava/lang/Object;Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/PersistentHashMapBuilder;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "mutableCollisionPutAll", "intersectionCounter", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/internal/DeltaCounter;", "mutableCollisionRemove", "(Ljava/lang/Object;Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/PersistentHashMapBuilder;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "mutableCollisionRemoveEntryAtIndex", "mutableInsertEntryAt", "(ILjava/lang/Object;Ljava/lang/Object;Landroidx/compose/runtime/external/kotlinx/collections/immutable/internal/MutabilityOwnership;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "mutableMoveEntryToNode", "(IIILjava/lang/Object;Ljava/lang/Object;ILandroidx/compose/runtime/external/kotlinx/collections/immutable/internal/MutabilityOwnership;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "mutablePut", "(ILjava/lang/Object;Ljava/lang/Object;ILandroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/PersistentHashMapBuilder;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "mutablePutAll", "mutablePutAllFromOtherNodeCell", "mutableRemove", "(ILjava/lang/Object;ILandroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/PersistentHashMapBuilder;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "mutableRemoveEntryAtIndex", "mutableRemoveNodeAtIndex", "nodeIndex", "mutableReplaceNode", "targetNode", "newNode", "mutableUpdateNodeAtIndex", "mutableUpdateValueAtIndex", "(ILjava/lang/Object;Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/PersistentHashMapBuilder;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "nodeAtIndex", "nodeAtIndex$runtime_release", "nodeIndex$runtime_release", "put", "(ILjava/lang/Object;Ljava/lang/Object;I)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode$ModificationResult;", "remove", "(ILjava/lang/Object;Ljava/lang/Object;I)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "(ILjava/lang/Object;I)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "removeEntryAtIndex", "removeNodeAtIndex", "replaceNode", "updateNodeAtIndex", "updateValueAtIndex", "(ILjava/lang/Object;)Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "valueAtKeyIndex", "Companion", "ModificationResult", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class TrieNode<K, V> {
    public static final Companion Companion = new Companion(null);
    private static final TrieNode EMPTY = new TrieNode(0, 0, new Object[0]);
    private Object[] buffer;
    private int dataMap;
    private int nodeMap;
    private final MutabilityOwnership ownedBy;

    public TrieNode(int dataMap, int nodeMap, Object[] buffer, MutabilityOwnership ownedBy) {
        Intrinsics.checkNotNullParameter(buffer, "buffer");
        this.dataMap = dataMap;
        this.nodeMap = nodeMap;
        this.ownedBy = ownedBy;
        this.buffer = buffer;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public TrieNode(int dataMap, int nodeMap, Object[] buffer) {
        this(dataMap, nodeMap, buffer, null);
        Intrinsics.checkNotNullParameter(buffer, "buffer");
    }

    /* compiled from: TrieNode.kt */
    @Metadata(d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\t\n\u0002\u0018\u0002\n\u0000\b\u0000\u0018\u0000*\u0004\b\u0002\u0010\u0001*\u0004\b\u0003\u0010\u00022\u00020\u0003B!\u0012\u0012\u0010\u0004\u001a\u000e\u0012\u0004\u0012\u00028\u0002\u0012\u0004\u0012\u00028\u00030\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007¢\u0006\u0002\u0010\bJD\u0010\u000f\u001a\u000e\u0012\u0004\u0012\u00028\u0002\u0012\u0004\u0012\u00028\u00030\u00002*\u0010\u0010\u001a&\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00028\u0002\u0012\u0004\u0012\u00028\u00030\u0005\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00028\u0002\u0012\u0004\u0012\u00028\u00030\u00050\u0011H\u0086\bø\u0001\u0000R&\u0010\u0004\u001a\u000e\u0012\u0004\u0012\u00028\u0002\u0012\u0004\u0012\u00028\u00030\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\fR\u0011\u0010\u0006\u001a\u00020\u0007¢\u0006\b\n\u0000\u001a\u0004\b\r\u0010\u000e\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006\u0012"}, d2 = {"Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode$ModificationResult;", "K", "V", "", "node", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "sizeDelta", "", "(Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;I)V", "getNode", "()Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "setNode", "(Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;)V", "getSizeDelta", "()I", "replaceNode", "operation", "Lkotlin/Function1;", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class ModificationResult<K, V> {
        private TrieNode<K, V> node;
        private final int sizeDelta;

        public ModificationResult(TrieNode<K, V> node, int sizeDelta) {
            Intrinsics.checkNotNullParameter(node, "node");
            this.node = node;
            this.sizeDelta = sizeDelta;
        }

        public final TrieNode<K, V> getNode() {
            return this.node;
        }

        public final int getSizeDelta() {
            return this.sizeDelta;
        }

        public final void setNode(TrieNode<K, V> trieNode) {
            Intrinsics.checkNotNullParameter(trieNode, "<set-?>");
            this.node = trieNode;
        }

        public final ModificationResult<K, V> replaceNode(Function1<? super TrieNode<K, V>, TrieNode<K, V>> operation) {
            Intrinsics.checkNotNullParameter(operation, "operation");
            ModificationResult<K, V> $this$replaceNode_u24lambda_u240 = this;
            $this$replaceNode_u24lambda_u240.setNode(operation.invoke($this$replaceNode_u24lambda_u240.getNode()));
            return this;
        }
    }

    private final ModificationResult<K, V> asInsertResult() {
        return new ModificationResult<>(this, 1);
    }

    private final ModificationResult<K, V> asUpdateResult() {
        return new ModificationResult<>(this, 0);
    }

    public final Object[] getBuffer$runtime_release() {
        return this.buffer;
    }

    public final int entryCount$runtime_release() {
        return Integer.bitCount(this.dataMap);
    }

    public final boolean hasEntryAt$runtime_release(int positionMask) {
        return (this.dataMap & positionMask) != 0;
    }

    private final boolean hasNodeAt(int positionMask) {
        return (this.nodeMap & positionMask) != 0;
    }

    public final int entryKeyIndex$runtime_release(int positionMask) {
        return Integer.bitCount(this.dataMap & (positionMask - 1)) * 2;
    }

    public final int nodeIndex$runtime_release(int positionMask) {
        return (this.buffer.length - 1) - Integer.bitCount(this.nodeMap & (positionMask - 1));
    }

    private final K keyAtIndex(int keyIndex) {
        return (K) this.buffer[keyIndex];
    }

    private final V valueAtKeyIndex(int keyIndex) {
        return (V) this.buffer[keyIndex + 1];
    }

    public final TrieNode<K, V> nodeAtIndex$runtime_release(int nodeIndex) {
        Object obj = this.buffer[nodeIndex];
        Intrinsics.checkNotNull(obj, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNode, V of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNode>");
        return (TrieNode) obj;
    }

    private final TrieNode<K, V> insertEntryAt(int positionMask, K k, V v) {
        int keyIndex = entryKeyIndex$runtime_release(positionMask);
        Object[] newBuffer = TrieNodeKt.access$insertEntryAtIndex(this.buffer, keyIndex, k, v);
        return new TrieNode<>(this.dataMap | positionMask, this.nodeMap, newBuffer);
    }

    private final TrieNode<K, V> mutableInsertEntryAt(int positionMask, K k, V v, MutabilityOwnership owner) {
        int keyIndex = entryKeyIndex$runtime_release(positionMask);
        if (this.ownedBy == owner) {
            this.buffer = TrieNodeKt.access$insertEntryAtIndex(this.buffer, keyIndex, k, v);
            this.dataMap |= positionMask;
            return this;
        }
        Object[] newBuffer = TrieNodeKt.access$insertEntryAtIndex(this.buffer, keyIndex, k, v);
        return new TrieNode<>(this.dataMap | positionMask, this.nodeMap, newBuffer, owner);
    }

    private final TrieNode<K, V> updateValueAtIndex(int keyIndex, V v) {
        Object[] objArr = this.buffer;
        Object[] newBuffer = Arrays.copyOf(objArr, objArr.length);
        Intrinsics.checkNotNullExpressionValue(newBuffer, "copyOf(this, size)");
        newBuffer[keyIndex + 1] = v;
        return new TrieNode<>(this.dataMap, this.nodeMap, newBuffer);
    }

    private final TrieNode<K, V> mutableUpdateValueAtIndex(int keyIndex, V v, PersistentHashMapBuilder<K, V> persistentHashMapBuilder) {
        if (this.ownedBy == persistentHashMapBuilder.getOwnership$runtime_release()) {
            this.buffer[keyIndex + 1] = v;
            return this;
        }
        persistentHashMapBuilder.setModCount$runtime_release(persistentHashMapBuilder.getModCount$runtime_release() + 1);
        Object[] objArr = this.buffer;
        Object[] newBuffer = Arrays.copyOf(objArr, objArr.length);
        Intrinsics.checkNotNullExpressionValue(newBuffer, "copyOf(this, size)");
        newBuffer[keyIndex + 1] = v;
        return new TrieNode<>(this.dataMap, this.nodeMap, newBuffer, persistentHashMapBuilder.getOwnership$runtime_release());
    }

    private final TrieNode<K, V> updateNodeAtIndex(int nodeIndex, int positionMask, TrieNode<K, V> trieNode) {
        Object[] newNodeBuffer = trieNode.buffer;
        if (newNodeBuffer.length == 2 && trieNode.nodeMap == 0) {
            if (this.buffer.length == 1) {
                trieNode.dataMap = this.nodeMap;
                return trieNode;
            }
            int keyIndex = entryKeyIndex$runtime_release(positionMask);
            return new TrieNode<>(this.dataMap ^ positionMask, this.nodeMap ^ positionMask, TrieNodeKt.access$replaceNodeWithEntry(this.buffer, nodeIndex, keyIndex, newNodeBuffer[0], newNodeBuffer[1]));
        }
        Object[] objArr = this.buffer;
        Object[] newBuffer = Arrays.copyOf(objArr, objArr.length);
        Intrinsics.checkNotNullExpressionValue(newBuffer, "copyOf(this, newSize)");
        newBuffer[nodeIndex] = trieNode;
        return new TrieNode<>(this.dataMap, this.nodeMap, newBuffer);
    }

    private final TrieNode<K, V> mutableUpdateNodeAtIndex(int nodeIndex, TrieNode<K, V> trieNode, MutabilityOwnership owner) {
        Object[] objArr = this.buffer;
        if (objArr.length == 1 && trieNode.buffer.length == 2 && trieNode.nodeMap == 0) {
            trieNode.dataMap = this.nodeMap;
            return trieNode;
        } else if (this.ownedBy == owner) {
            objArr[nodeIndex] = trieNode;
            return this;
        } else {
            Object[] newBuffer = Arrays.copyOf(objArr, objArr.length);
            Intrinsics.checkNotNullExpressionValue(newBuffer, "copyOf(this, size)");
            newBuffer[nodeIndex] = trieNode;
            return new TrieNode<>(this.dataMap, this.nodeMap, newBuffer, owner);
        }
    }

    private final TrieNode<K, V> removeNodeAtIndex(int nodeIndex, int positionMask) {
        Object[] objArr = this.buffer;
        if (objArr.length == 1) {
            return null;
        }
        Object[] newBuffer = TrieNodeKt.access$removeNodeAtIndex(objArr, nodeIndex);
        return new TrieNode<>(this.dataMap, this.nodeMap ^ positionMask, newBuffer);
    }

    private final TrieNode<K, V> mutableRemoveNodeAtIndex(int nodeIndex, int positionMask, MutabilityOwnership owner) {
        Object[] objArr = this.buffer;
        if (objArr.length == 1) {
            return null;
        }
        if (this.ownedBy == owner) {
            this.buffer = TrieNodeKt.access$removeNodeAtIndex(objArr, nodeIndex);
            this.nodeMap ^= positionMask;
            return this;
        }
        Object[] newBuffer = TrieNodeKt.access$removeNodeAtIndex(objArr, nodeIndex);
        return new TrieNode<>(this.dataMap, this.nodeMap ^ positionMask, newBuffer, owner);
    }

    private final Object[] bufferMoveEntryToNode(int keyIndex, int positionMask, int newKeyHash, K k, V v, int shift, MutabilityOwnership owner) {
        K keyAtIndex = keyAtIndex(keyIndex);
        int storedKeyHash = keyAtIndex != null ? keyAtIndex.hashCode() : 0;
        TrieNode newNode = makeNode(storedKeyHash, keyAtIndex, valueAtKeyIndex(keyIndex), newKeyHash, k, v, shift + 5, owner);
        int nodeIndex = nodeIndex$runtime_release(positionMask) + 1;
        return TrieNodeKt.access$replaceEntryWithNode(this.buffer, keyIndex, nodeIndex, newNode);
    }

    private final TrieNode<K, V> moveEntryToNode(int keyIndex, int positionMask, int newKeyHash, K k, V v, int shift) {
        Object[] newBuffer = bufferMoveEntryToNode(keyIndex, positionMask, newKeyHash, k, v, shift, null);
        return new TrieNode<>(this.dataMap ^ positionMask, this.nodeMap | positionMask, newBuffer);
    }

    private final TrieNode<K, V> mutableMoveEntryToNode(int keyIndex, int positionMask, int newKeyHash, K k, V v, int shift, MutabilityOwnership owner) {
        if (this.ownedBy == owner) {
            this.buffer = bufferMoveEntryToNode(keyIndex, positionMask, newKeyHash, k, v, shift, owner);
            this.dataMap ^= positionMask;
            this.nodeMap |= positionMask;
            return this;
        }
        Object[] newBuffer = bufferMoveEntryToNode(keyIndex, positionMask, newKeyHash, k, v, shift, owner);
        return new TrieNode<>(this.dataMap ^ positionMask, this.nodeMap | positionMask, newBuffer, owner);
    }

    private final TrieNode<K, V> makeNode(int keyHash1, K k, V v, int keyHash2, K k2, V v2, int shift, MutabilityOwnership owner) {
        Object[] nodeBuffer;
        if (shift > 30) {
            return new TrieNode<>(0, 0, new Object[]{k, v, k2, v2}, owner);
        }
        int setBit1 = TrieNodeKt.indexSegment(keyHash1, shift);
        int setBit2 = TrieNodeKt.indexSegment(keyHash2, shift);
        if (setBit1 != setBit2) {
            if (setBit1 < setBit2) {
                nodeBuffer = new Object[]{k, v, k2, v2};
            } else {
                nodeBuffer = new Object[]{k2, v2, k, v};
            }
            return new TrieNode<>((1 << setBit1) | (1 << setBit2), 0, nodeBuffer, owner);
        }
        TrieNode node = makeNode(keyHash1, k, v, keyHash2, k2, v2, shift + 5, owner);
        return new TrieNode<>(0, 1 << setBit1, new Object[]{node}, owner);
    }

    private final TrieNode<K, V> removeEntryAtIndex(int keyIndex, int positionMask) {
        Object[] objArr = this.buffer;
        if (objArr.length == 2) {
            return null;
        }
        Object[] newBuffer = TrieNodeKt.access$removeEntryAtIndex(objArr, keyIndex);
        return new TrieNode<>(this.dataMap ^ positionMask, this.nodeMap, newBuffer);
    }

    private final TrieNode<K, V> mutableRemoveEntryAtIndex(int keyIndex, int positionMask, PersistentHashMapBuilder<K, V> persistentHashMapBuilder) {
        persistentHashMapBuilder.setSize(persistentHashMapBuilder.size() - 1);
        persistentHashMapBuilder.setOperationResult$runtime_release(valueAtKeyIndex(keyIndex));
        if (this.buffer.length == 2) {
            return null;
        }
        if (this.ownedBy == persistentHashMapBuilder.getOwnership$runtime_release()) {
            this.buffer = TrieNodeKt.access$removeEntryAtIndex(this.buffer, keyIndex);
            this.dataMap ^= positionMask;
            return this;
        }
        Object[] newBuffer = TrieNodeKt.access$removeEntryAtIndex(this.buffer, keyIndex);
        return new TrieNode<>(this.dataMap ^ positionMask, this.nodeMap, newBuffer, persistentHashMapBuilder.getOwnership$runtime_release());
    }

    private final TrieNode<K, V> collisionRemoveEntryAtIndex(int i) {
        Object[] objArr = this.buffer;
        if (objArr.length == 2) {
            return null;
        }
        Object[] newBuffer = TrieNodeKt.access$removeEntryAtIndex(objArr, i);
        return new TrieNode<>(0, 0, newBuffer);
    }

    private final TrieNode<K, V> mutableCollisionRemoveEntryAtIndex(int i, PersistentHashMapBuilder<K, V> persistentHashMapBuilder) {
        persistentHashMapBuilder.setSize(persistentHashMapBuilder.size() - 1);
        persistentHashMapBuilder.setOperationResult$runtime_release(valueAtKeyIndex(i));
        if (this.buffer.length == 2) {
            return null;
        }
        if (this.ownedBy == persistentHashMapBuilder.getOwnership$runtime_release()) {
            this.buffer = TrieNodeKt.access$removeEntryAtIndex(this.buffer, i);
            return this;
        }
        Object[] newBuffer = TrieNodeKt.access$removeEntryAtIndex(this.buffer, i);
        return new TrieNode<>(0, 0, newBuffer, persistentHashMapBuilder.getOwnership$runtime_release());
    }

    private final boolean collisionContainsKey(K k) {
        IntProgression step = RangesKt.step(RangesKt.until(0, this.buffer.length), 2);
        int i = step.getFirst();
        int last = step.getLast();
        int step2 = step.getStep();
        if ((step2 > 0 && i <= last) || (step2 < 0 && last <= i)) {
            while (!Intrinsics.areEqual(k, this.buffer[i])) {
                if (i != last) {
                    i += step2;
                }
            }
            return true;
        }
        return false;
    }

    private final V collisionGet(K k) {
        IntProgression step = RangesKt.step(RangesKt.until(0, this.buffer.length), 2);
        int i = step.getFirst();
        int last = step.getLast();
        int step2 = step.getStep();
        if ((step2 > 0 && i <= last) || (step2 < 0 && last <= i)) {
            while (!Intrinsics.areEqual(k, keyAtIndex(i))) {
                if (i == last) {
                    return null;
                }
                i += step2;
            }
            return valueAtKeyIndex(i);
        }
        return null;
    }

    private final ModificationResult<K, V> collisionPut(K k, V v) {
        IntProgression step = RangesKt.step(RangesKt.until(0, this.buffer.length), 2);
        int i = step.getFirst();
        int last = step.getLast();
        int step2 = step.getStep();
        if ((step2 > 0 && i <= last) || (step2 < 0 && last <= i)) {
            while (!Intrinsics.areEqual(k, keyAtIndex(i))) {
                if (i != last) {
                    i += step2;
                }
            }
            if (v == valueAtKeyIndex(i)) {
                return null;
            }
            Object[] objArr = this.buffer;
            Object[] newBuffer = Arrays.copyOf(objArr, objArr.length);
            Intrinsics.checkNotNullExpressionValue(newBuffer, "copyOf(this, size)");
            newBuffer[i + 1] = v;
            return new TrieNode(0, 0, newBuffer).asUpdateResult();
        }
        return new TrieNode(0, 0, TrieNodeKt.access$insertEntryAtIndex(this.buffer, 0, k, v)).asInsertResult();
    }

    private final TrieNode<K, V> mutableCollisionPut(K k, V v, PersistentHashMapBuilder<K, V> persistentHashMapBuilder) {
        IntProgression step = RangesKt.step(RangesKt.until(0, this.buffer.length), 2);
        int i = step.getFirst();
        int last = step.getLast();
        int step2 = step.getStep();
        if ((step2 > 0 && i <= last) || (step2 < 0 && last <= i)) {
            while (!Intrinsics.areEqual(k, keyAtIndex(i))) {
                if (i != last) {
                    i += step2;
                }
            }
            persistentHashMapBuilder.setOperationResult$runtime_release(valueAtKeyIndex(i));
            if (this.ownedBy == persistentHashMapBuilder.getOwnership$runtime_release()) {
                this.buffer[i + 1] = v;
                return this;
            }
            persistentHashMapBuilder.setModCount$runtime_release(persistentHashMapBuilder.getModCount$runtime_release() + 1);
            Object[] objArr = this.buffer;
            Object[] newBuffer = Arrays.copyOf(objArr, objArr.length);
            Intrinsics.checkNotNullExpressionValue(newBuffer, "copyOf(this, size)");
            newBuffer[i + 1] = v;
            return new TrieNode<>(0, 0, newBuffer, persistentHashMapBuilder.getOwnership$runtime_release());
        }
        persistentHashMapBuilder.setSize(persistentHashMapBuilder.size() + 1);
        return new TrieNode<>(0, 0, TrieNodeKt.access$insertEntryAtIndex(this.buffer, 0, k, v), persistentHashMapBuilder.getOwnership$runtime_release());
    }

    private final TrieNode<K, V> collisionRemove(K k) {
        IntProgression step = RangesKt.step(RangesKt.until(0, this.buffer.length), 2);
        int i = step.getFirst();
        int last = step.getLast();
        int step2 = step.getStep();
        if ((step2 > 0 && i <= last) || (step2 < 0 && last <= i)) {
            while (!Intrinsics.areEqual(k, keyAtIndex(i))) {
                if (i != last) {
                    i += step2;
                }
            }
            return collisionRemoveEntryAtIndex(i);
        }
        return this;
    }

    private final TrieNode<K, V> mutableCollisionRemove(K k, PersistentHashMapBuilder<K, V> persistentHashMapBuilder) {
        IntProgression step = RangesKt.step(RangesKt.until(0, this.buffer.length), 2);
        int i = step.getFirst();
        int last = step.getLast();
        int step2 = step.getStep();
        if ((step2 > 0 && i <= last) || (step2 < 0 && last <= i)) {
            while (!Intrinsics.areEqual(k, keyAtIndex(i))) {
                if (i != last) {
                    i += step2;
                }
            }
            return mutableCollisionRemoveEntryAtIndex(i, persistentHashMapBuilder);
        }
        return this;
    }

    private final TrieNode<K, V> collisionRemove(K k, V v) {
        IntProgression step = RangesKt.step(RangesKt.until(0, this.buffer.length), 2);
        int i = step.getFirst();
        int last = step.getLast();
        int step2 = step.getStep();
        if ((step2 > 0 && i <= last) || (step2 < 0 && last <= i)) {
            while (true) {
                if (!Intrinsics.areEqual(k, keyAtIndex(i)) || !Intrinsics.areEqual(v, valueAtKeyIndex(i))) {
                    if (i == last) {
                        break;
                    }
                    i += step2;
                } else {
                    return collisionRemoveEntryAtIndex(i);
                }
            }
        }
        return this;
    }

    private final TrieNode<K, V> mutableCollisionRemove(K k, V v, PersistentHashMapBuilder<K, V> persistentHashMapBuilder) {
        IntProgression step = RangesKt.step(RangesKt.until(0, this.buffer.length), 2);
        int i = step.getFirst();
        int last = step.getLast();
        int step2 = step.getStep();
        if ((step2 > 0 && i <= last) || (step2 < 0 && last <= i)) {
            while (true) {
                if (!Intrinsics.areEqual(k, keyAtIndex(i)) || !Intrinsics.areEqual(v, valueAtKeyIndex(i))) {
                    if (i == last) {
                        break;
                    }
                    i += step2;
                } else {
                    return mutableCollisionRemoveEntryAtIndex(i, persistentHashMapBuilder);
                }
            }
        }
        return this;
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final TrieNode<K, V> mutableCollisionPutAll(TrieNode<K, V> trieNode, DeltaCounter intersectionCounter, MutabilityOwnership owner) {
        CommonFunctionsKt.m2259assert(this.nodeMap == 0);
        CommonFunctionsKt.m2259assert(this.dataMap == 0);
        CommonFunctionsKt.m2259assert(trieNode.nodeMap == 0);
        CommonFunctionsKt.m2259assert(trieNode.dataMap == 0);
        Object[] objArr = this.buffer;
        Object[] tempBuffer = Arrays.copyOf(objArr, objArr.length + trieNode.buffer.length);
        Intrinsics.checkNotNullExpressionValue(tempBuffer, "copyOf(this, newSize)");
        int i = this.buffer.length;
        IntProgression step = RangesKt.step(RangesKt.until(0, trieNode.buffer.length), 2);
        int j = step.getFirst();
        int last = step.getLast();
        int step2 = step.getStep();
        if ((step2 > 0 && j <= last) || (step2 < 0 && last <= j)) {
            while (true) {
                if (!collisionContainsKey(trieNode.buffer[j])) {
                    Object[] objArr2 = trieNode.buffer;
                    tempBuffer[i] = objArr2[j];
                    tempBuffer[i + 1] = objArr2[j + 1];
                    i += 2;
                } else {
                    intersectionCounter.setCount(intersectionCounter.getCount() + 1);
                }
                if (j == last) {
                    break;
                }
                j += step2;
            }
        }
        int newSize = i;
        if (newSize == this.buffer.length) {
            return this;
        }
        if (newSize == trieNode.buffer.length) {
            return trieNode;
        }
        if (newSize == tempBuffer.length) {
            return new TrieNode<>(0, 0, tempBuffer, owner);
        }
        Object[] copyOf = Arrays.copyOf(tempBuffer, newSize);
        Intrinsics.checkNotNullExpressionValue(copyOf, "copyOf(this, newSize)");
        return new TrieNode<>(0, 0, copyOf, owner);
    }

    private final TrieNode<K, V> mutablePutAllFromOtherNodeCell(TrieNode<K, V> trieNode, int positionMask, int shift, DeltaCounter intersectionCounter, PersistentHashMapBuilder<K, V> persistentHashMapBuilder) {
        if (hasNodeAt(positionMask)) {
            TrieNode targetNode = nodeAtIndex$runtime_release(nodeIndex$runtime_release(positionMask));
            if (trieNode.hasNodeAt(positionMask)) {
                return targetNode.mutablePutAll(trieNode.nodeAtIndex$runtime_release(trieNode.nodeIndex$runtime_release(positionMask)), shift + 5, intersectionCounter, persistentHashMapBuilder);
            }
            if (trieNode.hasEntryAt$runtime_release(positionMask)) {
                int keyIndex = trieNode.entryKeyIndex$runtime_release(positionMask);
                K keyAtIndex = trieNode.keyAtIndex(keyIndex);
                V valueAtKeyIndex = trieNode.valueAtKeyIndex(keyIndex);
                int oldSize = persistentHashMapBuilder.size();
                TrieNode<K, V> mutablePut = targetNode.mutablePut(keyAtIndex != null ? keyAtIndex.hashCode() : 0, keyAtIndex, valueAtKeyIndex, shift + 5, persistentHashMapBuilder);
                if (persistentHashMapBuilder.size() == oldSize) {
                    intersectionCounter.setCount(intersectionCounter.getCount() + 1);
                }
                return mutablePut;
            }
            return targetNode;
        } else if (trieNode.hasNodeAt(positionMask)) {
            TrieNode otherTargetNode = trieNode.nodeAtIndex$runtime_release(trieNode.nodeIndex$runtime_release(positionMask));
            if (hasEntryAt$runtime_release(positionMask)) {
                int keyIndex2 = entryKeyIndex$runtime_release(positionMask);
                K keyAtIndex2 = keyAtIndex(keyIndex2);
                if (!otherTargetNode.containsKey(keyAtIndex2 != null ? keyAtIndex2.hashCode() : 0, keyAtIndex2, shift + 5)) {
                    return otherTargetNode.mutablePut(keyAtIndex2 != null ? keyAtIndex2.hashCode() : 0, keyAtIndex2, valueAtKeyIndex(keyIndex2), shift + 5, persistentHashMapBuilder);
                }
                intersectionCounter.setCount(intersectionCounter.getCount() + 1);
                return otherTargetNode;
            }
            return otherTargetNode;
        } else {
            int thisKeyIndex = entryKeyIndex$runtime_release(positionMask);
            K keyAtIndex3 = keyAtIndex(thisKeyIndex);
            V valueAtKeyIndex2 = valueAtKeyIndex(thisKeyIndex);
            int otherKeyIndex = trieNode.entryKeyIndex$runtime_release(positionMask);
            K keyAtIndex4 = trieNode.keyAtIndex(otherKeyIndex);
            return makeNode(keyAtIndex3 != null ? keyAtIndex3.hashCode() : 0, keyAtIndex3, valueAtKeyIndex2, keyAtIndex4 != null ? keyAtIndex4.hashCode() : 0, keyAtIndex4, trieNode.valueAtKeyIndex(otherKeyIndex), shift + 5, persistentHashMapBuilder.getOwnership$runtime_release());
        }
    }

    private final int calculateSize() {
        if (this.nodeMap == 0) {
            return this.buffer.length / 2;
        }
        int numValues = Integer.bitCount(this.dataMap);
        int result = numValues;
        int length = this.buffer.length;
        for (int i = numValues * 2; i < length; i++) {
            result += nodeAtIndex$runtime_release(i).calculateSize();
        }
        return result;
    }

    private final boolean elementsIdentityEquals(TrieNode<K, V> trieNode) {
        if (this == trieNode) {
            return true;
        }
        if (this.nodeMap == trieNode.nodeMap && this.dataMap == trieNode.dataMap) {
            int length = this.buffer.length;
            for (int i = 0; i < length; i++) {
                if (this.buffer[i] != trieNode.buffer[i]) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    public final boolean containsKey(int keyHash, K k, int shift) {
        int keyPositionMask = 1 << TrieNodeKt.indexSegment(keyHash, shift);
        if (hasEntryAt$runtime_release(keyPositionMask)) {
            return Intrinsics.areEqual(k, keyAtIndex(entryKeyIndex$runtime_release(keyPositionMask)));
        }
        if (hasNodeAt(keyPositionMask)) {
            TrieNode targetNode = nodeAtIndex$runtime_release(nodeIndex$runtime_release(keyPositionMask));
            if (shift == 30) {
                return targetNode.collisionContainsKey(k);
            }
            return targetNode.containsKey(keyHash, k, shift + 5);
        }
        return false;
    }

    public final V get(int keyHash, K k, int shift) {
        int keyPositionMask = 1 << TrieNodeKt.indexSegment(keyHash, shift);
        if (hasEntryAt$runtime_release(keyPositionMask)) {
            int keyIndex = entryKeyIndex$runtime_release(keyPositionMask);
            if (Intrinsics.areEqual(k, keyAtIndex(keyIndex))) {
                return valueAtKeyIndex(keyIndex);
            }
            return null;
        } else if (hasNodeAt(keyPositionMask)) {
            TrieNode targetNode = nodeAtIndex$runtime_release(nodeIndex$runtime_release(keyPositionMask));
            if (shift == 30) {
                return targetNode.collisionGet(k);
            }
            return targetNode.get(keyHash, k, shift + 5);
        } else {
            return null;
        }
    }

    public final TrieNode<K, V> mutablePutAll(TrieNode<K, V> otherNode, int shift, DeltaCounter intersectionCounter, PersistentHashMapBuilder<K, V> mutator) {
        TrieNode trieNode;
        int $this$forEachOneBit$iv;
        boolean z;
        Intrinsics.checkNotNullParameter(otherNode, "otherNode");
        Intrinsics.checkNotNullParameter(intersectionCounter, "intersectionCounter");
        Intrinsics.checkNotNullParameter(mutator, "mutator");
        if (this == otherNode) {
            intersectionCounter.plusAssign(calculateSize());
            return this;
        } else if (shift > 30) {
            return mutableCollisionPutAll(otherNode, intersectionCounter, mutator.getOwnership$runtime_release());
        } else {
            int newNodeMap = this.nodeMap | otherNode.nodeMap;
            int i = this.dataMap;
            int i2 = otherNode.dataMap;
            int newDataMap = (i ^ i2) & (~newNodeMap);
            int $this$forEachOneBit$iv2 = i & i2;
            int mask$iv = $this$forEachOneBit$iv2;
            int index$iv = 0;
            int newNodeMap2 = newNodeMap;
            int newDataMap2 = newDataMap;
            while (mask$iv != 0) {
                int bit$iv = Integer.lowestOneBit(mask$iv);
                Object leftKey = keyAtIndex(entryKeyIndex$runtime_release(bit$iv));
                Object rightKey = otherNode.keyAtIndex(otherNode.entryKeyIndex$runtime_release(bit$iv));
                if (!Intrinsics.areEqual(leftKey, rightKey)) {
                    newNodeMap2 |= bit$iv;
                } else {
                    newDataMap2 |= bit$iv;
                }
                index$iv++;
                mask$iv ^= bit$iv;
            }
            if (!((newNodeMap2 & newDataMap2) == 0)) {
                throw new IllegalStateException("Check failed.".toString());
            }
            if (Intrinsics.areEqual(this.ownedBy, mutator.getOwnership$runtime_release()) && this.dataMap == newDataMap2 && this.nodeMap == newNodeMap2) {
                trieNode = this;
            } else {
                Object[] newBuffer = new Object[(Integer.bitCount(newDataMap2) * 2) + Integer.bitCount(newNodeMap2)];
                trieNode = new TrieNode(newDataMap2, newNodeMap2, newBuffer);
            }
            TrieNode mutableNode = trieNode;
            int $this$forEachOneBit$iv3 = newNodeMap2;
            int mask$iv2 = $this$forEachOneBit$iv3;
            int index$iv2 = 0;
            while (mask$iv2 != 0) {
                int bit$iv2 = Integer.lowestOneBit(mask$iv2);
                int index = index$iv2;
                Object[] objArr = mutableNode.buffer;
                int newNodeIndex = (objArr.length - 1) - index;
                objArr[newNodeIndex] = mutablePutAllFromOtherNodeCell(otherNode, bit$iv2, shift, intersectionCounter, mutator);
                index$iv2++;
                mask$iv2 ^= bit$iv2;
            }
            int $this$forEachOneBit$iv4 = newDataMap2;
            int mask$iv3 = $this$forEachOneBit$iv4;
            int index$iv3 = 0;
            while (mask$iv3 != 0) {
                int bit$iv3 = Integer.lowestOneBit(mask$iv3);
                int index2 = index$iv3;
                int newKeyIndex = index2 * 2;
                if (!otherNode.hasEntryAt$runtime_release(bit$iv3)) {
                    int oldKeyIndex = entryKeyIndex$runtime_release(bit$iv3);
                    $this$forEachOneBit$iv = $this$forEachOneBit$iv4;
                    mutableNode.buffer[newKeyIndex] = keyAtIndex(oldKeyIndex);
                    mutableNode.buffer[newKeyIndex + 1] = valueAtKeyIndex(oldKeyIndex);
                    z = true;
                } else {
                    $this$forEachOneBit$iv = $this$forEachOneBit$iv4;
                    int oldKeyIndex2 = otherNode.entryKeyIndex$runtime_release(bit$iv3);
                    mutableNode.buffer[newKeyIndex] = otherNode.keyAtIndex(oldKeyIndex2);
                    mutableNode.buffer[newKeyIndex + 1] = otherNode.valueAtKeyIndex(oldKeyIndex2);
                    if (hasEntryAt$runtime_release(bit$iv3)) {
                        z = true;
                        intersectionCounter.setCount(intersectionCounter.getCount() + 1);
                    } else {
                        z = true;
                    }
                }
                index$iv3++;
                mask$iv3 ^= bit$iv3;
                $this$forEachOneBit$iv4 = $this$forEachOneBit$iv;
            }
            return elementsIdentityEquals(mutableNode) ? this : otherNode.elementsIdentityEquals(mutableNode) ? otherNode : mutableNode;
        }
    }

    public final ModificationResult<K, V> put(int keyHash, K k, V v, int shift) {
        ModificationResult put;
        int keyPositionMask = 1 << TrieNodeKt.indexSegment(keyHash, shift);
        if (hasEntryAt$runtime_release(keyPositionMask)) {
            int keyIndex = entryKeyIndex$runtime_release(keyPositionMask);
            if (Intrinsics.areEqual(k, keyAtIndex(keyIndex))) {
                if (valueAtKeyIndex(keyIndex) == v) {
                    return null;
                }
                return updateValueAtIndex(keyIndex, v).asUpdateResult();
            }
            return moveEntryToNode(keyIndex, keyPositionMask, keyHash, k, v, shift).asInsertResult();
        } else if (hasNodeAt(keyPositionMask)) {
            int nodeIndex = nodeIndex$runtime_release(keyPositionMask);
            TrieNode targetNode = nodeAtIndex$runtime_release(nodeIndex);
            if (shift == 30) {
                put = targetNode.collisionPut(k, v);
                if (put == null) {
                    return null;
                }
            } else {
                put = targetNode.put(keyHash, k, v, shift + 5);
                if (put == null) {
                    return null;
                }
            }
            ModificationResult $this$replaceNode_u24lambda_u240$iv = put;
            TrieNode node = $this$replaceNode_u24lambda_u240$iv.getNode();
            $this$replaceNode_u24lambda_u240$iv.setNode(updateNodeAtIndex(nodeIndex, keyPositionMask, node));
            return put;
        } else {
            return insertEntryAt(keyPositionMask, k, v).asInsertResult();
        }
    }

    public final TrieNode<K, V> mutablePut(int keyHash, K k, V v, int shift, PersistentHashMapBuilder<K, V> mutator) {
        TrieNode newNode;
        Intrinsics.checkNotNullParameter(mutator, "mutator");
        int keyPositionMask = 1 << TrieNodeKt.indexSegment(keyHash, shift);
        if (hasEntryAt$runtime_release(keyPositionMask)) {
            int keyIndex = entryKeyIndex$runtime_release(keyPositionMask);
            if (Intrinsics.areEqual(k, keyAtIndex(keyIndex))) {
                mutator.setOperationResult$runtime_release(valueAtKeyIndex(keyIndex));
                return valueAtKeyIndex(keyIndex) == v ? this : mutableUpdateValueAtIndex(keyIndex, v, mutator);
            }
            mutator.setSize(mutator.size() + 1);
            return mutableMoveEntryToNode(keyIndex, keyPositionMask, keyHash, k, v, shift, mutator.getOwnership$runtime_release());
        } else if (hasNodeAt(keyPositionMask)) {
            int nodeIndex = nodeIndex$runtime_release(keyPositionMask);
            TrieNode targetNode = nodeAtIndex$runtime_release(nodeIndex);
            if (shift == 30) {
                newNode = targetNode.mutableCollisionPut(k, v, mutator);
            } else {
                newNode = targetNode.mutablePut(keyHash, k, v, shift + 5, mutator);
            }
            return targetNode == newNode ? this : mutableUpdateNodeAtIndex(nodeIndex, newNode, mutator.getOwnership$runtime_release());
        } else {
            mutator.setSize(mutator.size() + 1);
            return mutableInsertEntryAt(keyPositionMask, k, v, mutator.getOwnership$runtime_release());
        }
    }

    public final TrieNode<K, V> remove(int keyHash, K k, int shift) {
        TrieNode newNode;
        int keyPositionMask = 1 << TrieNodeKt.indexSegment(keyHash, shift);
        if (hasEntryAt$runtime_release(keyPositionMask)) {
            int keyIndex = entryKeyIndex$runtime_release(keyPositionMask);
            if (Intrinsics.areEqual(k, keyAtIndex(keyIndex))) {
                return removeEntryAtIndex(keyIndex, keyPositionMask);
            }
            return this;
        } else if (hasNodeAt(keyPositionMask)) {
            int nodeIndex = nodeIndex$runtime_release(keyPositionMask);
            TrieNode targetNode = nodeAtIndex$runtime_release(nodeIndex);
            if (shift == 30) {
                newNode = targetNode.collisionRemove(k);
            } else {
                newNode = targetNode.remove(keyHash, k, shift + 5);
            }
            return replaceNode(targetNode, newNode, nodeIndex, keyPositionMask);
        } else {
            return this;
        }
    }

    private final TrieNode<K, V> replaceNode(TrieNode<K, V> trieNode, TrieNode<K, V> trieNode2, int nodeIndex, int positionMask) {
        if (trieNode2 == null) {
            return removeNodeAtIndex(nodeIndex, positionMask);
        }
        if (trieNode != trieNode2) {
            return updateNodeAtIndex(nodeIndex, positionMask, trieNode2);
        }
        return this;
    }

    public final TrieNode<K, V> mutableRemove(int keyHash, K k, int shift, PersistentHashMapBuilder<K, V> mutator) {
        TrieNode newNode;
        Intrinsics.checkNotNullParameter(mutator, "mutator");
        int keyPositionMask = 1 << TrieNodeKt.indexSegment(keyHash, shift);
        if (hasEntryAt$runtime_release(keyPositionMask)) {
            int keyIndex = entryKeyIndex$runtime_release(keyPositionMask);
            if (Intrinsics.areEqual(k, keyAtIndex(keyIndex))) {
                return mutableRemoveEntryAtIndex(keyIndex, keyPositionMask, mutator);
            }
            return this;
        } else if (hasNodeAt(keyPositionMask)) {
            int nodeIndex = nodeIndex$runtime_release(keyPositionMask);
            TrieNode targetNode = nodeAtIndex$runtime_release(nodeIndex);
            if (shift == 30) {
                newNode = targetNode.mutableCollisionRemove(k, mutator);
            } else {
                newNode = targetNode.mutableRemove(keyHash, k, shift + 5, mutator);
            }
            return mutableReplaceNode(targetNode, newNode, nodeIndex, keyPositionMask, mutator.getOwnership$runtime_release());
        } else {
            return this;
        }
    }

    private final TrieNode<K, V> mutableReplaceNode(TrieNode<K, V> trieNode, TrieNode<K, V> trieNode2, int nodeIndex, int positionMask, MutabilityOwnership owner) {
        if (trieNode2 == null) {
            return mutableRemoveNodeAtIndex(nodeIndex, positionMask, owner);
        }
        if (this.ownedBy == owner || trieNode != trieNode2) {
            return mutableUpdateNodeAtIndex(nodeIndex, trieNode2, owner);
        }
        return this;
    }

    public final TrieNode<K, V> remove(int keyHash, K k, V v, int shift) {
        TrieNode newNode;
        int keyPositionMask = 1 << TrieNodeKt.indexSegment(keyHash, shift);
        if (hasEntryAt$runtime_release(keyPositionMask)) {
            int keyIndex = entryKeyIndex$runtime_release(keyPositionMask);
            if (Intrinsics.areEqual(k, keyAtIndex(keyIndex)) && Intrinsics.areEqual(v, valueAtKeyIndex(keyIndex))) {
                return removeEntryAtIndex(keyIndex, keyPositionMask);
            }
            return this;
        } else if (hasNodeAt(keyPositionMask)) {
            int nodeIndex = nodeIndex$runtime_release(keyPositionMask);
            TrieNode targetNode = nodeAtIndex$runtime_release(nodeIndex);
            if (shift == 30) {
                newNode = targetNode.collisionRemove(k, v);
            } else {
                newNode = targetNode.remove(keyHash, k, v, shift + 5);
            }
            return replaceNode(targetNode, newNode, nodeIndex, keyPositionMask);
        } else {
            return this;
        }
    }

    public final TrieNode<K, V> mutableRemove(int keyHash, K k, V v, int shift, PersistentHashMapBuilder<K, V> mutator) {
        TrieNode newNode;
        Intrinsics.checkNotNullParameter(mutator, "mutator");
        int keyPositionMask = 1 << TrieNodeKt.indexSegment(keyHash, shift);
        if (hasEntryAt$runtime_release(keyPositionMask)) {
            int keyIndex = entryKeyIndex$runtime_release(keyPositionMask);
            if (Intrinsics.areEqual(k, keyAtIndex(keyIndex)) && Intrinsics.areEqual(v, valueAtKeyIndex(keyIndex))) {
                return mutableRemoveEntryAtIndex(keyIndex, keyPositionMask, mutator);
            }
            return this;
        } else if (hasNodeAt(keyPositionMask)) {
            int nodeIndex = nodeIndex$runtime_release(keyPositionMask);
            TrieNode targetNode = nodeAtIndex$runtime_release(nodeIndex);
            if (shift == 30) {
                newNode = targetNode.mutableCollisionRemove(k, v, mutator);
            } else {
                newNode = targetNode.mutableRemove(keyHash, k, v, shift + 5, mutator);
            }
            return mutableReplaceNode(targetNode, newNode, nodeIndex, keyPositionMask, mutator.getOwnership$runtime_release());
        } else {
            return this;
        }
    }

    public final void accept$runtime_release(Function5<? super TrieNode<K, V>, ? super Integer, ? super Integer, ? super Integer, ? super Integer, Unit> visitor) {
        Intrinsics.checkNotNullParameter(visitor, "visitor");
        accept(visitor, 0, 0);
    }

    private final void accept(Function5<? super TrieNode<K, V>, ? super Integer, ? super Integer, ? super Integer, ? super Integer, Unit> function5, int hash, int shift) {
        function5.invoke(this, Integer.valueOf(shift), Integer.valueOf(hash), Integer.valueOf(this.dataMap), Integer.valueOf(this.nodeMap));
        int nodePositions = this.nodeMap;
        while (nodePositions != 0) {
            int mask = Integer.lowestOneBit(nodePositions);
            int hashSegment = Integer.numberOfTrailingZeros(mask);
            TrieNode childNode = nodeAtIndex$runtime_release(nodeIndex$runtime_release(mask));
            childNode.accept(function5, (hashSegment << shift) + hash, shift + 5);
            nodePositions -= mask;
        }
    }

    /* compiled from: TrieNode.kt */
    @Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0001\n\u0002\b\u0003\b\u0080\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R \u0010\u0003\u001a\u000e\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00050\u0004X\u0080\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0006\u0010\u0007¨\u0006\b"}, d2 = {"Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode$Companion;", "", "()V", "EMPTY", "Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "", "getEMPTY$runtime_release", "()Landroidx/compose/runtime/external/kotlinx/collections/immutable/implementations/immutableMap/TrieNode;", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
    /* loaded from: classes.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        public final TrieNode getEMPTY$runtime_release() {
            return TrieNode.EMPTY;
        }
    }
}
