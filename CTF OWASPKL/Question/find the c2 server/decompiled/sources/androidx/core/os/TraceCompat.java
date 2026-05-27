package androidx.core.os;

import android.os.Trace;
import java.lang.reflect.Method;
@Deprecated
/* loaded from: classes.dex */
public final class TraceCompat {
    private static final String TAG = "TraceCompat";
    private static Method sAsyncTraceBeginMethod;
    private static Method sAsyncTraceEndMethod;
    private static Method sIsTagEnabledMethod;
    private static Method sTraceCounterMethod;
    private static long sTraceTagApp;

    public static boolean isEnabled() {
        return Api29Impl.isEnabled();
    }

    public static void beginSection(String sectionName) {
        Api18Impl.beginSection(sectionName);
    }

    public static void endSection() {
        Api18Impl.endSection();
    }

    public static void beginAsyncSection(String methodName, int cookie) {
        Api29Impl.beginAsyncSection(methodName, cookie);
    }

    public static void endAsyncSection(String methodName, int cookie) {
        Api29Impl.endAsyncSection(methodName, cookie);
    }

    public static void setCounter(String counterName, int counterValue) {
        Api29Impl.setCounter(counterName, counterValue);
    }

    private TraceCompat() {
    }

    /* loaded from: classes.dex */
    static class Api29Impl {
        private Api29Impl() {
        }

        static boolean isEnabled() {
            return Trace.isEnabled();
        }

        static void endAsyncSection(String methodName, int cookie) {
            Trace.endAsyncSection(methodName, cookie);
        }

        static void beginAsyncSection(String methodName, int cookie) {
            Trace.beginAsyncSection(methodName, cookie);
        }

        static void setCounter(String counterName, long counterValue) {
            Trace.setCounter(counterName, counterValue);
        }
    }

    /* loaded from: classes.dex */
    static class Api18Impl {
        private Api18Impl() {
        }

        static void beginSection(String sectionName) {
            Trace.beginSection(sectionName);
        }

        static void endSection() {
            Trace.endSection();
        }
    }
}
