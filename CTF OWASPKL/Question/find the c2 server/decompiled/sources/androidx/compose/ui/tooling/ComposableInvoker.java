package androidx.compose.ui.tooling;

import androidx.compose.runtime.Composer;
import androidx.compose.ui.tooling.PreviewLogger;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.collections.ArraysKt;
import kotlin.collections.CollectionsKt;
import kotlin.collections.IntIterator;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt;
/* compiled from: ComposableInvoker.kt */
@Deprecated(message = "Use androidx.compose.runtime.reflect.ComposableMethodInvoker instead")
@Metadata(d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\b\bÇ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J\u0018\u0010\u0006\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u00042\u0006\u0010\b\u001a\u00020\u0004H\u0002J1\u0010\t\u001a\u00020\n2\u0010\u0010\u000b\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\r0\f2\u0010\u0010\u000e\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\r0\fH\u0002¢\u0006\u0002\u0010\u000fJ\u0010\u0010\u0010\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u0004H\u0002J=\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0016\u001a\u00020\u00172\u0016\u0010\u0018\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010\u00010\f\"\u0004\u0018\u00010\u0001H\u0007¢\u0006\u0002\u0010\u0019J(\u0010\u001a\u001a\b\u0012\u0004\u0012\u0002H\u001b0\f\"\u0006\b\u0000\u0010\u001b\u0018\u0001*\u0002H\u001b2\u0006\u0010\u001c\u001a\u00020\u0004H\u0082\b¢\u0006\u0002\u0010\u001dJ5\u0010\u001e\u001a\u00020\u001f*\u0006\u0012\u0002\b\u00030\r2\u0006\u0010\u0015\u001a\u00020\u00142\u0016\u0010\u0018\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010\u00010\f\"\u0004\u0018\u00010\u0001H\u0002¢\u0006\u0002\u0010 J9\u0010!\u001a\u00020\u001f*\u0006\u0012\u0002\b\u00030\r2\u0006\u0010\u0015\u001a\u00020\u00142\u001a\u0010\u0018\u001a\u000e\u0012\n\b\u0001\u0012\u0006\u0012\u0002\b\u00030\r0\f\"\u0006\u0012\u0002\b\u00030\rH\u0002¢\u0006\u0002\u0010\"J\u0012\u0010#\u001a\u0004\u0018\u00010\u0001*\u0006\u0012\u0002\b\u00030\rH\u0002J=\u0010$\u001a\u0004\u0018\u00010\u0001*\u00020\u001f2\b\u0010%\u001a\u0004\u0018\u00010\u00012\u0006\u0010\u0016\u001a\u00020\u00172\u0016\u0010\u0018\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010\u00010\f\"\u0004\u0018\u00010\u0001H\u0002¢\u0006\u0002\u0010&R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082T¢\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0004X\u0082T¢\u0006\u0002\n\u0000¨\u0006'"}, d2 = {"Landroidx/compose/ui/tooling/ComposableInvoker;", "", "()V", "BITS_PER_INT", "", "SLOTS_PER_INT", "changedParamCount", "realValueParams", "thisParams", "compatibleTypes", "", "methodTypes", "", "Ljava/lang/Class;", "actualTypes", "([Ljava/lang/Class;[Ljava/lang/Class;)Z", "defaultParamCount", "invokeComposable", "", "className", "", "methodName", "composer", "Landroidx/compose/runtime/Composer;", "args", "(Ljava/lang/String;Ljava/lang/String;Landroidx/compose/runtime/Composer;[Ljava/lang/Object;)V", "dup", "T", "count", "(Ljava/lang/Object;I)[Ljava/lang/Object;", "findComposableMethod", "Ljava/lang/reflect/Method;", "(Ljava/lang/Class;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/reflect/Method;", "getDeclaredCompatibleMethod", "(Ljava/lang/Class;Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", "getDefaultValue", "invokeComposableMethod", "instance", "(Ljava/lang/reflect/Method;Ljava/lang/Object;Landroidx/compose/runtime/Composer;[Ljava/lang/Object;)Ljava/lang/Object;", "ui-tooling_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ComposableInvoker {
    public static final int $stable = 0;
    private static final int BITS_PER_INT = 31;
    public static final ComposableInvoker INSTANCE = new ComposableInvoker();
    private static final int SLOTS_PER_INT = 10;

    private ComposableInvoker() {
    }

    private final boolean compatibleTypes(Class<?>[] clsArr, Class<?>[] clsArr2) {
        Iterable $this$all$iv;
        if (clsArr.length == clsArr2.length) {
            Collection destination$iv$iv = new ArrayList(clsArr.length);
            int index$iv$iv = 0;
            int length = clsArr.length;
            int i = 0;
            while (i < length) {
                destination$iv$iv.add(Boolean.valueOf(clsArr[i].isAssignableFrom(clsArr2[index$iv$iv])));
                i++;
                index$iv$iv++;
            }
            Iterable $this$all$iv2 = (List) destination$iv$iv;
            if (!($this$all$iv2 instanceof Collection) || !((Collection) $this$all$iv2).isEmpty()) {
                Iterator it = $this$all$iv2.iterator();
                while (true) {
                    if (it.hasNext()) {
                        Object element$iv = it.next();
                        boolean it2 = ((Boolean) element$iv).booleanValue();
                        if (!it2) {
                            $this$all$iv = null;
                            break;
                        }
                    } else {
                        $this$all$iv = 1;
                        break;
                    }
                }
            } else {
                $this$all$iv = 1;
            }
            return $this$all$iv != null;
        }
        return false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:8:0x004f, code lost:
        if (kotlin.text.StringsKt.startsWith$default(r12, r17 + '-', false, 2, (java.lang.Object) null) != false) goto L19;
     */
    /* JADX WARN: Removed duplicated region for block: B:16:0x006b A[LOOP:0: B:3:0x001a->B:16:0x006b, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0069 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final java.lang.reflect.Method getDeclaredCompatibleMethod(java.lang.Class<?> r16, java.lang.String r17, java.lang.Class<?>... r18) {
        /*
            r15 = this;
            r0 = r17
            r1 = r18
            int r2 = r1.length
            java.lang.Object[] r2 = java.util.Arrays.copyOf(r1, r2)
            java.lang.Class[] r2 = (java.lang.Class[]) r2
            java.lang.reflect.Method[] r3 = r16.getDeclaredMethods()
            java.lang.String r4 = "declaredMethods"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r4)
            java.lang.Object[] r3 = (java.lang.Object[]) r3
            r4 = 0
            int r5 = r3.length
            r6 = 0
            r7 = r6
        L1a:
            r8 = 0
            if (r7 >= r5) goto L6e
            r9 = r3[r7]
            r10 = r9
            java.lang.reflect.Method r10 = (java.lang.reflect.Method) r10
            r11 = 0
            java.lang.String r12 = r10.getName()
            boolean r12 = kotlin.jvm.internal.Intrinsics.areEqual(r0, r12)
            if (r12 != 0) goto L51
            java.lang.String r12 = r10.getName()
            java.lang.String r13 = "it.name"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r12, r13)
            java.lang.StringBuilder r13 = new java.lang.StringBuilder
            r13.<init>()
            java.lang.StringBuilder r13 = r13.append(r0)
            r14 = 45
            java.lang.StringBuilder r13 = r13.append(r14)
            java.lang.String r13 = r13.toString()
            r14 = 2
            boolean r8 = kotlin.text.StringsKt.startsWith$default(r12, r13, r6, r14, r8)
            if (r8 == 0) goto L65
        L51:
            androidx.compose.ui.tooling.ComposableInvoker r8 = androidx.compose.ui.tooling.ComposableInvoker.INSTANCE
            java.lang.Class[] r12 = r10.getParameterTypes()
            java.lang.String r13 = "it.parameterTypes"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r12, r13)
            boolean r8 = r8.compatibleTypes(r12, r2)
            if (r8 == 0) goto L65
            r8 = 1
            goto L66
        L65:
            r8 = r6
        L66:
            if (r8 == 0) goto L6b
            r8 = r9
            goto L6f
        L6b:
            int r7 = r7 + 1
            goto L1a
        L6e:
        L6f:
            java.lang.reflect.Method r8 = (java.lang.reflect.Method) r8
            if (r8 == 0) goto L74
            return r8
        L74:
            java.lang.NoSuchMethodException r3 = new java.lang.NoSuchMethodException
            java.lang.StringBuilder r4 = new java.lang.StringBuilder
            r4.<init>()
            java.lang.StringBuilder r4 = r4.append(r0)
            java.lang.String r5 = " not found"
            java.lang.StringBuilder r4 = r4.append(r5)
            java.lang.String r4 = r4.toString()
            r3.<init>(r4)
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.tooling.ComposableInvoker.getDeclaredCompatibleMethod(java.lang.Class, java.lang.String, java.lang.Class[]):java.lang.reflect.Method");
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final /* synthetic */ <T> T[] dup(T t, int count) {
        Iterable $this$map$iv = RangesKt.until(0, count);
        Collection destination$iv$iv = new ArrayList(CollectionsKt.collectionSizeOrDefault($this$map$iv, 10));
        Iterator<T> it = $this$map$iv.iterator();
        while (it.hasNext()) {
            ((IntIterator) it).nextInt();
            destination$iv$iv.add(t);
        }
        Collection $this$toTypedArray$iv = (List) destination$iv$iv;
        Intrinsics.reifiedOperationMarker(0, "T?");
        return (T[]) $this$toTypedArray$iv.toArray(new Object[0]);
    }

    /* JADX WARN: Removed duplicated region for block: B:40:0x0111 A[Catch: ReflectiveOperationException -> 0x011a, LOOP:2: B:26:0x00d1->B:40:0x0111, LOOP_END, TryCatch #3 {ReflectiveOperationException -> 0x011a, blocks: (B:31:0x0102, B:42:0x0116, B:40:0x0111), top: B:61:0x0102 }] */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0122  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0124  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0110 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final java.lang.reflect.Method findComposableMethod(java.lang.Class<?> r23, java.lang.String r24, java.lang.Object... r25) {
        /*
            Method dump skipped, instructions count: 325
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.tooling.ComposableInvoker.findComposableMethod(java.lang.Class, java.lang.String, java.lang.Object[]):java.lang.reflect.Method");
    }

    private final Object getDefaultValue(Class<?> cls) {
        String name = cls.getName();
        if (name != null) {
            switch (name.hashCode()) {
                case -1325958191:
                    if (name.equals("double")) {
                        return Double.valueOf(0.0d);
                    }
                    break;
                case 104431:
                    if (name.equals("int")) {
                        return 0;
                    }
                    break;
                case 3039496:
                    if (name.equals("byte")) {
                        return (byte) 0;
                    }
                    break;
                case 3052374:
                    if (name.equals("char")) {
                        return (char) 0;
                    }
                    break;
                case 3327612:
                    if (name.equals("long")) {
                        return 0L;
                    }
                    break;
                case 64711720:
                    if (name.equals("boolean")) {
                        return false;
                    }
                    break;
                case 97526364:
                    if (name.equals("float")) {
                        return Float.valueOf(0.0f);
                    }
                    break;
                case 109413500:
                    if (name.equals("short")) {
                        return (short) 0;
                    }
                    break;
            }
        }
        return null;
    }

    private final Object invokeComposableMethod(Method $this$invokeComposableMethod, Object instance, Composer composer, Object... args) {
        int defaultParams;
        int realParams;
        Object obj;
        Object[] parameterTypes = $this$invokeComposableMethod.getParameterTypes();
        Intrinsics.checkNotNullExpressionValue(parameterTypes, "parameterTypes");
        Object[] $this$indexOfLast$iv = parameterTypes;
        int i = -1;
        int length = $this$indexOfLast$iv.length - 1;
        if (length >= 0) {
            while (true) {
                int index$iv = length;
                length--;
                Class it = (Class) $this$indexOfLast$iv[index$iv];
                if (!Intrinsics.areEqual(it, Composer.class)) {
                    if (length < 0) {
                        break;
                    }
                } else {
                    i = index$iv;
                    break;
                }
            }
        }
        int composerIndex = i;
        int realParams2 = composerIndex;
        int thisParams = instance != null ? 1 : 0;
        int changedParams = changedParamCount(realParams2, thisParams);
        int totalParamsWithoutDefaults = realParams2 + 1 + changedParams;
        int totalParams = $this$invokeComposableMethod.getParameterTypes().length;
        boolean isDefault = totalParams != totalParamsWithoutDefaults;
        if (isDefault) {
            defaultParams = defaultParamCount(realParams2);
        } else {
            defaultParams = 0;
        }
        if (((realParams2 + 1) + changedParams) + defaultParams == totalParams) {
            int changedStartIndex = composerIndex + 1;
            int defaultStartIndex = changedStartIndex + changedParams;
            Object[] arguments = new Object[totalParams];
            int i2 = 0;
            while (i2 < totalParams) {
                if (!(i2 >= 0 && i2 < realParams2)) {
                    realParams = realParams2;
                    if (i2 == composerIndex) {
                        obj = composer;
                    } else {
                        if (changedStartIndex <= i2 && i2 < defaultStartIndex) {
                            obj = 0;
                        } else {
                            if (!(defaultStartIndex <= i2 && i2 < totalParams)) {
                                throw new IllegalStateException("Unexpected index".toString());
                            }
                            obj = 2097151;
                        }
                    }
                } else if (i2 < 0 || i2 > ArraysKt.getLastIndex(args)) {
                    ComposableInvoker composableInvoker = INSTANCE;
                    Class<?> cls = $this$invokeComposableMethod.getParameterTypes()[i2];
                    realParams = realParams2;
                    Intrinsics.checkNotNullExpressionValue(cls, "parameterTypes[idx]");
                    obj = composableInvoker.getDefaultValue(cls);
                } else {
                    obj = args[i2];
                    realParams = realParams2;
                }
                arguments[i2] = obj;
                i2++;
                realParams2 = realParams;
            }
            return $this$invokeComposableMethod.invoke(instance, Arrays.copyOf(arguments, arguments.length));
        }
        throw new IllegalStateException("Check failed.".toString());
    }

    private final int changedParamCount(int realValueParams, int thisParams) {
        if (realValueParams == 0) {
            return 1;
        }
        int totalParams = realValueParams + thisParams;
        return (int) Math.ceil(totalParams / 10.0d);
    }

    private final int defaultParamCount(int realValueParams) {
        return (int) Math.ceil(realValueParams / 31.0d);
    }

    public final void invokeComposable(String className, String methodName, Composer composer, Object... args) {
        Intrinsics.checkNotNullParameter(className, "className");
        Intrinsics.checkNotNullParameter(methodName, "methodName");
        Intrinsics.checkNotNullParameter(composer, "composer");
        Intrinsics.checkNotNullParameter(args, "args");
        try {
            Class composableClass = Class.forName(className);
            Intrinsics.checkNotNullExpressionValue(composableClass, "composableClass");
            Method method = findComposableMethod(composableClass, methodName, Arrays.copyOf(args, args.length));
            method.setAccessible(true);
            if (Modifier.isStatic(method.getModifiers())) {
                invokeComposableMethod(method, null, composer, Arrays.copyOf(args, args.length));
                return;
            }
            Object instance = composableClass.getConstructor(new Class[0]).newInstance(new Object[0]);
            invokeComposableMethod(method, instance, composer, Arrays.copyOf(args, args.length));
        } catch (ReflectiveOperationException e) {
            PreviewLogger.Companion.logWarning$ui_tooling_release$default(PreviewLogger.Companion, "Failed to invoke Composable Method '" + className + '.' + methodName + '\'', null, 2, null);
            throw e;
        }
    }
}
