package com.example.protonx1337;

import androidx.compose.foundation.layout.SizeKt;
import androidx.compose.material3.MaterialTheme;
import androidx.compose.material3.SurfaceKt;
import androidx.compose.material3.TextKt;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.internal.ComposableLambdaKt;
import androidx.compose.ui.Modifier;
import com.example.protonx1337.ui.theme.ThemeKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
/* compiled from: MainActivity.kt */
@Metadata(k = 3, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class ComposableSingletons$MainActivityKt {
    public static final ComposableSingletons$MainActivityKt INSTANCE = new ComposableSingletons$MainActivityKt();

    /* renamed from: lambda-1  reason: not valid java name */
    public static Function2<Composer, Integer, Unit> f50lambda1 = ComposableLambdaKt.composableLambdaInstance(-649353578, false, new Function2<Composer, Integer, Unit>() { // from class: com.example.protonx1337.ComposableSingletons$MainActivityKt$lambda-1$1
        @Override // kotlin.jvm.functions.Function2
        public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
            invoke(composer, num.intValue());
            return Unit.INSTANCE;
        }

        public final void invoke(Composer $composer, int $changed) {
            ComposerKt.sourceInformation($composer, "C23@893L19:MainActivity.kt#2ypmt5");
            if (($changed & 11) == 2 && $composer.getSkipping()) {
                $composer.skipToGroupEnd();
                return;
            }
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(-649353578, $changed, -1, "com.example.protonx1337.ComposableSingletons$MainActivityKt.lambda-1.<anonymous> (MainActivity.kt:22)");
            }
            TextKt.m1640TextfLXpl1I(LiveLiterals$MainActivityKt.INSTANCE.m5413x6ea9d6d0(), null, 0L, 0L, null, null, null, 0L, null, null, 0L, 0, false, 0, null, null, $composer, 0, 0, 65534);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
        }
    });

    /* renamed from: lambda-2  reason: not valid java name */
    public static Function2<Composer, Integer, Unit> f51lambda2 = ComposableLambdaKt.composableLambdaInstance(952191057, false, new Function2<Composer, Integer, Unit>() { // from class: com.example.protonx1337.ComposableSingletons$MainActivityKt$lambda-2$1
        @Override // kotlin.jvm.functions.Function2
        public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
            invoke(composer, num.intValue());
            return Unit.INSTANCE;
        }

        public final void invoke(Composer $composer, int $changed) {
            ComposerKt.sourceInformation($composer, "C22@847L11,22@782L148:MainActivity.kt#2ypmt5");
            if (($changed & 11) != 2 || !$composer.getSkipping()) {
                if (ComposerKt.isTraceInProgress()) {
                    ComposerKt.traceEventStart(952191057, $changed, -1, "com.example.protonx1337.ComposableSingletons$MainActivityKt.lambda-2.<anonymous> (MainActivity.kt:21)");
                }
                SurfaceKt.m1565SurfaceT9BRK9s(SizeKt.fillMaxSize$default(Modifier.Companion, 0.0f, 1, null), null, MaterialTheme.INSTANCE.getColorScheme($composer, MaterialTheme.$stable).m1278getBackground0d7_KjU(), 0L, 0.0f, 0.0f, null, ComposableSingletons$MainActivityKt.INSTANCE.m5401getLambda1$app_debug(), $composer, 12582918, 122);
                if (ComposerKt.isTraceInProgress()) {
                    ComposerKt.traceEventEnd();
                    return;
                }
                return;
            }
            $composer.skipToGroupEnd();
        }
    });

    /* renamed from: lambda-3  reason: not valid java name */
    public static Function2<Composer, Integer, Unit> f52lambda3 = ComposableLambdaKt.composableLambdaInstance(1779329649, false, new Function2<Composer, Integer, Unit>() { // from class: com.example.protonx1337.ComposableSingletons$MainActivityKt$lambda-3$1
        @Override // kotlin.jvm.functions.Function2
        public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
            invoke(composer, num.intValue());
            return Unit.INSTANCE;
        }

        public final void invoke(Composer $composer, int $changed) {
            ComposerKt.sourceInformation($composer, "C21@747L197:MainActivity.kt#2ypmt5");
            if (($changed & 11) != 2 || !$composer.getSkipping()) {
                if (ComposerKt.isTraceInProgress()) {
                    ComposerKt.traceEventStart(1779329649, $changed, -1, "com.example.protonx1337.ComposableSingletons$MainActivityKt.lambda-3.<anonymous> (MainActivity.kt:20)");
                }
                ThemeKt.ProtonX1337Theme(false, false, ComposableSingletons$MainActivityKt.INSTANCE.m5402getLambda2$app_debug(), $composer, 384, 3);
                if (ComposerKt.isTraceInProgress()) {
                    ComposerKt.traceEventEnd();
                    return;
                }
                return;
            }
            $composer.skipToGroupEnd();
        }
    });

    /* renamed from: getLambda-1$app_debug  reason: not valid java name */
    public final Function2<Composer, Integer, Unit> m5401getLambda1$app_debug() {
        return f50lambda1;
    }

    /* renamed from: getLambda-2$app_debug  reason: not valid java name */
    public final Function2<Composer, Integer, Unit> m5402getLambda2$app_debug() {
        return f51lambda2;
    }

    /* renamed from: getLambda-3$app_debug  reason: not valid java name */
    public final Function2<Composer, Integer, Unit> m5403getLambda3$app_debug() {
        return f52lambda3;
    }
}
