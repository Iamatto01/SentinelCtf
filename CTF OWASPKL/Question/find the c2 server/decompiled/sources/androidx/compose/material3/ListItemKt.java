package androidx.compose.material3;

import androidx.compose.foundation.layout.Arrangement;
import androidx.compose.foundation.layout.BoxKt;
import androidx.compose.foundation.layout.BoxScopeInstance;
import androidx.compose.foundation.layout.ColumnKt;
import androidx.compose.foundation.layout.ColumnScopeInstance;
import androidx.compose.foundation.layout.PaddingKt;
import androidx.compose.foundation.layout.RowScope;
import androidx.compose.material3.tokens.ListTokens;
import androidx.compose.material3.tokens.TypographyKeyTokens;
import androidx.compose.runtime.Applier;
import androidx.compose.runtime.ComposablesKt;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.CompositionLocalKt;
import androidx.compose.runtime.ProvidedValue;
import androidx.compose.runtime.ScopeUpdateScope;
import androidx.compose.runtime.SkippableUpdater;
import androidx.compose.runtime.Updater;
import androidx.compose.runtime.internal.ComposableLambda;
import androidx.compose.runtime.internal.ComposableLambdaKt;
import androidx.compose.ui.Alignment;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.graphics.Color;
import androidx.compose.ui.layout.LayoutKt;
import androidx.compose.ui.layout.MeasurePolicy;
import androidx.compose.ui.node.ComposeUiNode;
import androidx.compose.ui.platform.CompositionLocalsKt;
import androidx.compose.ui.platform.ViewConfiguration;
import androidx.compose.ui.text.TextStyle;
import androidx.compose.ui.unit.Density;
import androidx.compose.ui.unit.Dp;
import androidx.compose.ui.unit.LayoutDirection;
import androidx.core.app.FrameMetricsAggregator;
import androidx.profileinstaller.ProfileVerifier;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: ListItem.kt */
@Metadata(d1 = {"\u0000^\n\u0000\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0004\u001a¬\u0001\u0010\n\u001a\u00020\u000b2\u0011\u0010\f\u001a\r\u0012\u0004\u0012\u00020\u000b0\r¢\u0006\u0002\b\u000e2\b\b\u0002\u0010\u000f\u001a\u00020\u00102\u0015\b\u0002\u0010\u0011\u001a\u000f\u0012\u0004\u0012\u00020\u000b\u0018\u00010\r¢\u0006\u0002\b\u000e2\u0015\b\u0002\u0010\u0012\u001a\u000f\u0012\u0004\u0012\u00020\u000b\u0018\u00010\r¢\u0006\u0002\b\u000e2\u0015\b\u0002\u0010\u0013\u001a\u000f\u0012\u0004\u0012\u00020\u000b\u0018\u00010\r¢\u0006\u0002\b\u000e2\u0015\b\u0002\u0010\u0014\u001a\u000f\u0012\u0004\u0012\u00020\u000b\u0018\u00010\r¢\u0006\u0002\b\u000e2\b\b\u0002\u0010\u0015\u001a\u00020\u00162\b\b\u0002\u0010\u0017\u001a\u00020\u00012\b\b\u0002\u0010\u0018\u001a\u00020\u0001H\u0007ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\u0019\u0010\u001a\u001a\u007f\u0010\n\u001a\u00020\u000b2\b\b\u0002\u0010\u000f\u001a\u00020\u00102\b\b\u0002\u0010\u001b\u001a\u00020\u001c2\b\b\u0002\u0010\u001d\u001a\u00020\u001e2\b\b\u0002\u0010\u001f\u001a\u00020\u001e2\b\b\u0002\u0010\u0017\u001a\u00020\u00012\b\b\u0002\u0010\u0018\u001a\u00020\u00012\u0006\u0010 \u001a\u00020\u00012\u0006\u0010!\u001a\u00020\"2\u001c\u0010#\u001a\u0018\u0012\u0004\u0012\u00020%\u0012\u0004\u0012\u00020\u000b0$¢\u0006\u0002\b\u000e¢\u0006\u0002\b&H\u0003ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b'\u0010(\u001a8\u0010)\u001a\u00020\u000b2\u0006\u0010*\u001a\u00020\u001e2\u0006\u0010+\u001a\u00020,2\u0011\u0010#\u001a\r\u0012\u0004\u0012\u00020\u000b0\r¢\u0006\u0002\b\u000eH\u0003ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b-\u0010.\u001aN\u0010\u0013\u001a\u0018\u0012\u0004\u0012\u00020%\u0012\u0004\u0012\u00020\u000b0$¢\u0006\u0002\b\u000e¢\u0006\u0002\b&2\u0011\u0010\u0013\u001a\r\u0012\u0004\u0012\u00020\u000b0\r¢\u0006\u0002\b\u000e2\u0006\u0010\u001f\u001a\u00020\u001e2\u0006\u0010/\u001a\u000200H\u0003ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b1\u00102\u001aN\u0010\u0014\u001a\u0018\u0012\u0004\u0012\u00020%\u0012\u0004\u0012\u00020\u000b0$¢\u0006\u0002\b\u000e¢\u0006\u0002\b&2\u0011\u0010\u0014\u001a\r\u0012\u0004\u0012\u00020\u000b0\r¢\u0006\u0002\b\u000e2\u0006\u0010\u001f\u001a\u00020\u001e2\u0006\u0010/\u001a\u000200H\u0003ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b3\u00102\"\u0013\u0010\u0000\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\"\u0013\u0010\u0003\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\"\u0013\u0010\u0004\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\"\u0013\u0010\u0005\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\"\u0013\u0010\u0006\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\"\u0013\u0010\u0007\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\"\u0013\u0010\b\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\"\u0013\u0010\t\u001a\u00020\u0001X\u0082\u0004ø\u0001\u0000¢\u0006\u0004\n\u0002\u0010\u0002\u0082\u0002\u000b\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001¨\u00064"}, d2 = {"ContentEndPadding", "Landroidx/compose/ui/unit/Dp;", "F", "LeadingContentEndPadding", "ListItemHorizontalPadding", "ListItemThreeLineVerticalPadding", "ListItemVerticalPadding", "ThreeLineListItemContainerHeight", "TrailingHorizontalPadding", "TwoLineListItemContainerHeight", "ListItem", "", "headlineText", "Lkotlin/Function0;", "Landroidx/compose/runtime/Composable;", "modifier", "Landroidx/compose/ui/Modifier;", "overlineText", "supportingText", "leadingContent", "trailingContent", "colors", "Landroidx/compose/material3/ListItemColors;", "tonalElevation", "shadowElevation", "ListItem-HXNGIdc", "(Lkotlin/jvm/functions/Function2;Landroidx/compose/ui/Modifier;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Lkotlin/jvm/functions/Function2;Landroidx/compose/material3/ListItemColors;FFLandroidx/compose/runtime/Composer;II)V", "shape", "Landroidx/compose/ui/graphics/Shape;", "containerColor", "Landroidx/compose/ui/graphics/Color;", "contentColor", "minHeight", "paddingValues", "Landroidx/compose/foundation/layout/PaddingValues;", "content", "Lkotlin/Function1;", "Landroidx/compose/foundation/layout/RowScope;", "Lkotlin/ExtensionFunctionType;", "ListItem-xOgov6c", "(Landroidx/compose/ui/Modifier;Landroidx/compose/ui/graphics/Shape;JJFFFLandroidx/compose/foundation/layout/PaddingValues;Lkotlin/jvm/functions/Function3;Landroidx/compose/runtime/Composer;II)V", "ProvideTextStyleFromToken", "color", "textToken", "Landroidx/compose/material3/tokens/TypographyKeyTokens;", "ProvideTextStyleFromToken-3J-VO9M", "(JLandroidx/compose/material3/tokens/TypographyKeyTokens;Lkotlin/jvm/functions/Function2;Landroidx/compose/runtime/Composer;I)V", "topAlign", "", "leadingContent-iJQMabo", "(Lkotlin/jvm/functions/Function2;JZLandroidx/compose/runtime/Composer;I)Lkotlin/jvm/functions/Function3;", "trailingContent-iJQMabo", "material3_release"}, k = 2, mv = {1, 7, 1}, xi = 48)
/* loaded from: classes.dex */
public final class ListItemKt {
    private static final float TwoLineListItemContainerHeight = Dp.m5122constructorimpl(72);
    private static final float ThreeLineListItemContainerHeight = Dp.m5122constructorimpl(88);
    private static final float ListItemVerticalPadding = Dp.m5122constructorimpl(8);
    private static final float ListItemThreeLineVerticalPadding = Dp.m5122constructorimpl(16);
    private static final float ListItemHorizontalPadding = Dp.m5122constructorimpl(16);
    private static final float LeadingContentEndPadding = Dp.m5122constructorimpl(16);
    private static final float ContentEndPadding = Dp.m5122constructorimpl(8);
    private static final float TrailingHorizontalPadding = Dp.m5122constructorimpl(8);

    @ExperimentalMaterial3Api
    /* renamed from: ListItem-HXNGIdc  reason: not valid java name */
    public static final void m1448ListItemHXNGIdc(final Function2<? super Composer, ? super Integer, Unit> headlineText, Modifier modifier, Function2<? super Composer, ? super Integer, Unit> function2, Function2<? super Composer, ? super Integer, Unit> function22, Function2<? super Composer, ? super Integer, Unit> function23, Function2<? super Composer, ? super Integer, Unit> function24, ListItemColors colors, float tonalElevation, float shadowElevation, Composer $composer, final int $changed, final int i) {
        Function2 function25;
        Function2 function26;
        Modifier.Companion modifier2;
        Function2 overlineText;
        Function2 supportingText;
        Function2 leadingContent;
        Function2 trailingContent;
        ListItemColors colors2;
        float tonalElevation2;
        float shadowElevation2;
        float tonalElevation3;
        Modifier modifier3;
        float shadowElevation3;
        Function2 overlineText2;
        Function2 supportingText2;
        Function2 leadingContent2;
        Function2 trailingContent2;
        ListItemColors colors3;
        int i2;
        Intrinsics.checkNotNullParameter(headlineText, "headlineText");
        Composer $composer2 = $composer.startRestartGroup(-1647707763);
        ComposerKt.sourceInformation($composer2, "C(ListItem)P(1,3,4,6,2,8!1,7:c#ui.unit.Dp,5:c#ui.unit.Dp)78@3522L8:ListItem.kt#uh7d8r");
        int $dirty = $changed;
        if ((i & 1) != 0) {
            $dirty |= 6;
        } else if (($changed & 14) == 0) {
            $dirty |= $composer2.changed(headlineText) ? 4 : 2;
        }
        int i3 = i & 2;
        if (i3 != 0) {
            $dirty |= 48;
        } else if (($changed & 112) == 0) {
            $dirty |= $composer2.changed(modifier) ? 32 : 16;
        }
        int i4 = i & 4;
        if (i4 != 0) {
            $dirty |= 384;
        } else if (($changed & 896) == 0) {
            $dirty |= $composer2.changed(function2) ? 256 : 128;
        }
        int i5 = i & 8;
        if (i5 != 0) {
            $dirty |= 3072;
        } else if (($changed & 7168) == 0) {
            $dirty |= $composer2.changed(function22) ? 2048 : 1024;
        }
        int i6 = i & 16;
        if (i6 != 0) {
            $dirty |= 24576;
            function25 = function23;
        } else if (($changed & 57344) == 0) {
            function25 = function23;
            $dirty |= $composer2.changed(function25) ? 16384 : 8192;
        } else {
            function25 = function23;
        }
        int i7 = i & 32;
        if (i7 != 0) {
            $dirty |= ProfileVerifier.CompilationStatus.RESULT_CODE_ERROR_CANT_WRITE_PROFILE_VERIFICATION_RESULT_CACHE_FILE;
            function26 = function24;
        } else if (($changed & 458752) == 0) {
            function26 = function24;
            $dirty |= $composer2.changed(function26) ? 131072 : 65536;
        } else {
            function26 = function24;
        }
        if (($changed & 3670016) == 0) {
            if ((i & 64) == 0 && $composer2.changed(colors)) {
                i2 = 1048576;
                $dirty |= i2;
            }
            i2 = 524288;
            $dirty |= i2;
        }
        int i8 = i & 128;
        if (i8 != 0) {
            $dirty |= 12582912;
        } else if (($changed & 29360128) == 0) {
            $dirty |= $composer2.changed(tonalElevation) ? 8388608 : 4194304;
        }
        int i9 = i & 256;
        if (i9 != 0) {
            $dirty |= 100663296;
        } else if (($changed & 234881024) == 0) {
            $dirty |= $composer2.changed(shadowElevation) ? 67108864 : 33554432;
        }
        if (($dirty & 191739611) == 38347922 && $composer2.getSkipping()) {
            $composer2.skipToGroupEnd();
            overlineText2 = function2;
            supportingText2 = function22;
            colors3 = colors;
            tonalElevation3 = tonalElevation;
            shadowElevation3 = shadowElevation;
            trailingContent2 = function26;
            leadingContent2 = function25;
            modifier3 = modifier;
        } else {
            $composer2.startDefaults();
            if (($changed & 1) == 0 || $composer2.getDefaultsInvalid()) {
                modifier2 = i3 != 0 ? Modifier.Companion : modifier;
                overlineText = i4 != 0 ? null : function2;
                supportingText = i5 != 0 ? null : function22;
                leadingContent = i6 != 0 ? null : function25;
                trailingContent = i7 != 0 ? null : function26;
                if ((i & 64) != 0) {
                    colors2 = ListItemDefaults.INSTANCE.m1446colorsJ08w3E(0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, $composer2, 805306368, FrameMetricsAggregator.EVERY_DURATION);
                    $dirty &= -3670017;
                } else {
                    colors2 = colors;
                }
                tonalElevation2 = i8 != 0 ? ListItemDefaults.INSTANCE.m1447getElevationD9Ej5fM() : tonalElevation;
                shadowElevation2 = i9 != 0 ? ListItemDefaults.INSTANCE.m1447getElevationD9Ej5fM() : shadowElevation;
            } else {
                $composer2.skipToGroupEnd();
                if ((i & 64) != 0) {
                    modifier2 = modifier;
                    overlineText = function2;
                    supportingText = function22;
                    shadowElevation2 = shadowElevation;
                    $dirty &= -3670017;
                    trailingContent = function26;
                    leadingContent = function25;
                    colors2 = colors;
                    tonalElevation2 = tonalElevation;
                } else {
                    modifier2 = modifier;
                    overlineText = function2;
                    supportingText = function22;
                    tonalElevation2 = tonalElevation;
                    shadowElevation2 = shadowElevation;
                    trailingContent = function26;
                    leadingContent = function25;
                    colors2 = colors;
                }
            }
            $composer2.endDefaults();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(-1647707763, $dirty, -1, "androidx.compose.material3.ListItem (ListItem.kt:71)");
            }
            if (overlineText == null && supportingText == null) {
                $composer2.startReplaceableGroup(-85614273);
                ComposerKt.sourceInformation($composer2, "86@3818L16,87@3876L29,84@3739L1377");
                final Function2 function27 = leadingContent;
                final ListItemColors listItemColors = colors2;
                final int i10 = $dirty;
                final Function2 function28 = trailingContent;
                m1449ListItemxOgov6c(modifier2, null, colors2.containerColor$material3_release($composer2, ($dirty >> 18) & 14).getValue().m2616unboximpl(), colors2.headlineColor$material3_release(true, $composer2, (($dirty >> 15) & 112) | 6).getValue().m2616unboximpl(), tonalElevation2, shadowElevation2, ListTokens.INSTANCE.m1964getListItemContainerHeightD9Ej5fM(), PaddingKt.m408PaddingValuesYgX7TsA(ListItemHorizontalPadding, ListItemVerticalPadding), ComposableLambdaKt.composableLambda($composer2, 967218806, true, new Function3<RowScope, Composer, Integer, Unit>() { // from class: androidx.compose.material3.ListItemKt$ListItem$1
                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    /* JADX WARN: Multi-variable type inference failed */
                    {
                        super(3);
                    }

                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Unit invoke(RowScope rowScope, Composer composer, Integer num) {
                        invoke(rowScope, composer, num.intValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(RowScope ListItem, Composer $composer3, int $changed2) {
                        Composer $composer$iv;
                        Function3 m1456trailingContentiJQMabo;
                        Function3 m1455leadingContentiJQMabo;
                        Intrinsics.checkNotNullParameter(ListItem, "$this$ListItem");
                        ComposerKt.sourceInformation($composer3, "C100@4463L358,114@4995L33,112@4881L209,112@4881L211:ListItem.kt#uh7d8r");
                        int $dirty2 = $changed2;
                        if (($changed2 & 14) == 0) {
                            $dirty2 |= $composer3.changed(ListItem) ? 4 : 2;
                        }
                        int $dirty3 = $dirty2;
                        if (($dirty3 & 91) != 18 || !$composer3.getSkipping()) {
                            if (ComposerKt.isTraceInProgress()) {
                                ComposerKt.traceEventStart(967218806, $dirty3, -1, "androidx.compose.material3.ListItem.<anonymous> (ListItem.kt:92)");
                            }
                            $composer3.startReplaceableGroup(1316672324);
                            ComposerKt.sourceInformation($composer3, "96@4340L32,94@4229L205,94@4229L207");
                            Function2<Composer, Integer, Unit> function29 = function27;
                            if (function29 != null) {
                                m1455leadingContentiJQMabo = ListItemKt.m1455leadingContentiJQMabo(function29, listItemColors.leadingIconColor$material3_release(true, $composer3, ((i10 >> 15) & 112) | 6).getValue().m2616unboximpl(), false, $composer3, ((i10 >> 12) & 14) | 384);
                                m1455leadingContentiJQMabo.invoke(ListItem, $composer3, Integer.valueOf($dirty3 & 14));
                            }
                            $composer3.endReplaceableGroup();
                            Modifier modifier$iv = ListItem.align(RowScope.weight$default(ListItem, Modifier.Companion, 1.0f, false, 2, null), Alignment.Companion.getCenterVertically());
                            ListItemColors listItemColors2 = listItemColors;
                            int i11 = i10;
                            Function2<Composer, Integer, Unit> function210 = headlineText;
                            $composer3.startReplaceableGroup(733328855);
                            ComposerKt.sourceInformation($composer3, "C(Box)P(2,1,3)70@3267L67,71@3339L130:Box.kt#2w3rfo");
                            Alignment contentAlignment$iv = Alignment.Companion.getTopStart();
                            MeasurePolicy measurePolicy$iv = BoxKt.rememberBoxMeasurePolicy(contentAlignment$iv, false, $composer3, ((0 >> 3) & 14) | ((0 >> 3) & 112));
                            int $changed$iv$iv = (0 << 3) & 112;
                            $composer3.startReplaceableGroup(-1323940314);
                            ComposerKt.sourceInformation($composer3, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                            Object consume = $composer3.consume(CompositionLocalsKt.getLocalDensity());
                            ComposerKt.sourceInformationMarkerEnd($composer3);
                            Density density$iv$iv = (Density) consume;
                            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                            Object consume2 = $composer3.consume(CompositionLocalsKt.getLocalLayoutDirection());
                            ComposerKt.sourceInformationMarkerEnd($composer3);
                            LayoutDirection layoutDirection$iv$iv = (LayoutDirection) consume2;
                            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                            Object consume3 = $composer3.consume(CompositionLocalsKt.getLocalViewConfiguration());
                            ComposerKt.sourceInformationMarkerEnd($composer3);
                            ViewConfiguration viewConfiguration$iv$iv = (ViewConfiguration) consume3;
                            Function0 factory$iv$iv$iv = ComposeUiNode.Companion.getConstructor();
                            Function3 skippableUpdate$iv$iv$iv = LayoutKt.materializerOf(modifier$iv);
                            int $changed$iv$iv$iv = (($changed$iv$iv << 9) & 7168) | 6;
                            if (!($composer3.getApplier() instanceof Applier)) {
                                ComposablesKt.invalidApplier();
                            }
                            $composer3.startReusableNode();
                            if ($composer3.getInserting()) {
                                $composer3.createNode(factory$iv$iv$iv);
                            } else {
                                $composer3.useNode();
                            }
                            $composer3.disableReusing();
                            Composer $this$Layout_u24lambda_u2d0$iv$iv = Updater.m2247constructorimpl($composer3);
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, measurePolicy$iv, ComposeUiNode.Companion.getSetMeasurePolicy());
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, density$iv$iv, ComposeUiNode.Companion.getSetDensity());
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, layoutDirection$iv$iv, ComposeUiNode.Companion.getSetLayoutDirection());
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, viewConfiguration$iv$iv, ComposeUiNode.Companion.getSetViewConfiguration());
                            $composer3.enableReusing();
                            skippableUpdate$iv$iv$iv.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer3)), $composer3, Integer.valueOf(($changed$iv$iv$iv >> 3) & 112));
                            $composer3.startReplaceableGroup(2058660585);
                            int $changed$iv = ($changed$iv$iv$iv >> 9) & 14;
                            $composer3.startReplaceableGroup(-2137368960);
                            ComposerKt.sourceInformation($composer3, "C72@3384L9:Box.kt#2w3rfo");
                            if (($changed$iv & 11) == 2 && $composer3.getSkipping()) {
                                $composer3.skipToGroupEnd();
                                $composer$iv = $composer3;
                            } else {
                                BoxScopeInstance boxScopeInstance = BoxScopeInstance.INSTANCE;
                                $composer3.startReplaceableGroup(181297456);
                                ComposerKt.sourceInformation($composer3, "C106@4666L29,105@4612L195:ListItem.kt#uh7d8r");
                                if (((((0 >> 6) & 112) | 6) & 81) != 16 || !$composer3.getSkipping()) {
                                    $composer$iv = $composer3;
                                    ListItemKt.m1450ProvideTextStyleFromToken3JVO9M(listItemColors2.headlineColor$material3_release(true, $composer3, ((i11 >> 15) & 112) | 6).getValue().m2616unboximpl(), ListTokens.INSTANCE.getListItemLabelTextFont(), function210, $composer3, ((i11 << 6) & 896) | 48);
                                } else {
                                    $composer3.skipToGroupEnd();
                                    $composer$iv = $composer3;
                                }
                                $composer3.endReplaceableGroup();
                            }
                            $composer$iv.endReplaceableGroup();
                            $composer3.endReplaceableGroup();
                            $composer3.endNode();
                            $composer3.endReplaceableGroup();
                            $composer3.endReplaceableGroup();
                            Function2<Composer, Integer, Unit> function211 = function28;
                            if (function211 != null) {
                                m1456trailingContentiJQMabo = ListItemKt.m1456trailingContentiJQMabo(function211, listItemColors.trailingIconColor$material3_release(true, $composer3, ((i10 >> 15) & 112) | 6).getValue().m2616unboximpl(), false, $composer3, ((i10 >> 15) & 14) | 384);
                                m1456trailingContentiJQMabo.invoke(ListItem, $composer3, Integer.valueOf($dirty3 & 14));
                            }
                            if (ComposerKt.isTraceInProgress()) {
                                ComposerKt.traceEventEnd();
                                return;
                            }
                            return;
                        }
                        $composer3.skipToGroupEnd();
                    }
                }), $composer2, (($dirty >> 3) & 14) | 114819072 | (($dirty >> 9) & 57344) | (($dirty >> 9) & 458752), 2);
                $composer2.endReplaceableGroup();
            } else if (overlineText == null) {
                $composer2.startReplaceableGroup(-85612818);
                ComposerKt.sourceInformation($composer2, "123@5273L16,124@5331L29,121@5194L1665");
                final Function2 function29 = leadingContent;
                final ListItemColors listItemColors2 = colors2;
                final int i11 = $dirty;
                final Function2 function210 = trailingContent;
                final Function2 function211 = supportingText;
                m1449ListItemxOgov6c(modifier2, null, colors2.containerColor$material3_release($composer2, ($dirty >> 18) & 14).getValue().m2616unboximpl(), colors2.headlineColor$material3_release(true, $composer2, (($dirty >> 15) & 112) | 6).getValue().m2616unboximpl(), tonalElevation2, shadowElevation2, TwoLineListItemContainerHeight, PaddingKt.m408PaddingValuesYgX7TsA(ListItemHorizontalPadding, ListItemVerticalPadding), ComposableLambdaKt.composableLambda($composer2, 48069791, true, new Function3<RowScope, Composer, Integer, Unit>() { // from class: androidx.compose.material3.ListItemKt$ListItem$2
                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    /* JADX WARN: Multi-variable type inference failed */
                    {
                        super(3);
                    }

                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Unit invoke(RowScope rowScope, Composer composer, Integer num) {
                        invoke(rowScope, composer, num.intValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(RowScope ListItem, Composer $composer3, int $changed2) {
                        Composer $composer$iv;
                        Composer $composer$iv2;
                        Composer $composer4;
                        Function3 m1456trailingContentiJQMabo;
                        Function3 m1455leadingContentiJQMabo;
                        Intrinsics.checkNotNullParameter(ListItem, "$this$ListItem");
                        ComposerKt.sourceInformation($composer3, "C137@5914L650,158@6738L33,156@6624L209,156@6624L211:ListItem.kt#uh7d8r");
                        int $dirty2 = $changed2;
                        if (($changed2 & 14) == 0) {
                            $dirty2 |= $composer3.changed(ListItem) ? 4 : 2;
                        }
                        int $dirty3 = $dirty2;
                        if (($dirty3 & 91) != 18 || !$composer3.getSkipping()) {
                            if (ComposerKt.isTraceInProgress()) {
                                ComposerKt.traceEventStart(48069791, $dirty3, -1, "androidx.compose.material3.ListItem.<anonymous> (ListItem.kt:129)");
                            }
                            $composer3.startReplaceableGroup(1316673775);
                            ComposerKt.sourceInformation($composer3, "133@5791L32,131@5680L205,131@5680L207");
                            Function2<Composer, Integer, Unit> function212 = function29;
                            if (function212 != null) {
                                m1455leadingContentiJQMabo = ListItemKt.m1455leadingContentiJQMabo(function212, listItemColors2.leadingIconColor$material3_release(true, $composer3, ((i11 >> 15) & 112) | 6).getValue().m2616unboximpl(), false, $composer3, ((i11 >> 12) & 14) | 384);
                                m1455leadingContentiJQMabo.invoke(ListItem, $composer3, Integer.valueOf($dirty3 & 14));
                            }
                            $composer3.endReplaceableGroup();
                            Modifier modifier$iv = ListItem.align(RowScope.weight$default(ListItem, Modifier.Companion, 1.0f, false, 2, null), Alignment.Companion.getCenterVertically());
                            ListItemColors listItemColors3 = listItemColors2;
                            int i12 = i11;
                            Function2<Composer, Integer, Unit> function213 = headlineText;
                            Function2<Composer, Integer, Unit> function214 = function211;
                            $composer3.startReplaceableGroup(733328855);
                            ComposerKt.sourceInformation($composer3, "C(Box)P(2,1,3)70@3267L67,71@3339L130:Box.kt#2w3rfo");
                            Alignment contentAlignment$iv = Alignment.Companion.getTopStart();
                            MeasurePolicy measurePolicy$iv = BoxKt.rememberBoxMeasurePolicy(contentAlignment$iv, false, $composer3, ((0 >> 3) & 14) | ((0 >> 3) & 112));
                            int $changed$iv$iv = (0 << 3) & 112;
                            $composer3.startReplaceableGroup(-1323940314);
                            ComposerKt.sourceInformation($composer3, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                            Object consume = $composer3.consume(CompositionLocalsKt.getLocalDensity());
                            ComposerKt.sourceInformationMarkerEnd($composer3);
                            Density density$iv$iv = (Density) consume;
                            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                            Object consume2 = $composer3.consume(CompositionLocalsKt.getLocalLayoutDirection());
                            ComposerKt.sourceInformationMarkerEnd($composer3);
                            LayoutDirection layoutDirection$iv$iv = (LayoutDirection) consume2;
                            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                            Object consume3 = $composer3.consume(CompositionLocalsKt.getLocalViewConfiguration());
                            ComposerKt.sourceInformationMarkerEnd($composer3);
                            ViewConfiguration viewConfiguration$iv$iv = (ViewConfiguration) consume3;
                            Function0 factory$iv$iv$iv = ComposeUiNode.Companion.getConstructor();
                            Function3 skippableUpdate$iv$iv$iv = LayoutKt.materializerOf(modifier$iv);
                            int $changed$iv$iv$iv = (($changed$iv$iv << 9) & 7168) | 6;
                            if (!($composer3.getApplier() instanceof Applier)) {
                                ComposablesKt.invalidApplier();
                            }
                            $composer3.startReusableNode();
                            if ($composer3.getInserting()) {
                                $composer3.createNode(factory$iv$iv$iv);
                            } else {
                                $composer3.useNode();
                            }
                            $composer3.disableReusing();
                            Composer $this$Layout_u24lambda_u2d0$iv$iv = Updater.m2247constructorimpl($composer3);
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, measurePolicy$iv, ComposeUiNode.Companion.getSetMeasurePolicy());
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, density$iv$iv, ComposeUiNode.Companion.getSetDensity());
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, layoutDirection$iv$iv, ComposeUiNode.Companion.getSetLayoutDirection());
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, viewConfiguration$iv$iv, ComposeUiNode.Companion.getSetViewConfiguration());
                            $composer3.enableReusing();
                            skippableUpdate$iv$iv$iv.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer3)), $composer3, Integer.valueOf(($changed$iv$iv$iv >> 3) & 112));
                            $composer3.startReplaceableGroup(2058660585);
                            int $changed$iv = ($changed$iv$iv$iv >> 9) & 14;
                            $composer3.startReplaceableGroup(-2137368960);
                            ComposerKt.sourceInformation($composer3, "C72@3384L9:Box.kt#2w3rfo");
                            if (($changed$iv & 11) == 2 && $composer3.getSkipping()) {
                                $composer3.skipToGroupEnd();
                                $composer$iv2 = $composer3;
                            } else {
                                BoxScopeInstance boxScopeInstance = BoxScopeInstance.INSTANCE;
                                $composer3.startReplaceableGroup(691896537);
                                ComposerKt.sourceInformation($composer3, "C142@6063L487:ListItem.kt#uh7d8r");
                                if (((((0 >> 6) & 112) | 6) & 81) == 16 && $composer3.getSkipping()) {
                                    $composer3.skipToGroupEnd();
                                    $composer$iv2 = $composer3;
                                } else {
                                    $composer3.startReplaceableGroup(-483455358);
                                    ComposerKt.sourceInformation($composer3, "C(Column)P(2,3,1)77@3880L61,78@3946L133:Column.kt#2w3rfo");
                                    Modifier modifier$iv2 = Modifier.Companion;
                                    Arrangement.Vertical verticalArrangement$iv = Arrangement.INSTANCE.getTop();
                                    Alignment.Horizontal horizontalAlignment$iv = Alignment.Companion.getStart();
                                    MeasurePolicy measurePolicy$iv2 = ColumnKt.columnMeasurePolicy(verticalArrangement$iv, horizontalAlignment$iv, $composer3, ((0 >> 3) & 14) | ((0 >> 3) & 112));
                                    int $changed$iv$iv2 = (0 << 3) & 112;
                                    $composer3.startReplaceableGroup(-1323940314);
                                    ComposerKt.sourceInformation($composer3, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume4 = $composer3.consume(CompositionLocalsKt.getLocalDensity());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    Density density$iv$iv2 = (Density) consume4;
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume5 = $composer3.consume(CompositionLocalsKt.getLocalLayoutDirection());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    LayoutDirection layoutDirection$iv$iv2 = (LayoutDirection) consume5;
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume6 = $composer3.consume(CompositionLocalsKt.getLocalViewConfiguration());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    ViewConfiguration viewConfiguration$iv$iv2 = (ViewConfiguration) consume6;
                                    Function0 factory$iv$iv$iv2 = ComposeUiNode.Companion.getConstructor();
                                    Function3 skippableUpdate$iv$iv$iv2 = LayoutKt.materializerOf(modifier$iv2);
                                    int $changed$iv$iv$iv2 = (($changed$iv$iv2 << 9) & 7168) | 6;
                                    if (!($composer3.getApplier() instanceof Applier)) {
                                        ComposablesKt.invalidApplier();
                                    }
                                    $composer3.startReusableNode();
                                    if ($composer3.getInserting()) {
                                        $composer3.createNode(factory$iv$iv$iv2);
                                    } else {
                                        $composer3.useNode();
                                    }
                                    $composer3.disableReusing();
                                    Composer $this$Layout_u24lambda_u2d0$iv$iv2 = Updater.m2247constructorimpl($composer3);
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, measurePolicy$iv2, ComposeUiNode.Companion.getSetMeasurePolicy());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, density$iv$iv2, ComposeUiNode.Companion.getSetDensity());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, layoutDirection$iv$iv2, ComposeUiNode.Companion.getSetLayoutDirection());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, viewConfiguration$iv$iv2, ComposeUiNode.Companion.getSetViewConfiguration());
                                    $composer3.enableReusing();
                                    skippableUpdate$iv$iv$iv2.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer3)), $composer3, Integer.valueOf(($changed$iv$iv$iv2 >> 3) & 112));
                                    $composer3.startReplaceableGroup(2058660585);
                                    int $changed$iv2 = ($changed$iv$iv$iv2 >> 9) & 14;
                                    $composer3.startReplaceableGroup(-1163856341);
                                    ComposerKt.sourceInformation($composer3, "C79@3994L9:Column.kt#2w3rfo");
                                    if (($changed$iv2 & 11) == 2 && $composer3.getSkipping()) {
                                        $composer3.skipToGroupEnd();
                                        $composer$iv = $composer3;
                                        $composer$iv2 = $composer3;
                                    } else {
                                        ColumnScopeInstance columnScopeInstance = ColumnScopeInstance.INSTANCE;
                                        $composer3.startReplaceableGroup(-1123604189);
                                        ComposerKt.sourceInformation($composer3, "C144@6150L29,143@6092L211,149@6382L17,148@6324L208:ListItem.kt#uh7d8r");
                                        if (((((0 >> 6) & 112) | 6) & 81) == 16 && $composer3.getSkipping()) {
                                            $composer3.skipToGroupEnd();
                                            $composer4 = $composer3;
                                            $composer$iv = $composer3;
                                            $composer$iv2 = $composer3;
                                        } else {
                                            $composer$iv = $composer3;
                                            $composer$iv2 = $composer3;
                                            ListItemKt.m1450ProvideTextStyleFromToken3JVO9M(listItemColors3.headlineColor$material3_release(true, $composer3, ((i12 >> 15) & 112) | 6).getValue().m2616unboximpl(), ListTokens.INSTANCE.getListItemLabelTextFont(), function213, $composer3, ((i12 << 6) & 896) | 48);
                                            $composer4 = $composer3;
                                            long m2616unboximpl = listItemColors3.supportingColor$material3_release($composer4, (i12 >> 18) & 14).getValue().m2616unboximpl();
                                            TypographyKeyTokens listItemSupportingTextFont = ListTokens.INSTANCE.getListItemSupportingTextFont();
                                            Intrinsics.checkNotNull(function214);
                                            ListItemKt.m1450ProvideTextStyleFromToken3JVO9M(m2616unboximpl, listItemSupportingTextFont, function214, $composer4, 48);
                                        }
                                        $composer4.endReplaceableGroup();
                                    }
                                    $composer$iv.endReplaceableGroup();
                                    $composer3.endReplaceableGroup();
                                    $composer3.endNode();
                                    $composer3.endReplaceableGroup();
                                    $composer3.endReplaceableGroup();
                                }
                                $composer3.endReplaceableGroup();
                            }
                            $composer$iv2.endReplaceableGroup();
                            $composer3.endReplaceableGroup();
                            $composer3.endNode();
                            $composer3.endReplaceableGroup();
                            $composer3.endReplaceableGroup();
                            Function2<Composer, Integer, Unit> function215 = function210;
                            if (function215 != null) {
                                m1456trailingContentiJQMabo = ListItemKt.m1456trailingContentiJQMabo(function215, listItemColors2.trailingIconColor$material3_release(true, $composer3, ((i11 >> 15) & 112) | 6).getValue().m2616unboximpl(), false, $composer3, ((i11 >> 15) & 14) | 384);
                                m1456trailingContentiJQMabo.invoke(ListItem, $composer3, Integer.valueOf($dirty3 & 14));
                            }
                            if (ComposerKt.isTraceInProgress()) {
                                ComposerKt.traceEventEnd();
                                return;
                            }
                            return;
                        }
                        $composer3.skipToGroupEnd();
                    }
                }), $composer2, (($dirty >> 3) & 14) | 114819072 | (($dirty >> 9) & 57344) | (($dirty >> 9) & 458752), 2);
                $composer2.endReplaceableGroup();
            } else if (supportingText == null) {
                $composer2.startReplaceableGroup(-85611073);
                ComposerKt.sourceInformation($composer2, "167@7018L16,168@7076L29,165@6939L1653");
                final Function2 function212 = leadingContent;
                final ListItemColors listItemColors3 = colors2;
                final int i12 = $dirty;
                final Function2 function213 = trailingContent;
                final Function2 function214 = overlineText;
                m1449ListItemxOgov6c(modifier2, null, colors2.containerColor$material3_release($composer2, ($dirty >> 18) & 14).getValue().m2616unboximpl(), colors2.headlineColor$material3_release(true, $composer2, (($dirty >> 15) & 112) | 6).getValue().m2616unboximpl(), tonalElevation2, shadowElevation2, TwoLineListItemContainerHeight, PaddingKt.m408PaddingValuesYgX7TsA(ListItemHorizontalPadding, ListItemVerticalPadding), ComposableLambdaKt.composableLambda($composer2, 1733969726, true, new Function3<RowScope, Composer, Integer, Unit>() { // from class: androidx.compose.material3.ListItemKt$ListItem$3
                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    /* JADX WARN: Multi-variable type inference failed */
                    {
                        super(3);
                    }

                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Unit invoke(RowScope rowScope, Composer composer, Integer num) {
                        invoke(rowScope, composer, num.intValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(RowScope ListItem, Composer $composer3, int $changed2) {
                        Composer $composer$iv;
                        Composer $composer$iv2;
                        Composer $composer4;
                        Function3 m1456trailingContentiJQMabo;
                        Function3 m1455leadingContentiJQMabo;
                        Intrinsics.checkNotNullParameter(ListItem, "$this$ListItem");
                        ComposerKt.sourceInformation($composer3, "C181@7659L638,202@8471L33,200@8357L209,200@8357L211:ListItem.kt#uh7d8r");
                        int $dirty2 = $changed2;
                        if (($changed2 & 14) == 0) {
                            $dirty2 |= $composer3.changed(ListItem) ? 4 : 2;
                        }
                        int $dirty3 = $dirty2;
                        if (($dirty3 & 91) != 18 || !$composer3.getSkipping()) {
                            if (ComposerKt.isTraceInProgress()) {
                                ComposerKt.traceEventStart(1733969726, $dirty3, -1, "androidx.compose.material3.ListItem.<anonymous> (ListItem.kt:173)");
                            }
                            $composer3.startReplaceableGroup(1316675520);
                            ComposerKt.sourceInformation($composer3, "177@7536L32,175@7425L205,175@7425L207");
                            Function2<Composer, Integer, Unit> function215 = function212;
                            if (function215 != null) {
                                m1455leadingContentiJQMabo = ListItemKt.m1455leadingContentiJQMabo(function215, listItemColors3.leadingIconColor$material3_release(true, $composer3, ((i12 >> 15) & 112) | 6).getValue().m2616unboximpl(), false, $composer3, ((i12 >> 12) & 14) | 384);
                                m1455leadingContentiJQMabo.invoke(ListItem, $composer3, Integer.valueOf($dirty3 & 14));
                            }
                            $composer3.endReplaceableGroup();
                            Modifier modifier$iv = ListItem.align(RowScope.weight$default(ListItem, Modifier.Companion, 1.0f, false, 2, null), Alignment.Companion.getCenterVertically());
                            ListItemColors listItemColors4 = listItemColors3;
                            int i13 = i12;
                            Function2<Composer, Integer, Unit> function216 = function214;
                            Function2<Composer, Integer, Unit> function217 = headlineText;
                            $composer3.startReplaceableGroup(733328855);
                            ComposerKt.sourceInformation($composer3, "C(Box)P(2,1,3)70@3267L67,71@3339L130:Box.kt#2w3rfo");
                            Alignment contentAlignment$iv = Alignment.Companion.getTopStart();
                            MeasurePolicy measurePolicy$iv = BoxKt.rememberBoxMeasurePolicy(contentAlignment$iv, false, $composer3, ((0 >> 3) & 14) | ((0 >> 3) & 112));
                            int $changed$iv$iv = (0 << 3) & 112;
                            $composer3.startReplaceableGroup(-1323940314);
                            ComposerKt.sourceInformation($composer3, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                            Object consume = $composer3.consume(CompositionLocalsKt.getLocalDensity());
                            ComposerKt.sourceInformationMarkerEnd($composer3);
                            Density density$iv$iv = (Density) consume;
                            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                            Object consume2 = $composer3.consume(CompositionLocalsKt.getLocalLayoutDirection());
                            ComposerKt.sourceInformationMarkerEnd($composer3);
                            LayoutDirection layoutDirection$iv$iv = (LayoutDirection) consume2;
                            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                            Object consume3 = $composer3.consume(CompositionLocalsKt.getLocalViewConfiguration());
                            ComposerKt.sourceInformationMarkerEnd($composer3);
                            ViewConfiguration viewConfiguration$iv$iv = (ViewConfiguration) consume3;
                            Function0 factory$iv$iv$iv = ComposeUiNode.Companion.getConstructor();
                            Function3 skippableUpdate$iv$iv$iv = LayoutKt.materializerOf(modifier$iv);
                            int $changed$iv$iv$iv = (($changed$iv$iv << 9) & 7168) | 6;
                            if (!($composer3.getApplier() instanceof Applier)) {
                                ComposablesKt.invalidApplier();
                            }
                            $composer3.startReusableNode();
                            if ($composer3.getInserting()) {
                                $composer3.createNode(factory$iv$iv$iv);
                            } else {
                                $composer3.useNode();
                            }
                            $composer3.disableReusing();
                            Composer $this$Layout_u24lambda_u2d0$iv$iv = Updater.m2247constructorimpl($composer3);
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, measurePolicy$iv, ComposeUiNode.Companion.getSetMeasurePolicy());
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, density$iv$iv, ComposeUiNode.Companion.getSetDensity());
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, layoutDirection$iv$iv, ComposeUiNode.Companion.getSetLayoutDirection());
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, viewConfiguration$iv$iv, ComposeUiNode.Companion.getSetViewConfiguration());
                            $composer3.enableReusing();
                            skippableUpdate$iv$iv$iv.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer3)), $composer3, Integer.valueOf(($changed$iv$iv$iv >> 3) & 112));
                            $composer3.startReplaceableGroup(2058660585);
                            int $changed$iv = ($changed$iv$iv$iv >> 9) & 14;
                            $composer3.startReplaceableGroup(-2137368960);
                            ComposerKt.sourceInformation($composer3, "C72@3384L9:Box.kt#2w3rfo");
                            if (($changed$iv & 11) == 2 && $composer3.getSkipping()) {
                                $composer3.skipToGroupEnd();
                                $composer$iv2 = $composer3;
                            } else {
                                BoxScopeInstance boxScopeInstance = BoxScopeInstance.INSTANCE;
                                $composer3.startReplaceableGroup(-1917170824);
                                ComposerKt.sourceInformation($composer3, "C186@7808L475:ListItem.kt#uh7d8r");
                                if (((((0 >> 6) & 112) | 6) & 81) == 16 && $composer3.getSkipping()) {
                                    $composer3.skipToGroupEnd();
                                    $composer$iv2 = $composer3;
                                } else {
                                    $composer3.startReplaceableGroup(-483455358);
                                    ComposerKt.sourceInformation($composer3, "C(Column)P(2,3,1)77@3880L61,78@3946L133:Column.kt#2w3rfo");
                                    Modifier modifier$iv2 = Modifier.Companion;
                                    Arrangement.Vertical verticalArrangement$iv = Arrangement.INSTANCE.getTop();
                                    Alignment.Horizontal horizontalAlignment$iv = Alignment.Companion.getStart();
                                    MeasurePolicy measurePolicy$iv2 = ColumnKt.columnMeasurePolicy(verticalArrangement$iv, horizontalAlignment$iv, $composer3, ((0 >> 3) & 14) | ((0 >> 3) & 112));
                                    int $changed$iv$iv2 = (0 << 3) & 112;
                                    $composer3.startReplaceableGroup(-1323940314);
                                    ComposerKt.sourceInformation($composer3, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume4 = $composer3.consume(CompositionLocalsKt.getLocalDensity());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    Density density$iv$iv2 = (Density) consume4;
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume5 = $composer3.consume(CompositionLocalsKt.getLocalLayoutDirection());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    LayoutDirection layoutDirection$iv$iv2 = (LayoutDirection) consume5;
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume6 = $composer3.consume(CompositionLocalsKt.getLocalViewConfiguration());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    ViewConfiguration viewConfiguration$iv$iv2 = (ViewConfiguration) consume6;
                                    Function0 factory$iv$iv$iv2 = ComposeUiNode.Companion.getConstructor();
                                    Function3 skippableUpdate$iv$iv$iv2 = LayoutKt.materializerOf(modifier$iv2);
                                    int $changed$iv$iv$iv2 = (($changed$iv$iv2 << 9) & 7168) | 6;
                                    if (!($composer3.getApplier() instanceof Applier)) {
                                        ComposablesKt.invalidApplier();
                                    }
                                    $composer3.startReusableNode();
                                    if ($composer3.getInserting()) {
                                        $composer3.createNode(factory$iv$iv$iv2);
                                    } else {
                                        $composer3.useNode();
                                    }
                                    $composer3.disableReusing();
                                    Composer $this$Layout_u24lambda_u2d0$iv$iv2 = Updater.m2247constructorimpl($composer3);
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, measurePolicy$iv2, ComposeUiNode.Companion.getSetMeasurePolicy());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, density$iv$iv2, ComposeUiNode.Companion.getSetDensity());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, layoutDirection$iv$iv2, ComposeUiNode.Companion.getSetLayoutDirection());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, viewConfiguration$iv$iv2, ComposeUiNode.Companion.getSetViewConfiguration());
                                    $composer3.enableReusing();
                                    skippableUpdate$iv$iv$iv2.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer3)), $composer3, Integer.valueOf(($changed$iv$iv$iv2 >> 3) & 112));
                                    $composer3.startReplaceableGroup(2058660585);
                                    int $changed$iv2 = ($changed$iv$iv$iv2 >> 9) & 14;
                                    $composer3.startReplaceableGroup(-1163856341);
                                    ComposerKt.sourceInformation($composer3, "C79@3994L9:Column.kt#2w3rfo");
                                    if (($changed$iv2 & 11) == 2 && $composer3.getSkipping()) {
                                        $composer3.skipToGroupEnd();
                                        $composer$iv = $composer3;
                                        $composer$iv2 = $composer3;
                                    } else {
                                        ColumnScopeInstance columnScopeInstance = ColumnScopeInstance.INSTANCE;
                                        $composer3.startReplaceableGroup(562295746);
                                        ComposerKt.sourceInformation($composer3, "C188@7895L15,187@7837L196,193@8112L29,192@8054L211:ListItem.kt#uh7d8r");
                                        if (((((0 >> 6) & 112) | 6) & 81) == 16 && $composer3.getSkipping()) {
                                            $composer3.skipToGroupEnd();
                                            $composer4 = $composer3;
                                            $composer$iv = $composer3;
                                            $composer$iv2 = $composer3;
                                        } else {
                                            $composer$iv = $composer3;
                                            $composer$iv2 = $composer3;
                                            ListItemKt.m1450ProvideTextStyleFromToken3JVO9M(listItemColors4.overlineColor$material3_release($composer3, (i13 >> 18) & 14).getValue().m2616unboximpl(), ListTokens.INSTANCE.getListItemOverlineFont(), function216, $composer3, (i13 & 896) | 48);
                                            $composer4 = $composer3;
                                            ListItemKt.m1450ProvideTextStyleFromToken3JVO9M(listItemColors4.headlineColor$material3_release(true, $composer4, ((i13 >> 15) & 112) | 6).getValue().m2616unboximpl(), ListTokens.INSTANCE.getListItemLabelTextFont(), function217, $composer4, ((i13 << 6) & 896) | 48);
                                        }
                                        $composer4.endReplaceableGroup();
                                    }
                                    $composer$iv.endReplaceableGroup();
                                    $composer3.endReplaceableGroup();
                                    $composer3.endNode();
                                    $composer3.endReplaceableGroup();
                                    $composer3.endReplaceableGroup();
                                }
                                $composer3.endReplaceableGroup();
                            }
                            $composer$iv2.endReplaceableGroup();
                            $composer3.endReplaceableGroup();
                            $composer3.endNode();
                            $composer3.endReplaceableGroup();
                            $composer3.endReplaceableGroup();
                            Function2<Composer, Integer, Unit> function218 = function213;
                            if (function218 != null) {
                                m1456trailingContentiJQMabo = ListItemKt.m1456trailingContentiJQMabo(function218, listItemColors3.trailingIconColor$material3_release(true, $composer3, ((i12 >> 15) & 112) | 6).getValue().m2616unboximpl(), false, $composer3, ((i12 >> 15) & 14) | 384);
                                m1456trailingContentiJQMabo.invoke(ListItem, $composer3, Integer.valueOf($dirty3 & 14));
                            }
                            if (ComposerKt.isTraceInProgress()) {
                                ComposerKt.traceEventEnd();
                                return;
                            }
                            return;
                        }
                        $composer3.skipToGroupEnd();
                    }
                }), $composer2, (($dirty >> 3) & 14) | 114819072 | (($dirty >> 9) & 57344) | (($dirty >> 9) & 458752), 2);
                $composer2.endReplaceableGroup();
            } else {
                $composer2.startReplaceableGroup(-85609368);
                ComposerKt.sourceInformation($composer2, "211@8725L16,212@8783L29,209@8646L1935");
                final Function2 function215 = leadingContent;
                final ListItemColors listItemColors4 = colors2;
                final int i13 = $dirty;
                final Function2 function216 = trailingContent;
                final Function2 function217 = overlineText;
                final Function2 function218 = supportingText;
                m1449ListItemxOgov6c(modifier2, null, colors2.containerColor$material3_release($composer2, ($dirty >> 18) & 14).getValue().m2616unboximpl(), colors2.headlineColor$material3_release(true, $composer2, (($dirty >> 15) & 112) | 6).getValue().m2616unboximpl(), tonalElevation2, shadowElevation2, ThreeLineListItemContainerHeight, PaddingKt.m408PaddingValuesYgX7TsA(ListItemHorizontalPadding, ListItemThreeLineVerticalPadding), ComposableLambdaKt.composableLambda($composer2, -1269203265, true, new Function3<RowScope, Composer, Integer, Unit>() { // from class: androidx.compose.material3.ListItemKt$ListItem$4
                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    /* JADX WARN: Multi-variable type inference failed */
                    {
                        super(3);
                    }

                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Unit invoke(RowScope rowScope, Composer composer, Integer num) {
                        invoke(rowScope, composer, num.intValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(RowScope ListItem, Composer $composer3, int $changed2) {
                        float f;
                        Composer $composer$iv;
                        Composer $composer$iv2;
                        Composer $composer4;
                        Function3 m1456trailingContentiJQMabo;
                        Function3 m1455leadingContentiJQMabo;
                        Intrinsics.checkNotNullParameter(ListItem, "$this$ListItem");
                        ComposerKt.sourceInformation($composer3, "C228@9422L865,254@10461L33,252@10347L208,252@10347L210:ListItem.kt#uh7d8r");
                        int $dirty2 = $changed2;
                        if (($changed2 & 14) == 0) {
                            $dirty2 |= $composer3.changed(ListItem) ? 4 : 2;
                        }
                        int $dirty3 = $dirty2;
                        if (($dirty3 & 91) != 18 || !$composer3.getSkipping()) {
                            if (ComposerKt.isTraceInProgress()) {
                                ComposerKt.traceEventStart(-1269203265, $dirty3, -1, "androidx.compose.material3.ListItem.<anonymous> (ListItem.kt:220)");
                            }
                            $composer3.startReplaceableGroup(1316677284);
                            ComposerKt.sourceInformation($composer3, "224@9300L32,222@9189L204,222@9189L206");
                            Function2<Composer, Integer, Unit> function219 = function215;
                            if (function219 != null) {
                                m1455leadingContentiJQMabo = ListItemKt.m1455leadingContentiJQMabo(function219, listItemColors4.leadingIconColor$material3_release(true, $composer3, ((i13 >> 15) & 112) | 6).getValue().m2616unboximpl(), true, $composer3, ((i13 >> 12) & 14) | 384);
                                m1455leadingContentiJQMabo.invoke(ListItem, $composer3, Integer.valueOf($dirty3 & 14));
                            }
                            $composer3.endReplaceableGroup();
                            Modifier weight$default = RowScope.weight$default(ListItem, Modifier.Companion, 1.0f, false, 2, null);
                            f = ListItemKt.ContentEndPadding;
                            Modifier modifier$iv = PaddingKt.m418paddingqDBjuR0$default(weight$default, 0.0f, 0.0f, f, 0.0f, 11, null);
                            ListItemColors listItemColors5 = listItemColors4;
                            int i14 = i13;
                            Function2<Composer, Integer, Unit> function220 = function217;
                            Function2<Composer, Integer, Unit> function221 = headlineText;
                            Function2<Composer, Integer, Unit> function222 = function218;
                            $composer3.startReplaceableGroup(733328855);
                            ComposerKt.sourceInformation($composer3, "C(Box)P(2,1,3)70@3267L67,71@3339L130:Box.kt#2w3rfo");
                            Alignment contentAlignment$iv = Alignment.Companion.getTopStart();
                            MeasurePolicy measurePolicy$iv = BoxKt.rememberBoxMeasurePolicy(contentAlignment$iv, false, $composer3, ((0 >> 3) & 14) | ((0 >> 3) & 112));
                            int $changed$iv$iv = (0 << 3) & 112;
                            $composer3.startReplaceableGroup(-1323940314);
                            ComposerKt.sourceInformation($composer3, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                            Object consume = $composer3.consume(CompositionLocalsKt.getLocalDensity());
                            ComposerKt.sourceInformationMarkerEnd($composer3);
                            Density density$iv$iv = (Density) consume;
                            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                            Object consume2 = $composer3.consume(CompositionLocalsKt.getLocalLayoutDirection());
                            ComposerKt.sourceInformationMarkerEnd($composer3);
                            LayoutDirection layoutDirection$iv$iv = (LayoutDirection) consume2;
                            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                            Object consume3 = $composer3.consume(CompositionLocalsKt.getLocalViewConfiguration());
                            ComposerKt.sourceInformationMarkerEnd($composer3);
                            ViewConfiguration viewConfiguration$iv$iv = (ViewConfiguration) consume3;
                            Function0 factory$iv$iv$iv = ComposeUiNode.Companion.getConstructor();
                            Function3 skippableUpdate$iv$iv$iv = LayoutKt.materializerOf(modifier$iv);
                            int $changed$iv$iv$iv = (($changed$iv$iv << 9) & 7168) | 6;
                            if (!($composer3.getApplier() instanceof Applier)) {
                                ComposablesKt.invalidApplier();
                            }
                            $composer3.startReusableNode();
                            if ($composer3.getInserting()) {
                                $composer3.createNode(factory$iv$iv$iv);
                            } else {
                                $composer3.useNode();
                            }
                            $composer3.disableReusing();
                            Composer $this$Layout_u24lambda_u2d0$iv$iv = Updater.m2247constructorimpl($composer3);
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, measurePolicy$iv, ComposeUiNode.Companion.getSetMeasurePolicy());
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, density$iv$iv, ComposeUiNode.Companion.getSetDensity());
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, layoutDirection$iv$iv, ComposeUiNode.Companion.getSetLayoutDirection());
                            Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, viewConfiguration$iv$iv, ComposeUiNode.Companion.getSetViewConfiguration());
                            $composer3.enableReusing();
                            skippableUpdate$iv$iv$iv.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer3)), $composer3, Integer.valueOf(($changed$iv$iv$iv >> 3) & 112));
                            $composer3.startReplaceableGroup(2058660585);
                            int $changed$iv = ($changed$iv$iv$iv >> 9) & 14;
                            $composer3.startReplaceableGroup(-2137368960);
                            ComposerKt.sourceInformation($composer3, "C72@3384L9:Box.kt#2w3rfo");
                            if (($changed$iv & 11) == 2 && $composer3.getSkipping()) {
                                $composer3.skipToGroupEnd();
                                $composer$iv2 = $composer3;
                            } else {
                                BoxScopeInstance boxScopeInstance = BoxScopeInstance.INSTANCE;
                                $composer3.startReplaceableGroup(-729239559);
                                ComposerKt.sourceInformation($composer3, "C233@9571L702:ListItem.kt#uh7d8r");
                                if (((((0 >> 6) & 112) | 6) & 81) == 16 && $composer3.getSkipping()) {
                                    $composer3.skipToGroupEnd();
                                    $composer$iv2 = $composer3;
                                } else {
                                    $composer3.startReplaceableGroup(-483455358);
                                    ComposerKt.sourceInformation($composer3, "C(Column)P(2,3,1)77@3880L61,78@3946L133:Column.kt#2w3rfo");
                                    Modifier modifier$iv2 = Modifier.Companion;
                                    Arrangement.Vertical verticalArrangement$iv = Arrangement.INSTANCE.getTop();
                                    Alignment.Horizontal horizontalAlignment$iv = Alignment.Companion.getStart();
                                    MeasurePolicy measurePolicy$iv2 = ColumnKt.columnMeasurePolicy(verticalArrangement$iv, horizontalAlignment$iv, $composer3, ((0 >> 3) & 14) | ((0 >> 3) & 112));
                                    int $changed$iv$iv2 = (0 << 3) & 112;
                                    $composer3.startReplaceableGroup(-1323940314);
                                    ComposerKt.sourceInformation($composer3, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume4 = $composer3.consume(CompositionLocalsKt.getLocalDensity());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    Density density$iv$iv2 = (Density) consume4;
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume5 = $composer3.consume(CompositionLocalsKt.getLocalLayoutDirection());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    LayoutDirection layoutDirection$iv$iv2 = (LayoutDirection) consume5;
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume6 = $composer3.consume(CompositionLocalsKt.getLocalViewConfiguration());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    ViewConfiguration viewConfiguration$iv$iv2 = (ViewConfiguration) consume6;
                                    Function0 factory$iv$iv$iv2 = ComposeUiNode.Companion.getConstructor();
                                    Function3 skippableUpdate$iv$iv$iv2 = LayoutKt.materializerOf(modifier$iv2);
                                    int $changed$iv$iv$iv2 = (($changed$iv$iv2 << 9) & 7168) | 6;
                                    if (!($composer3.getApplier() instanceof Applier)) {
                                        ComposablesKt.invalidApplier();
                                    }
                                    $composer3.startReusableNode();
                                    if ($composer3.getInserting()) {
                                        $composer3.createNode(factory$iv$iv$iv2);
                                    } else {
                                        $composer3.useNode();
                                    }
                                    $composer3.disableReusing();
                                    Composer $this$Layout_u24lambda_u2d0$iv$iv2 = Updater.m2247constructorimpl($composer3);
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, measurePolicy$iv2, ComposeUiNode.Companion.getSetMeasurePolicy());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, density$iv$iv2, ComposeUiNode.Companion.getSetDensity());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, layoutDirection$iv$iv2, ComposeUiNode.Companion.getSetLayoutDirection());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, viewConfiguration$iv$iv2, ComposeUiNode.Companion.getSetViewConfiguration());
                                    $composer3.enableReusing();
                                    skippableUpdate$iv$iv$iv2.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer3)), $composer3, Integer.valueOf(($changed$iv$iv$iv2 >> 3) & 112));
                                    $composer3.startReplaceableGroup(2058660585);
                                    int $changed$iv2 = ($changed$iv$iv$iv2 >> 9) & 14;
                                    $composer3.startReplaceableGroup(-1163856341);
                                    ComposerKt.sourceInformation($composer3, "C79@3994L9:Column.kt#2w3rfo");
                                    if (($changed$iv2 & 11) == 2 && $composer3.getSkipping()) {
                                        $composer3.skipToGroupEnd();
                                        $composer$iv = $composer3;
                                        $composer$iv2 = $composer3;
                                    } else {
                                        ColumnScopeInstance columnScopeInstance = ColumnScopeInstance.INSTANCE;
                                        $composer3.startReplaceableGroup(-466219709);
                                        ComposerKt.sourceInformation($composer3, "C235@9658L15,234@9600L196,240@9875L29,239@9817L211,245@10107L17,244@10049L206:ListItem.kt#uh7d8r");
                                        if (((((0 >> 6) & 112) | 6) & 81) != 16 || !$composer3.getSkipping()) {
                                            int i15 = (i14 >> 18) & 14;
                                            $composer$iv = $composer3;
                                            $composer$iv2 = $composer3;
                                            ListItemKt.m1450ProvideTextStyleFromToken3JVO9M(listItemColors5.overlineColor$material3_release($composer3, i15).getValue().m2616unboximpl(), ListTokens.INSTANCE.getListItemOverlineFont(), function220, $composer3, (i14 & 896) | 48);
                                            $composer4 = $composer3;
                                            ListItemKt.m1450ProvideTextStyleFromToken3JVO9M(listItemColors5.headlineColor$material3_release(true, $composer4, ((i14 >> 15) & 112) | 6).getValue().m2616unboximpl(), ListTokens.INSTANCE.getListItemLabelTextFont(), function221, $composer4, ((i14 << 6) & 896) | 48);
                                            ListItemKt.m1450ProvideTextStyleFromToken3JVO9M(listItemColors5.supportingColor$material3_release($composer4, i15).getValue().m2616unboximpl(), ListTokens.INSTANCE.getListItemSupportingTextFont(), function222, $composer4, ((i14 >> 3) & 896) | 48);
                                        } else {
                                            $composer3.skipToGroupEnd();
                                            $composer$iv = $composer3;
                                            $composer4 = $composer3;
                                            $composer$iv2 = $composer3;
                                        }
                                        $composer4.endReplaceableGroup();
                                    }
                                    $composer$iv.endReplaceableGroup();
                                    $composer3.endReplaceableGroup();
                                    $composer3.endNode();
                                    $composer3.endReplaceableGroup();
                                    $composer3.endReplaceableGroup();
                                }
                                $composer3.endReplaceableGroup();
                            }
                            $composer$iv2.endReplaceableGroup();
                            $composer3.endReplaceableGroup();
                            $composer3.endNode();
                            $composer3.endReplaceableGroup();
                            $composer3.endReplaceableGroup();
                            Function2<Composer, Integer, Unit> function223 = function216;
                            if (function223 != null) {
                                m1456trailingContentiJQMabo = ListItemKt.m1456trailingContentiJQMabo(function223, listItemColors4.trailingIconColor$material3_release(true, $composer3, ((i13 >> 15) & 112) | 6).getValue().m2616unboximpl(), true, $composer3, ((i13 >> 15) & 14) | 384);
                                m1456trailingContentiJQMabo.invoke(ListItem, $composer3, Integer.valueOf($dirty3 & 14));
                            }
                            if (ComposerKt.isTraceInProgress()) {
                                ComposerKt.traceEventEnd();
                                return;
                            }
                            return;
                        }
                        $composer3.skipToGroupEnd();
                    }
                }), $composer2, (($dirty >> 3) & 14) | 114819072 | (($dirty >> 9) & 57344) | (($dirty >> 9) & 458752), 2);
                $composer2.endReplaceableGroup();
            }
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            tonalElevation3 = tonalElevation2;
            modifier3 = modifier2;
            shadowElevation3 = shadowElevation2;
            overlineText2 = overlineText;
            supportingText2 = supportingText;
            leadingContent2 = leadingContent;
            trailingContent2 = trailingContent;
            colors3 = colors2;
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Modifier modifier4 = modifier3;
        final Function2 function219 = overlineText2;
        final Function2 function220 = supportingText2;
        final Function2 function221 = leadingContent2;
        final Function2 function222 = trailingContent2;
        final ListItemColors listItemColors5 = colors3;
        final float f = tonalElevation3;
        final float f2 = shadowElevation3;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material3.ListItemKt$ListItem$5
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
                invoke(composer, num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(Composer composer, int i14) {
                ListItemKt.m1448ListItemHXNGIdc(headlineText, modifier4, function219, function220, function221, function222, listItemColors5, f, f2, composer, $changed | 1, i);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:100:0x0123  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0144  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0177  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x017c  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x0183  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x018c  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x0191  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x019a  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x019f  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x01a8  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x01ab  */
    /* JADX WARN: Removed duplicated region for block: B:136:0x01b2  */
    /* JADX WARN: Removed duplicated region for block: B:138:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x01bd  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01c8  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x0216  */
    /* JADX WARN: Removed duplicated region for block: B:149:0x022d  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x0230  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x00ed  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00f0  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0105  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0109  */
    @androidx.compose.material3.ExperimentalMaterial3Api
    /* renamed from: ListItem-xOgov6c  reason: not valid java name */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void m1449ListItemxOgov6c(androidx.compose.ui.Modifier r29, androidx.compose.ui.graphics.Shape r30, long r31, long r33, float r35, float r36, final float r37, final androidx.compose.foundation.layout.PaddingValues r38, final kotlin.jvm.functions.Function3<? super androidx.compose.foundation.layout.RowScope, ? super androidx.compose.runtime.Composer, ? super java.lang.Integer, kotlin.Unit> r39, androidx.compose.runtime.Composer r40, final int r41, final int r42) {
        /*
            Method dump skipped, instructions count: 600
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.ListItemKt.m1449ListItemxOgov6c(androidx.compose.ui.Modifier, androidx.compose.ui.graphics.Shape, long, long, float, float, float, androidx.compose.foundation.layout.PaddingValues, kotlin.jvm.functions.Function3, androidx.compose.runtime.Composer, int, int):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: leadingContent-iJQMabo  reason: not valid java name */
    public static final Function3<RowScope, Composer, Integer, Unit> m1455leadingContentiJQMabo(final Function2<? super Composer, ? super Integer, Unit> function2, final long contentColor, final boolean topAlign, Composer $composer, final int $changed) {
        $composer.startReplaceableGroup(292744125);
        ComposerKt.sourceInformation($composer, "C(leadingContent)P(1,0:c#ui.graphics.Color):ListItem.kt#uh7d8r");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(292744125, $changed, -1, "androidx.compose.material3.leadingContent (ListItem.kt:309)");
        }
        ComposableLambda composableLambda = ComposableLambdaKt.composableLambda($composer, -1755598478, true, new Function3<RowScope, Composer, Integer, Unit>() { // from class: androidx.compose.material3.ListItemKt$leadingContent$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(3);
            }

            @Override // kotlin.jvm.functions.Function3
            public /* bridge */ /* synthetic */ Unit invoke(RowScope rowScope, Composer composer, Integer num) {
                invoke(rowScope, composer, num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(final RowScope $this$null, Composer $composer2, int $changed2) {
                Intrinsics.checkNotNullParameter($this$null, "$this$null");
                ComposerKt.sourceInformation($composer2, "C315@12372L554:ListItem.kt#uh7d8r");
                int $dirty = $changed2;
                if (($changed2 & 14) == 0) {
                    $dirty |= $composer2.changed($this$null) ? 4 : 2;
                }
                if (($dirty & 91) != 18 || !$composer2.getSkipping()) {
                    if (ComposerKt.isTraceInProgress()) {
                        ComposerKt.traceEventStart(-1755598478, $changed2, -1, "androidx.compose.material3.leadingContent.<anonymous> (ListItem.kt:314)");
                    }
                    ProvidedValue[] providedValueArr = {ContentColorKt.getLocalContentColor().provides(Color.m2596boximpl(contentColor))};
                    final boolean z = topAlign;
                    final Function2<Composer, Integer, Unit> function22 = function2;
                    final int i = $changed;
                    CompositionLocalKt.CompositionLocalProvider(providedValueArr, ComposableLambdaKt.composableLambda($composer2, -1636714958, true, new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material3.ListItemKt$leadingContent$1.1
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        /* JADX WARN: Multi-variable type inference failed */
                        {
                            super(2);
                        }

                        @Override // kotlin.jvm.functions.Function2
                        public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
                            invoke(composer, num.intValue());
                            return Unit.INSTANCE;
                        }

                        public final void invoke(Composer $composer3, int $changed3) {
                            float f;
                            float f2;
                            ComposerKt.sourceInformation($composer3, "C:ListItem.kt#uh7d8r");
                            if (($changed3 & 11) != 2 || !$composer3.getSkipping()) {
                                if (ComposerKt.isTraceInProgress()) {
                                    ComposerKt.traceEventStart(-1636714958, $changed3, -1, "androidx.compose.material3.leadingContent.<anonymous>.<anonymous> (ListItem.kt:316)");
                                }
                                if (z) {
                                    $composer3.startReplaceableGroup(377880875);
                                    ComposerKt.sourceInformation($composer3, "318@12497L171");
                                    f2 = ListItemKt.LeadingContentEndPadding;
                                    Modifier modifier$iv = PaddingKt.m418paddingqDBjuR0$default(Modifier.Companion, 0.0f, 0.0f, f2, 0.0f, 11, null);
                                    Alignment contentAlignment$iv = Alignment.Companion.getTopStart();
                                    Function2<Composer, Integer, Unit> function23 = function22;
                                    int i2 = i;
                                    $composer3.startReplaceableGroup(733328855);
                                    ComposerKt.sourceInformation($composer3, "C(Box)P(2,1,3)70@3267L67,71@3339L130:Box.kt#2w3rfo");
                                    MeasurePolicy measurePolicy$iv = BoxKt.rememberBoxMeasurePolicy(contentAlignment$iv, false, $composer3, ((54 >> 3) & 14) | ((54 >> 3) & 112));
                                    int $changed$iv$iv = (54 << 3) & 112;
                                    $composer3.startReplaceableGroup(-1323940314);
                                    ComposerKt.sourceInformation($composer3, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume = $composer3.consume(CompositionLocalsKt.getLocalDensity());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    Density density$iv$iv = (Density) consume;
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume2 = $composer3.consume(CompositionLocalsKt.getLocalLayoutDirection());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    LayoutDirection layoutDirection$iv$iv = (LayoutDirection) consume2;
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume3 = $composer3.consume(CompositionLocalsKt.getLocalViewConfiguration());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    ViewConfiguration viewConfiguration$iv$iv = (ViewConfiguration) consume3;
                                    Function0 factory$iv$iv$iv = ComposeUiNode.Companion.getConstructor();
                                    Function3 skippableUpdate$iv$iv$iv = LayoutKt.materializerOf(modifier$iv);
                                    int $changed$iv$iv$iv = (($changed$iv$iv << 9) & 7168) | 6;
                                    if (!($composer3.getApplier() instanceof Applier)) {
                                        ComposablesKt.invalidApplier();
                                    }
                                    $composer3.startReusableNode();
                                    if ($composer3.getInserting()) {
                                        $composer3.createNode(factory$iv$iv$iv);
                                    } else {
                                        $composer3.useNode();
                                    }
                                    $composer3.disableReusing();
                                    Composer $this$Layout_u24lambda_u2d0$iv$iv = Updater.m2247constructorimpl($composer3);
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, measurePolicy$iv, ComposeUiNode.Companion.getSetMeasurePolicy());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, density$iv$iv, ComposeUiNode.Companion.getSetDensity());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, layoutDirection$iv$iv, ComposeUiNode.Companion.getSetLayoutDirection());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, viewConfiguration$iv$iv, ComposeUiNode.Companion.getSetViewConfiguration());
                                    $composer3.enableReusing();
                                    skippableUpdate$iv$iv$iv.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer3)), $composer3, Integer.valueOf(($changed$iv$iv$iv >> 3) & 112));
                                    $composer3.startReplaceableGroup(2058660585);
                                    int $changed$iv = ($changed$iv$iv$iv >> 9) & 14;
                                    $composer3.startReplaceableGroup(-2137368960);
                                    ComposerKt.sourceInformation($composer3, "C72@3384L9:Box.kt#2w3rfo");
                                    if (($changed$iv & 11) == 2 && $composer3.getSkipping()) {
                                        $composer3.skipToGroupEnd();
                                    } else {
                                        BoxScopeInstance boxScopeInstance = BoxScopeInstance.INSTANCE;
                                        $composer3.startReplaceableGroup(781903379);
                                        ComposerKt.sourceInformation($composer3, "C321@12650L16:ListItem.kt#uh7d8r");
                                        if (((((54 >> 6) & 112) | 6) & 81) == 16 && $composer3.getSkipping()) {
                                            $composer3.skipToGroupEnd();
                                        } else {
                                            function23.invoke($composer3, Integer.valueOf(i2 & 14));
                                        }
                                        $composer3.endReplaceableGroup();
                                    }
                                    $composer3.endReplaceableGroup();
                                    $composer3.endReplaceableGroup();
                                    $composer3.endNode();
                                    $composer3.endReplaceableGroup();
                                    $composer3.endReplaceableGroup();
                                    $composer3.endReplaceableGroup();
                                } else {
                                    $composer3.startReplaceableGroup(377881084);
                                    ComposerKt.sourceInformation($composer3, "323@12706L196");
                                    Modifier align = $this$null.align(Modifier.Companion, Alignment.Companion.getCenterVertically());
                                    f = ListItemKt.LeadingContentEndPadding;
                                    Modifier modifier$iv2 = PaddingKt.m418paddingqDBjuR0$default(align, 0.0f, 0.0f, f, 0.0f, 11, null);
                                    Function2<Composer, Integer, Unit> function24 = function22;
                                    int i3 = i;
                                    $composer3.startReplaceableGroup(733328855);
                                    ComposerKt.sourceInformation($composer3, "C(Box)P(2,1,3)70@3267L67,71@3339L130:Box.kt#2w3rfo");
                                    Alignment contentAlignment$iv2 = Alignment.Companion.getTopStart();
                                    MeasurePolicy measurePolicy$iv2 = BoxKt.rememberBoxMeasurePolicy(contentAlignment$iv2, false, $composer3, ((0 >> 3) & 14) | ((0 >> 3) & 112));
                                    int $changed$iv$iv2 = (0 << 3) & 112;
                                    $composer3.startReplaceableGroup(-1323940314);
                                    ComposerKt.sourceInformation($composer3, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume4 = $composer3.consume(CompositionLocalsKt.getLocalDensity());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    Density density$iv$iv2 = (Density) consume4;
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume5 = $composer3.consume(CompositionLocalsKt.getLocalLayoutDirection());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    LayoutDirection layoutDirection$iv$iv2 = (LayoutDirection) consume5;
                                    ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, "C:CompositionLocal.kt#9igjgp");
                                    Object consume6 = $composer3.consume(CompositionLocalsKt.getLocalViewConfiguration());
                                    ComposerKt.sourceInformationMarkerEnd($composer3);
                                    ViewConfiguration viewConfiguration$iv$iv2 = (ViewConfiguration) consume6;
                                    Function0 factory$iv$iv$iv2 = ComposeUiNode.Companion.getConstructor();
                                    Function3 skippableUpdate$iv$iv$iv2 = LayoutKt.materializerOf(modifier$iv2);
                                    int $changed$iv$iv$iv2 = (($changed$iv$iv2 << 9) & 7168) | 6;
                                    if (!($composer3.getApplier() instanceof Applier)) {
                                        ComposablesKt.invalidApplier();
                                    }
                                    $composer3.startReusableNode();
                                    if ($composer3.getInserting()) {
                                        $composer3.createNode(factory$iv$iv$iv2);
                                    } else {
                                        $composer3.useNode();
                                    }
                                    $composer3.disableReusing();
                                    Composer $this$Layout_u24lambda_u2d0$iv$iv2 = Updater.m2247constructorimpl($composer3);
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, measurePolicy$iv2, ComposeUiNode.Companion.getSetMeasurePolicy());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, density$iv$iv2, ComposeUiNode.Companion.getSetDensity());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, layoutDirection$iv$iv2, ComposeUiNode.Companion.getSetLayoutDirection());
                                    Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, viewConfiguration$iv$iv2, ComposeUiNode.Companion.getSetViewConfiguration());
                                    $composer3.enableReusing();
                                    skippableUpdate$iv$iv$iv2.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer3)), $composer3, Integer.valueOf(($changed$iv$iv$iv2 >> 3) & 112));
                                    $composer3.startReplaceableGroup(2058660585);
                                    int $changed$iv2 = ($changed$iv$iv$iv2 >> 9) & 14;
                                    $composer3.startReplaceableGroup(-2137368960);
                                    ComposerKt.sourceInformation($composer3, "C72@3384L9:Box.kt#2w3rfo");
                                    if (($changed$iv2 & 11) == 2 && $composer3.getSkipping()) {
                                        $composer3.skipToGroupEnd();
                                    } else {
                                        BoxScopeInstance boxScopeInstance2 = BoxScopeInstance.INSTANCE;
                                        $composer3.startReplaceableGroup(-1395522852);
                                        ComposerKt.sourceInformation($composer3, "C327@12884L16:ListItem.kt#uh7d8r");
                                        if (((((0 >> 6) & 112) | 6) & 81) == 16 && $composer3.getSkipping()) {
                                            $composer3.skipToGroupEnd();
                                        } else {
                                            function24.invoke($composer3, Integer.valueOf(i3 & 14));
                                        }
                                        $composer3.endReplaceableGroup();
                                    }
                                    $composer3.endReplaceableGroup();
                                    $composer3.endReplaceableGroup();
                                    $composer3.endNode();
                                    $composer3.endReplaceableGroup();
                                    $composer3.endReplaceableGroup();
                                    $composer3.endReplaceableGroup();
                                }
                                if (ComposerKt.isTraceInProgress()) {
                                    ComposerKt.traceEventEnd();
                                    return;
                                }
                                return;
                            }
                            $composer3.skipToGroupEnd();
                        }
                    }), $composer2, 56);
                    if (ComposerKt.isTraceInProgress()) {
                        ComposerKt.traceEventEnd();
                        return;
                    }
                    return;
                }
                $composer2.skipToGroupEnd();
            }
        });
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return composableLambda;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: trailingContent-iJQMabo  reason: not valid java name */
    public static final Function3<RowScope, Composer, Integer, Unit> m1456trailingContentiJQMabo(final Function2<? super Composer, ? super Integer, Unit> function2, final long contentColor, final boolean topAlign, Composer $composer, final int $changed) {
        $composer.startReplaceableGroup(2067138571);
        ComposerKt.sourceInformation($composer, "C(trailingContent)P(2,0:c#ui.graphics.Color):ListItem.kt#uh7d8r");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(2067138571, $changed, -1, "androidx.compose.material3.trailingContent (ListItem.kt:334)");
        }
        ComposableLambda composableLambda = ComposableLambdaKt.composableLambda($composer, -1301939978, true, new Function3<RowScope, Composer, Integer, Unit>() { // from class: androidx.compose.material3.ListItemKt$trailingContent$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(3);
            }

            @Override // kotlin.jvm.functions.Function3
            public /* bridge */ /* synthetic */ Unit invoke(RowScope rowScope, Composer composer, Integer num) {
                invoke(rowScope, composer, num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(RowScope $this$null, Composer $composer2, int $changed2) {
                float f;
                float f2;
                Intrinsics.checkNotNullParameter($this$null, "$this$null");
                ComposerKt.sourceInformation($composer2, "C:ListItem.kt#uh7d8r");
                int $dirty = $changed2;
                if (($changed2 & 14) == 0) {
                    $dirty |= $composer2.changed($this$null) ? 4 : 2;
                }
                if (($dirty & 91) != 18 || !$composer2.getSkipping()) {
                    if (ComposerKt.isTraceInProgress()) {
                        ComposerKt.traceEventStart(-1301939978, $changed2, -1, "androidx.compose.material3.trailingContent.<anonymous> (ListItem.kt:339)");
                    }
                    if (topAlign) {
                        $composer2.startReplaceableGroup(1857837855);
                        ComposerKt.sourceInformation($composer2, "341@13158L348");
                        f2 = ListItemKt.TrailingHorizontalPadding;
                        Modifier modifier$iv = PaddingKt.m416paddingVpY3zN4$default(Modifier.Companion, f2, 0.0f, 2, null);
                        Alignment contentAlignment$iv = Alignment.Companion.getTopStart();
                        long j = contentColor;
                        Function2<Composer, Integer, Unit> function22 = function2;
                        int i = $changed;
                        $composer2.startReplaceableGroup(733328855);
                        ComposerKt.sourceInformation($composer2, "C(Box)P(2,1,3)70@3267L67,71@3339L130:Box.kt#2w3rfo");
                        MeasurePolicy measurePolicy$iv = BoxKt.rememberBoxMeasurePolicy(contentAlignment$iv, false, $composer2, ((54 >> 3) & 14) | ((54 >> 3) & 112));
                        int $changed$iv$iv = (54 << 3) & 112;
                        $composer2.startReplaceableGroup(-1323940314);
                        ComposerKt.sourceInformation($composer2, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                        ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "C:CompositionLocal.kt#9igjgp");
                        Object consume = $composer2.consume(CompositionLocalsKt.getLocalDensity());
                        ComposerKt.sourceInformationMarkerEnd($composer2);
                        Density density$iv$iv = (Density) consume;
                        ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "C:CompositionLocal.kt#9igjgp");
                        Object consume2 = $composer2.consume(CompositionLocalsKt.getLocalLayoutDirection());
                        ComposerKt.sourceInformationMarkerEnd($composer2);
                        LayoutDirection layoutDirection$iv$iv = (LayoutDirection) consume2;
                        ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "C:CompositionLocal.kt#9igjgp");
                        Object consume3 = $composer2.consume(CompositionLocalsKt.getLocalViewConfiguration());
                        ComposerKt.sourceInformationMarkerEnd($composer2);
                        ViewConfiguration viewConfiguration$iv$iv = (ViewConfiguration) consume3;
                        Function0 factory$iv$iv$iv = ComposeUiNode.Companion.getConstructor();
                        Function3 skippableUpdate$iv$iv$iv = LayoutKt.materializerOf(modifier$iv);
                        int $changed$iv$iv$iv = (($changed$iv$iv << 9) & 7168) | 6;
                        if (!($composer2.getApplier() instanceof Applier)) {
                            ComposablesKt.invalidApplier();
                        }
                        $composer2.startReusableNode();
                        if ($composer2.getInserting()) {
                            $composer2.createNode(factory$iv$iv$iv);
                        } else {
                            $composer2.useNode();
                        }
                        $composer2.disableReusing();
                        Composer $this$Layout_u24lambda_u2d0$iv$iv = Updater.m2247constructorimpl($composer2);
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, measurePolicy$iv, ComposeUiNode.Companion.getSetMeasurePolicy());
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, density$iv$iv, ComposeUiNode.Companion.getSetDensity());
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, layoutDirection$iv$iv, ComposeUiNode.Companion.getSetLayoutDirection());
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv, viewConfiguration$iv$iv, ComposeUiNode.Companion.getSetViewConfiguration());
                        $composer2.enableReusing();
                        skippableUpdate$iv$iv$iv.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer2)), $composer2, Integer.valueOf(($changed$iv$iv$iv >> 3) & 112));
                        $composer2.startReplaceableGroup(2058660585);
                        int $changed$iv = ($changed$iv$iv$iv >> 9) & 14;
                        $composer2.startReplaceableGroup(-2137368960);
                        ComposerKt.sourceInformation($composer2, "C72@3384L9:Box.kt#2w3rfo");
                        if (($changed$iv & 11) == 2 && $composer2.getSkipping()) {
                            $composer2.skipToGroupEnd();
                        } else {
                            BoxScopeInstance boxScopeInstance = BoxScopeInstance.INSTANCE;
                            $composer2.startReplaceableGroup(-1890987531);
                            ComposerKt.sourceInformation($composer2, "C345@13323L181:ListItem.kt#uh7d8r");
                            if (((((54 >> 6) & 112) | 6) & 81) != 16 || !$composer2.getSkipping()) {
                                ListItemKt.m1450ProvideTextStyleFromToken3JVO9M(j, ListTokens.INSTANCE.getListItemTrailingSupportingTextFont(), function22, $composer2, ((i >> 3) & 14) | 48 | ((i << 6) & 896));
                            } else {
                                $composer2.skipToGroupEnd();
                            }
                            $composer2.endReplaceableGroup();
                        }
                        $composer2.endReplaceableGroup();
                        $composer2.endReplaceableGroup();
                        $composer2.endNode();
                        $composer2.endReplaceableGroup();
                        $composer2.endReplaceableGroup();
                        $composer2.endReplaceableGroup();
                    } else {
                        $composer2.startReplaceableGroup(1857838233);
                        ComposerKt.sourceInformation($composer2, "351@13536L369");
                        Modifier align = $this$null.align(Modifier.Companion, Alignment.Companion.getCenterVertically());
                        f = ListItemKt.TrailingHorizontalPadding;
                        Modifier modifier$iv2 = PaddingKt.m416paddingVpY3zN4$default(align, f, 0.0f, 2, null);
                        long j2 = contentColor;
                        Function2<Composer, Integer, Unit> function23 = function2;
                        int i2 = $changed;
                        $composer2.startReplaceableGroup(733328855);
                        ComposerKt.sourceInformation($composer2, "C(Box)P(2,1,3)70@3267L67,71@3339L130:Box.kt#2w3rfo");
                        Alignment contentAlignment$iv2 = Alignment.Companion.getTopStart();
                        MeasurePolicy measurePolicy$iv2 = BoxKt.rememberBoxMeasurePolicy(contentAlignment$iv2, false, $composer2, ((0 >> 3) & 14) | ((0 >> 3) & 112));
                        int $changed$iv$iv2 = (0 << 3) & 112;
                        $composer2.startReplaceableGroup(-1323940314);
                        ComposerKt.sourceInformation($composer2, "C(Layout)P(!1,2)74@2915L7,75@2970L7,76@3029L7,77@3041L460:Layout.kt#80mrfh");
                        ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "C:CompositionLocal.kt#9igjgp");
                        Object consume4 = $composer2.consume(CompositionLocalsKt.getLocalDensity());
                        ComposerKt.sourceInformationMarkerEnd($composer2);
                        Density density$iv$iv2 = (Density) consume4;
                        ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "C:CompositionLocal.kt#9igjgp");
                        Object consume5 = $composer2.consume(CompositionLocalsKt.getLocalLayoutDirection());
                        ComposerKt.sourceInformationMarkerEnd($composer2);
                        LayoutDirection layoutDirection$iv$iv2 = (LayoutDirection) consume5;
                        ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "C:CompositionLocal.kt#9igjgp");
                        Object consume6 = $composer2.consume(CompositionLocalsKt.getLocalViewConfiguration());
                        ComposerKt.sourceInformationMarkerEnd($composer2);
                        ViewConfiguration viewConfiguration$iv$iv2 = (ViewConfiguration) consume6;
                        Function0 factory$iv$iv$iv2 = ComposeUiNode.Companion.getConstructor();
                        Function3 skippableUpdate$iv$iv$iv2 = LayoutKt.materializerOf(modifier$iv2);
                        int $changed$iv$iv$iv2 = (($changed$iv$iv2 << 9) & 7168) | 6;
                        if (!($composer2.getApplier() instanceof Applier)) {
                            ComposablesKt.invalidApplier();
                        }
                        $composer2.startReusableNode();
                        if ($composer2.getInserting()) {
                            $composer2.createNode(factory$iv$iv$iv2);
                        } else {
                            $composer2.useNode();
                        }
                        $composer2.disableReusing();
                        Composer $this$Layout_u24lambda_u2d0$iv$iv2 = Updater.m2247constructorimpl($composer2);
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, measurePolicy$iv2, ComposeUiNode.Companion.getSetMeasurePolicy());
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, density$iv$iv2, ComposeUiNode.Companion.getSetDensity());
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, layoutDirection$iv$iv2, ComposeUiNode.Companion.getSetLayoutDirection());
                        Updater.m2254setimpl($this$Layout_u24lambda_u2d0$iv$iv2, viewConfiguration$iv$iv2, ComposeUiNode.Companion.getSetViewConfiguration());
                        $composer2.enableReusing();
                        skippableUpdate$iv$iv$iv2.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer2)), $composer2, Integer.valueOf(($changed$iv$iv$iv2 >> 3) & 112));
                        $composer2.startReplaceableGroup(2058660585);
                        int $changed$iv2 = ($changed$iv$iv$iv2 >> 9) & 14;
                        $composer2.startReplaceableGroup(-2137368960);
                        ComposerKt.sourceInformation($composer2, "C72@3384L9:Box.kt#2w3rfo");
                        if (($changed$iv2 & 11) == 2 && $composer2.getSkipping()) {
                            $composer2.skipToGroupEnd();
                        } else {
                            BoxScopeInstance boxScopeInstance2 = BoxScopeInstance.INSTANCE;
                            $composer2.startReplaceableGroup(-471095028);
                            ComposerKt.sourceInformation($composer2, "C356@13722L181:ListItem.kt#uh7d8r");
                            if (((((0 >> 6) & 112) | 6) & 81) != 16 || !$composer2.getSkipping()) {
                                ListItemKt.m1450ProvideTextStyleFromToken3JVO9M(j2, ListTokens.INSTANCE.getListItemTrailingSupportingTextFont(), function23, $composer2, ((i2 >> 3) & 14) | 48 | ((i2 << 6) & 896));
                            } else {
                                $composer2.skipToGroupEnd();
                            }
                            $composer2.endReplaceableGroup();
                        }
                        $composer2.endReplaceableGroup();
                        $composer2.endReplaceableGroup();
                        $composer2.endNode();
                        $composer2.endReplaceableGroup();
                        $composer2.endReplaceableGroup();
                        $composer2.endReplaceableGroup();
                    }
                    if (ComposerKt.isTraceInProgress()) {
                        ComposerKt.traceEventEnd();
                        return;
                    }
                    return;
                }
                $composer2.skipToGroupEnd();
            }
        });
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return composableLambda;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: ProvideTextStyleFromToken-3J-VO9M  reason: not valid java name */
    public static final void m1450ProvideTextStyleFromToken3JVO9M(final long color, final TypographyKeyTokens textToken, final Function2<? super Composer, ? super Integer, Unit> function2, Composer $composer, final int $changed) {
        Composer $composer2 = $composer.startRestartGroup(1133967795);
        ComposerKt.sourceInformation($composer2, "C(ProvideTextStyleFromToken)P(0:c#ui.graphics.Color,2)494@19374L10,495@19410L111:ListItem.kt#uh7d8r");
        final int $dirty = $changed;
        if (($changed & 14) == 0) {
            $dirty |= $composer2.changed(color) ? 4 : 2;
        }
        if (($changed & 112) == 0) {
            $dirty |= $composer2.changed(textToken) ? 32 : 16;
        }
        if (($changed & 896) == 0) {
            $dirty |= $composer2.changed(function2) ? 256 : 128;
        }
        if (($dirty & 731) != 146 || !$composer2.getSkipping()) {
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(1133967795, $dirty, -1, "androidx.compose.material3.ProvideTextStyleFromToken (ListItem.kt:489)");
            }
            final TextStyle textStyle = TypographyKt.fromToken(MaterialTheme.INSTANCE.getTypography($composer2, 6), textToken);
            CompositionLocalKt.CompositionLocalProvider(new ProvidedValue[]{ContentColorKt.getLocalContentColor().provides(Color.m2596boximpl(color))}, ComposableLambdaKt.composableLambda($composer2, -514310925, true, new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material3.ListItemKt$ProvideTextStyleFromToken$1
                /* JADX INFO: Access modifiers changed from: package-private */
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                /* JADX WARN: Multi-variable type inference failed */
                {
                    super(2);
                }

                @Override // kotlin.jvm.functions.Function2
                public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
                    invoke(composer, num.intValue());
                    return Unit.INSTANCE;
                }

                public final void invoke(Composer $composer3, int $changed2) {
                    ComposerKt.sourceInformation($composer3, "C496@19479L36:ListItem.kt#uh7d8r");
                    if (($changed2 & 11) == 2 && $composer3.getSkipping()) {
                        $composer3.skipToGroupEnd();
                        return;
                    }
                    if (ComposerKt.isTraceInProgress()) {
                        ComposerKt.traceEventStart(-514310925, $changed2, -1, "androidx.compose.material3.ProvideTextStyleFromToken.<anonymous> (ListItem.kt:495)");
                    }
                    TextKt.ProvideTextStyle(TextStyle.this, function2, $composer3, ($dirty >> 3) & 112);
                    if (ComposerKt.isTraceInProgress()) {
                        ComposerKt.traceEventEnd();
                    }
                }
            }), $composer2, 56);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
        } else {
            $composer2.skipToGroupEnd();
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.material3.ListItemKt$ProvideTextStyleFromToken$2
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
                invoke(composer, num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(Composer composer, int i) {
                ListItemKt.m1450ProvideTextStyleFromToken3JVO9M(color, textToken, function2, composer, $changed | 1);
            }
        });
    }
}
