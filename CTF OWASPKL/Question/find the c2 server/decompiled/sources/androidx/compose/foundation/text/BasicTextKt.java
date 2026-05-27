package androidx.compose.foundation.text;

import androidx.compose.foundation.text.selection.SelectionRegistrar;
import androidx.compose.foundation.text.selection.SelectionRegistrarKt;
import androidx.compose.foundation.text.selection.TextSelectionColors;
import androidx.compose.foundation.text.selection.TextSelectionColorsKt;
import androidx.compose.runtime.Applier;
import androidx.compose.runtime.ComposablesKt;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.RecomposeScopeImplKt;
import androidx.compose.runtime.ScopeUpdateScope;
import androidx.compose.runtime.SkippableUpdater;
import androidx.compose.runtime.Updater;
import androidx.compose.runtime.internal.ComposableLambdaKt;
import androidx.compose.runtime.saveable.RememberSaveableKt;
import androidx.compose.runtime.saveable.Saver;
import androidx.compose.runtime.saveable.SaverKt;
import androidx.compose.runtime.saveable.SaverScope;
import androidx.compose.ui.ComposedModifierKt;
import androidx.compose.ui.Modifier;
import androidx.compose.ui.layout.LayoutKt;
import androidx.compose.ui.layout.MeasurePolicy;
import androidx.compose.ui.node.ComposeUiNode;
import androidx.compose.ui.platform.CompositionLocalsKt;
import androidx.compose.ui.platform.ViewConfiguration;
import androidx.compose.ui.text.AnnotatedString;
import androidx.compose.ui.text.Placeholder;
import androidx.compose.ui.text.TextLayoutResult;
import androidx.compose.ui.text.TextStyle;
import androidx.compose.ui.text.font.FontFamily;
import androidx.compose.ui.text.style.TextOverflow;
import androidx.compose.ui.unit.Density;
import androidx.compose.ui.unit.LayoutDirection;
import androidx.profileinstaller.ProfileVerifier;
import java.util.List;
import java.util.Map;
import kotlin.Deprecated;
import kotlin.DeprecationLevel;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.MapsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: BasicText.kt */
@Metadata(d1 = {"\u0000X\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010$\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0000\u001a\u0085\u0001\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00052\b\b\u0002\u0010\u0006\u001a\u00020\u00072\u0014\b\u0002\u0010\b\u001a\u000e\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\u00010\t2\b\b\u0002\u0010\u000b\u001a\u00020\f2\b\b\u0002\u0010\r\u001a\u00020\u000e2\b\b\u0002\u0010\u000f\u001a\u00020\u00102\b\b\u0002\u0010\u0011\u001a\u00020\u00102\u0014\b\u0002\u0010\u0012\u001a\u000e\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u00150\u0013H\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0016\u0010\u0017\u001a{\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00052\b\b\u0002\u0010\u0006\u001a\u00020\u00072\u0014\b\u0002\u0010\b\u001a\u000e\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\u00010\t2\b\b\u0002\u0010\u000b\u001a\u00020\f2\b\b\u0002\u0010\r\u001a\u00020\u000e2\b\b\u0002\u0010\u000f\u001a\u00020\u00102\u0014\b\u0002\u0010\u0012\u001a\u000e\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u00150\u0013H\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0018\u0010\u0019\u001ae\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00142\b\b\u0002\u0010\u0004\u001a\u00020\u00052\b\b\u0002\u0010\u0006\u001a\u00020\u00072\u0014\b\u0002\u0010\b\u001a\u000e\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\u00010\t2\b\b\u0002\u0010\u000b\u001a\u00020\f2\b\b\u0002\u0010\r\u001a\u00020\u000e2\b\b\u0002\u0010\u000f\u001a\u00020\u0010H\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u001a\u0010\u001b\u001ao\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00142\b\b\u0002\u0010\u0004\u001a\u00020\u00052\b\b\u0002\u0010\u0006\u001a\u00020\u00072\u0014\b\u0002\u0010\b\u001a\u000e\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\u00010\t2\b\b\u0002\u0010\u000b\u001a\u00020\f2\b\b\u0002\u0010\r\u001a\u00020\u000e2\b\b\u0002\u0010\u000f\u001a\u00020\u00102\b\b\u0002\u0010\u0011\u001a\u00020\u0010H\u0007ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0018\u0010\u001c\u001a\u001e\u0010\u001d\u001a\u000e\u0012\u0004\u0012\u00020\u001f\u0012\u0004\u0012\u00020\u001f0\u001e2\b\u0010 \u001a\u0004\u0018\u00010!H\u0002\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006\""}, d2 = {"BasicText", "", "text", "Landroidx/compose/ui/text/AnnotatedString;", "modifier", "Landroidx/compose/ui/Modifier;", "style", "Landroidx/compose/ui/text/TextStyle;", "onTextLayout", "Lkotlin/Function1;", "Landroidx/compose/ui/text/TextLayoutResult;", "overflow", "Landroidx/compose/ui/text/style/TextOverflow;", "softWrap", "", "maxLines", "", "minLines", "inlineContent", "", "", "Landroidx/compose/foundation/text/InlineTextContent;", "BasicText-VhcvRP8", "(Landroidx/compose/ui/text/AnnotatedString;Landroidx/compose/ui/Modifier;Landroidx/compose/ui/text/TextStyle;Lkotlin/jvm/functions/Function1;IZIILjava/util/Map;Landroidx/compose/runtime/Composer;II)V", "BasicText-4YKlhWE", "(Landroidx/compose/ui/text/AnnotatedString;Landroidx/compose/ui/Modifier;Landroidx/compose/ui/text/TextStyle;Lkotlin/jvm/functions/Function1;IZILjava/util/Map;Landroidx/compose/runtime/Composer;II)V", "BasicText-BpD7jsM", "(Ljava/lang/String;Landroidx/compose/ui/Modifier;Landroidx/compose/ui/text/TextStyle;Lkotlin/jvm/functions/Function1;IZILandroidx/compose/runtime/Composer;II)V", "(Ljava/lang/String;Landroidx/compose/ui/Modifier;Landroidx/compose/ui/text/TextStyle;Lkotlin/jvm/functions/Function1;IZIILandroidx/compose/runtime/Composer;II)V", "selectionIdSaver", "Landroidx/compose/runtime/saveable/Saver;", "", "selectionRegistrar", "Landroidx/compose/foundation/text/selection/SelectionRegistrar;", "foundation_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class BasicTextKt {
    /* renamed from: BasicText-4YKlhWE */
    public static final void m693BasicText4YKlhWE(final String text, Modifier modifier, TextStyle style, Function1<? super TextLayoutResult, Unit> function1, int overflow, boolean softWrap, int maxLines, int minLines, Composer $composer, final int $changed, final int i) {
        Object obj;
        Function1 onTextLayout;
        int overflow2;
        boolean softWrap2;
        TextStyle style2;
        int maxLines2;
        SelectionRegistrar selectionRegistrar;
        SelectionRegistrar selectionRegistrar2;
        TextState state;
        String str;
        int minLines2;
        int overflow3;
        boolean softWrap3;
        TextController controller;
        Function1 onTextLayout2;
        int i2;
        Modifier modifier2;
        int overflow4;
        Function1 onTextLayout3;
        Intrinsics.checkNotNullParameter(text, "text");
        Composer $composer2 = $composer.startRestartGroup(1542716361);
        ComposerKt.sourceInformation($composer2, "C(BasicText)P(7,2,6,3,4:c#ui.text.style.TextOverflow,5)80@4041L7,81@4080L7,82@4141L7,102@5126L514,141@6375L96:BasicText.kt#423gt5");
        int $dirty = $changed;
        if ((i & 1) != 0) {
            $dirty |= 6;
        } else if (($changed & 14) == 0) {
            $dirty |= $composer2.changed(text) ? 4 : 2;
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
            obj = style;
        } else if (($changed & 896) == 0) {
            obj = style;
            $dirty |= $composer2.changed(obj) ? 256 : 128;
        } else {
            obj = style;
        }
        int i5 = i & 8;
        if (i5 != 0) {
            $dirty |= 3072;
            onTextLayout = function1;
        } else if (($changed & 7168) == 0) {
            onTextLayout = function1;
            $dirty |= $composer2.changedInstance(onTextLayout) ? 2048 : 1024;
        } else {
            onTextLayout = function1;
        }
        int i6 = i & 16;
        if (i6 != 0) {
            $dirty |= 24576;
            overflow2 = overflow;
        } else if ((57344 & $changed) == 0) {
            overflow2 = overflow;
            $dirty |= $composer2.changed(overflow2) ? 16384 : 8192;
        } else {
            overflow2 = overflow;
        }
        int i7 = i & 32;
        if (i7 != 0) {
            $dirty |= ProfileVerifier.CompilationStatus.RESULT_CODE_ERROR_CANT_WRITE_PROFILE_VERIFICATION_RESULT_CACHE_FILE;
            softWrap2 = softWrap;
        } else if ((458752 & $changed) == 0) {
            softWrap2 = softWrap;
            $dirty |= $composer2.changed(softWrap2) ? 131072 : 65536;
        } else {
            softWrap2 = softWrap;
        }
        int i8 = i & 64;
        if (i8 != 0) {
            $dirty |= 1572864;
        } else if (($changed & 3670016) == 0) {
            $dirty |= $composer2.changed(maxLines) ? 1048576 : 524288;
        }
        int i9 = i & 128;
        if (i9 != 0) {
            $dirty |= 12582912;
        } else if (($changed & 29360128) == 0) {
            $dirty |= $composer2.changed(minLines) ? 8388608 : 4194304;
        }
        if (($dirty & 23967451) == 4793490 && $composer2.getSkipping()) {
            $composer2.skipToGroupEnd();
            modifier2 = modifier;
            maxLines2 = maxLines;
            minLines2 = minLines;
            style2 = obj;
            onTextLayout3 = onTextLayout;
            overflow4 = overflow2;
        } else {
            Modifier modifier3 = i3 != 0 ? Modifier.Companion : modifier;
            style2 = i4 != 0 ? TextStyle.Companion.getDefault() : obj;
            if (i5 != 0) {
                onTextLayout = new Function1<TextLayoutResult, Unit>() { // from class: androidx.compose.foundation.text.BasicTextKt$BasicText$1
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(TextLayoutResult textLayoutResult) {
                        invoke2(textLayoutResult);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke  reason: avoid collision after fix types in other method */
                    public final void invoke2(TextLayoutResult it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                    }
                };
            }
            if (i6 != 0) {
                overflow2 = TextOverflow.Companion.m5041getClipgIe3tQ8();
            }
            if (i7 != 0) {
                softWrap2 = true;
            }
            maxLines2 = i8 != 0 ? Integer.MAX_VALUE : maxLines;
            int minLines3 = i9 != 0 ? 1 : minLines;
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(1542716361, $changed, -1, "androidx.compose.foundation.text.BasicText (BasicText.kt:60)");
            }
            HeightInLinesModifierKt.validateMinMaxLines(minLines3, maxLines2);
            ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "CC:CompositionLocal.kt#9igjgp");
            Object consume = $composer2.consume(SelectionRegistrarKt.getLocalSelectionRegistrar());
            ComposerKt.sourceInformationMarkerEnd($composer2);
            final SelectionRegistrar selectionRegistrar3 = (SelectionRegistrar) consume;
            ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "CC:CompositionLocal.kt#9igjgp");
            Object consume2 = $composer2.consume(CompositionLocalsKt.getLocalDensity());
            ComposerKt.sourceInformationMarkerEnd($composer2);
            Density density = (Density) consume2;
            ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, "CC:CompositionLocal.kt#9igjgp");
            Object consume3 = $composer2.consume(CompositionLocalsKt.getLocalFontFamilyResolver());
            ComposerKt.sourceInformationMarkerEnd($composer2);
            FontFamily.Resolver fontFamilyResolver = (FontFamily.Resolver) consume3;
            $composer2.startReplaceableGroup(959238681);
            ComposerKt.sourceInformation($composer2, "97@4947L150");
            long longValue = selectionRegistrar3 == null ? 0L : ((Number) RememberSaveableKt.m2260rememberSaveable(new Object[]{text, selectionRegistrar3}, (Saver<Object, ? extends Object>) selectionIdSaver(selectionRegistrar3), (String) null, (Function0<? extends Object>) new Function0<Long>() { // from class: androidx.compose.foundation.text.BasicTextKt$BasicText$selectableId$1
                /* JADX INFO: Access modifiers changed from: package-private */
                {
                    super(0);
                }

                /* JADX WARN: Can't rename method to resolve collision */
                @Override // kotlin.jvm.functions.Function0
                public final Long invoke() {
                    return Long.valueOf(SelectionRegistrar.this.nextSelectableId());
                }
            }, $composer2, 72, 4)).longValue();
            $composer2.endReplaceableGroup();
            long selectableId = longValue;
            $composer2.startReplaceableGroup(-492369756);
            ComposerKt.sourceInformation($composer2, "CC(remember):Composables.kt#9igjgp");
            Object value$iv$iv = $composer2.rememberedValue();
            Modifier modifier4 = modifier3;
            if (value$iv$iv == Composer.Companion.getEmpty()) {
                selectionRegistrar = selectionRegistrar3;
                value$iv$iv = new TextController(new TextState(new TextDelegate(new AnnotatedString(text, null, null, 6, null), style2, maxLines2, minLines3, softWrap2, overflow2, density, fontFamilyResolver, null, 256, null), selectableId));
                $composer2.updateRememberedValue(value$iv$iv);
            } else {
                selectionRegistrar = selectionRegistrar3;
            }
            $composer2.endReplaceableGroup();
            TextController controller2 = (TextController) value$iv$iv;
            TextState state2 = controller2.getState();
            if ($composer2.getInserting()) {
                selectionRegistrar2 = selectionRegistrar;
                state = state2;
                str = "CC:CompositionLocal.kt#9igjgp";
                minLines2 = minLines3;
                overflow3 = overflow2;
                softWrap3 = softWrap2;
                controller = controller2;
                onTextLayout2 = onTextLayout;
            } else {
                selectionRegistrar2 = selectionRegistrar;
                state = state2;
                str = "CC:CompositionLocal.kt#9igjgp";
                boolean z = softWrap2;
                softWrap3 = softWrap2;
                controller = controller2;
                int i10 = overflow2;
                overflow3 = overflow2;
                onTextLayout2 = onTextLayout;
                minLines2 = minLines3;
                controller.setTextDelegate(CoreTextKt.m712updateTextDelegatex_uQXYA(state2.getTextDelegate(), text, style2, density, fontFamilyResolver, z, i10, maxLines2, minLines3));
            }
            state.setOnTextLayout(onTextLayout2);
            controller.update(selectionRegistrar2);
            $composer2.startReplaceableGroup(959240076);
            ComposerKt.sourceInformation($composer2, "138@6340L7");
            if (selectionRegistrar2 != null) {
                i2 = 2023513938;
                ComposerKt.sourceInformationMarkerStart($composer2, 2023513938, str);
                Object consume4 = $composer2.consume(TextSelectionColorsKt.getLocalTextSelectionColors());
                ComposerKt.sourceInformationMarkerEnd($composer2);
                state.m799setSelectionBackgroundColor8_81llA(((TextSelectionColors) consume4).m883getBackgroundColor0d7_KjU());
            } else {
                i2 = 2023513938;
            }
            $composer2.endReplaceableGroup();
            Modifier modifier$iv = modifier4.then(controller.getModifiers());
            MeasurePolicy measurePolicy$iv = controller.getMeasurePolicy();
            $composer2.startReplaceableGroup(544976794);
            ComposerKt.sourceInformation($composer2, "CC(Layout)P(1)119@4537L7,120@4592L7,121@4651L7,123@4724L439:Layout.kt#80mrfh");
            ComposerKt.sourceInformationMarkerStart($composer2, i2, str);
            Object consume5 = $composer2.consume(CompositionLocalsKt.getLocalDensity());
            ComposerKt.sourceInformationMarkerEnd($composer2);
            Density density$iv = (Density) consume5;
            ComposerKt.sourceInformationMarkerStart($composer2, i2, str);
            Object consume6 = $composer2.consume(CompositionLocalsKt.getLocalLayoutDirection());
            ComposerKt.sourceInformationMarkerEnd($composer2);
            LayoutDirection layoutDirection$iv = (LayoutDirection) consume6;
            ComposerKt.sourceInformationMarkerStart($composer2, i2, str);
            Object consume7 = $composer2.consume(CompositionLocalsKt.getLocalViewConfiguration());
            ComposerKt.sourceInformationMarkerEnd($composer2);
            ViewConfiguration viewConfiguration$iv = (ViewConfiguration) consume7;
            Modifier materialized$iv = ComposedModifierKt.materialize($composer2, modifier$iv);
            final Function0 factory$iv$iv = ComposeUiNode.Companion.getConstructor();
            $composer2.startReplaceableGroup(1405779621);
            ComposerKt.sourceInformation($composer2, "CC(ReusableComposeNode):Composables.kt#9igjgp");
            if (!($composer2.getApplier() instanceof Applier)) {
                ComposablesKt.invalidApplier();
            }
            $composer2.startReusableNode();
            if ($composer2.getInserting()) {
                $composer2.createNode(new Function0<ComposeUiNode>() { // from class: androidx.compose.foundation.text.BasicTextKt$BasicText-4YKlhWE$$inlined$Layout$1
                    {
                        super(0);
                    }

                    /* JADX WARN: Type inference failed for: r0v1, types: [androidx.compose.ui.node.ComposeUiNode, java.lang.Object] */
                    @Override // kotlin.jvm.functions.Function0
                    public final ComposeUiNode invoke() {
                        return Function0.this.invoke();
                    }
                });
            } else {
                $composer2.useNode();
            }
            Composer $this$Layout_u24lambda_u241$iv = Updater.m2247constructorimpl($composer2);
            modifier2 = modifier4;
            Updater.m2254setimpl($this$Layout_u24lambda_u241$iv, measurePolicy$iv, ComposeUiNode.Companion.getSetMeasurePolicy());
            Updater.m2254setimpl($this$Layout_u24lambda_u241$iv, density$iv, ComposeUiNode.Companion.getSetDensity());
            Updater.m2254setimpl($this$Layout_u24lambda_u241$iv, layoutDirection$iv, ComposeUiNode.Companion.getSetLayoutDirection());
            Updater.m2254setimpl($this$Layout_u24lambda_u241$iv, viewConfiguration$iv, ComposeUiNode.Companion.getSetViewConfiguration());
            Updater.m2254setimpl($this$Layout_u24lambda_u241$iv, materialized$iv, ComposeUiNode.Companion.getSetModifier());
            $composer2.endNode();
            $composer2.endReplaceableGroup();
            $composer2.endReplaceableGroup();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
            softWrap2 = softWrap3;
            overflow4 = overflow3;
            onTextLayout3 = onTextLayout2;
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Modifier modifier5 = modifier2;
        final TextStyle textStyle = style2;
        final Function1 function12 = onTextLayout3;
        final int i11 = overflow4;
        final boolean z2 = softWrap2;
        final int i12 = maxLines2;
        final int i13 = minLines2;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.foundation.text.BasicTextKt$BasicText$2
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
                BasicTextKt.m693BasicText4YKlhWE(text, modifier5, textStyle, function12, i11, z2, i12, i13, composer, RecomposeScopeImplKt.updateChangedFlags($changed | 1), i);
            }
        });
    }

    /* renamed from: BasicText-VhcvRP8 */
    public static final void m695BasicTextVhcvRP8(final AnnotatedString text, Modifier modifier, TextStyle style, Function1<? super TextLayoutResult, Unit> function1, int overflow, boolean softWrap, int maxLines, int minLines, Map<String, InlineTextContent> map, Composer $composer, final int $changed, final int i) {
        Function1 onTextLayout;
        int i2;
        TextStyle style2;
        int overflow2;
        boolean softWrap2;
        int $dirty;
        long longValue;
        Modifier modifier2;
        SelectionRegistrar selectionRegistrar;
        String str;
        long selectionBackgroundColor;
        Map inlineContent;
        Function1 onTextLayout2;
        int minLines2;
        int maxLines2;
        int $dirty2;
        long selectableId;
        List<AnnotatedString.Range<Function3<String, Composer, Integer, Unit>>> list;
        Composer $composer2;
        final List<AnnotatedString.Range<Function3<String, Composer, Integer, Unit>>> list2;
        final int $dirty3;
        Composer $composer3;
        Function2 content$iv;
        Function1 onTextLayout3;
        int $dirty4;
        Intrinsics.checkNotNullParameter(text, "text");
        Composer $composer4 = $composer.startRestartGroup(851408699);
        ComposerKt.sourceInformation($composer4, "C(BasicText)P(8,3,7,4,5:c#ui.text.style.TextOverflow,6,1,2)187@9049L7,188@9088L7,189@9149L7,190@9217L7,212@10305L545,252@11559L270:BasicText.kt#423gt5");
        int $dirty5 = $changed;
        if ((i & 1) != 0) {
            $dirty5 |= 6;
        } else if (($changed & 14) == 0) {
            $dirty5 |= $composer4.changed(text) ? 4 : 2;
        }
        int i3 = i & 2;
        if (i3 != 0) {
            $dirty5 |= 48;
        } else if (($changed & 112) == 0) {
            $dirty5 |= $composer4.changed(modifier) ? 32 : 16;
        }
        int i4 = i & 4;
        if (i4 != 0) {
            $dirty5 |= 384;
        } else if (($changed & 896) == 0) {
            $dirty5 |= $composer4.changed(style) ? 256 : 128;
        }
        int i5 = i & 8;
        if (i5 != 0) {
            $dirty5 |= 3072;
            onTextLayout = function1;
        } else if (($changed & 7168) == 0) {
            onTextLayout = function1;
            $dirty5 |= $composer4.changedInstance(onTextLayout) ? 2048 : 1024;
        } else {
            onTextLayout = function1;
        }
        int i6 = i & 16;
        if (i6 != 0) {
            $dirty5 |= 24576;
            i2 = overflow;
        } else if ((57344 & $changed) == 0) {
            i2 = overflow;
            $dirty5 |= $composer4.changed(i2) ? 16384 : 8192;
        } else {
            i2 = overflow;
        }
        int i7 = i & 32;
        if (i7 != 0) {
            $dirty5 |= ProfileVerifier.CompilationStatus.RESULT_CODE_ERROR_CANT_WRITE_PROFILE_VERIFICATION_RESULT_CACHE_FILE;
        } else if (($changed & 458752) == 0) {
            $dirty5 |= $composer4.changed(softWrap) ? 131072 : 65536;
        }
        int i8 = i & 64;
        if (i8 != 0) {
            $dirty5 |= 1572864;
        } else if (($changed & 3670016) == 0) {
            $dirty5 |= $composer4.changed(maxLines) ? 1048576 : 524288;
        }
        int i9 = i & 128;
        if (i9 != 0) {
            $dirty5 |= 12582912;
        } else if (($changed & 29360128) == 0) {
            $dirty5 |= $composer4.changed(minLines) ? 8388608 : 4194304;
        }
        int i10 = i & 256;
        if (i10 != 0) {
            $dirty5 |= 33554432;
        }
        if (i10 == 256 && (191739611 & $dirty5) == 38347922 && $composer4.getSkipping()) {
            $composer4.skipToGroupEnd();
            modifier2 = modifier;
            style2 = style;
            softWrap2 = softWrap;
            maxLines2 = maxLines;
            minLines2 = minLines;
            inlineContent = map;
            $dirty4 = $dirty5;
            onTextLayout3 = onTextLayout;
            overflow2 = i2;
            $composer3 = $composer4;
        } else {
            Modifier modifier3 = i3 != 0 ? Modifier.Companion : modifier;
            style2 = i4 != 0 ? TextStyle.Companion.getDefault() : style;
            if (i5 != 0) {
                onTextLayout = new Function1<TextLayoutResult, Unit>() { // from class: androidx.compose.foundation.text.BasicTextKt$BasicText$3
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(TextLayoutResult textLayoutResult) {
                        invoke2(textLayoutResult);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke  reason: avoid collision after fix types in other method */
                    public final void invoke2(TextLayoutResult it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                    }
                };
            }
            overflow2 = i6 != 0 ? TextOverflow.Companion.m5041getClipgIe3tQ8() : i2;
            softWrap2 = i7 != 0 ? true : softWrap;
            int maxLines3 = i8 != 0 ? Integer.MAX_VALUE : maxLines;
            int minLines3 = i9 != 0 ? 1 : minLines;
            Map inlineContent2 = i10 != 0 ? MapsKt.emptyMap() : map;
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(851408699, $dirty5, -1, "androidx.compose.foundation.text.BasicText (BasicText.kt:170)");
            }
            HeightInLinesModifierKt.validateMinMaxLines(minLines3, maxLines3);
            ComposerKt.sourceInformationMarkerStart($composer4, 2023513938, "CC:CompositionLocal.kt#9igjgp");
            Object consume = $composer4.consume(SelectionRegistrarKt.getLocalSelectionRegistrar());
            ComposerKt.sourceInformationMarkerEnd($composer4);
            final SelectionRegistrar selectionRegistrar2 = (SelectionRegistrar) consume;
            ComposerKt.sourceInformationMarkerStart($composer4, 2023513938, "CC:CompositionLocal.kt#9igjgp");
            Object consume2 = $composer4.consume(CompositionLocalsKt.getLocalDensity());
            ComposerKt.sourceInformationMarkerEnd($composer4);
            Density density = (Density) consume2;
            ComposerKt.sourceInformationMarkerStart($composer4, 2023513938, "CC:CompositionLocal.kt#9igjgp");
            Object consume3 = $composer4.consume(CompositionLocalsKt.getLocalFontFamilyResolver());
            ComposerKt.sourceInformationMarkerEnd($composer4);
            FontFamily.Resolver fontFamilyResolver = (FontFamily.Resolver) consume3;
            ComposerKt.sourceInformationMarkerStart($composer4, 2023513938, "CC:CompositionLocal.kt#9igjgp");
            Object consume4 = $composer4.consume(TextSelectionColorsKt.getLocalTextSelectionColors());
            ComposerKt.sourceInformationMarkerEnd($composer4);
            Modifier modifier4 = modifier3;
            long selectionBackgroundColor2 = ((TextSelectionColors) consume4).m883getBackgroundColor0d7_KjU();
            Pair<List<AnnotatedString.Range<Placeholder>>, List<AnnotatedString.Range<Function3<String, Composer, Integer, Unit>>>> resolveInlineContent = CoreTextKt.resolveInlineContent(text, inlineContent2);
            List placeholders = resolveInlineContent.component1();
            List<AnnotatedString.Range<Function3<String, Composer, Integer, Unit>>> component2 = resolveInlineContent.component2();
            $composer4.startReplaceableGroup(959243860);
            ComposerKt.sourceInformation($composer4, "207@10126L150");
            if (selectionRegistrar2 == null) {
                longValue = 0;
                $dirty = $dirty5;
            } else {
                $dirty = $dirty5;
                longValue = ((Number) RememberSaveableKt.m2260rememberSaveable(new Object[]{text, selectionRegistrar2}, (Saver<Object, ? extends Object>) selectionIdSaver(selectionRegistrar2), (String) null, (Function0<? extends Object>) new Function0<Long>() { // from class: androidx.compose.foundation.text.BasicTextKt$BasicText$selectableId$2
                    /* JADX INFO: Access modifiers changed from: package-private */
                    {
                        super(0);
                    }

                    /* JADX WARN: Can't rename method to resolve collision */
                    @Override // kotlin.jvm.functions.Function0
                    public final Long invoke() {
                        return Long.valueOf(SelectionRegistrar.this.nextSelectableId());
                    }
                }, $composer4, 72, 4)).longValue();
            }
            $composer4.endReplaceableGroup();
            long selectableId2 = longValue;
            $composer4.startReplaceableGroup(-492369756);
            ComposerKt.sourceInformation($composer4, "CC(remember):Composables.kt#9igjgp");
            Object value$iv$iv = $composer4.rememberedValue();
            if (value$iv$iv == Composer.Companion.getEmpty()) {
                $dirty2 = $dirty;
                $composer2 = $composer4;
                list = component2;
                selectionRegistrar = selectionRegistrar2;
                str = "CC:CompositionLocal.kt#9igjgp";
                selectionBackgroundColor = selectionBackgroundColor2;
                modifier2 = modifier4;
                inlineContent = inlineContent2;
                onTextLayout2 = onTextLayout;
                minLines2 = minLines3;
                maxLines2 = maxLines3;
                selectableId = selectableId2;
                value$iv$iv = new TextController(new TextState(new TextDelegate(text, style2, maxLines3, minLines3, softWrap2, overflow2, density, fontFamilyResolver, placeholders, null), selectableId));
                $composer4.updateRememberedValue(value$iv$iv);
            } else {
                modifier2 = modifier4;
                selectionRegistrar = selectionRegistrar2;
                str = "CC:CompositionLocal.kt#9igjgp";
                selectionBackgroundColor = selectionBackgroundColor2;
                inlineContent = inlineContent2;
                onTextLayout2 = onTextLayout;
                minLines2 = minLines3;
                maxLines2 = maxLines3;
                $dirty2 = $dirty;
                selectableId = selectableId2;
                list = component2;
                $composer2 = $composer4;
            }
            $composer2.endReplaceableGroup();
            TextController controller = (TextController) value$iv$iv;
            TextState state = controller.getState();
            if (!$composer2.getInserting()) {
                controller.setTextDelegate(CoreTextKt.m710updateTextDelegaterm0N8CA(state.getTextDelegate(), text, style2, density, fontFamilyResolver, softWrap2, overflow2, maxLines2, minLines2, placeholders));
            }
            Function1 onTextLayout4 = onTextLayout2;
            state.setOnTextLayout(onTextLayout4);
            state.m799setSelectionBackgroundColor8_81llA(selectionBackgroundColor);
            controller.update(selectionRegistrar);
            if (list.isEmpty()) {
                content$iv = ComposableSingletons$BasicTextKt.INSTANCE.m706getLambda1$foundation_release();
                list2 = list;
                $composer3 = $composer2;
                $dirty3 = $dirty2;
            } else {
                list2 = list;
                $dirty3 = $dirty2;
                $composer3 = $composer2;
                content$iv = ComposableLambdaKt.composableLambda($composer3, 1749415830, true, new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.foundation.text.BasicTextKt$BasicText$4
                    /* JADX INFO: Access modifiers changed from: package-private */
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(2);
                    }

                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(Composer composer, Integer num) {
                        invoke(composer, num.intValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(Composer $composer5, int $changed2) {
                        ComposerKt.sourceInformation($composer5, "C256@11666L39:BasicText.kt#423gt5");
                        if (($changed2 & 11) == 2 && $composer5.getSkipping()) {
                            $composer5.skipToGroupEnd();
                            return;
                        }
                        if (ComposerKt.isTraceInProgress()) {
                            ComposerKt.traceEventStart(1749415830, $changed2, -1, "androidx.compose.foundation.text.BasicText.<anonymous> (BasicText.kt:256)");
                        }
                        CoreTextKt.InlineChildren(AnnotatedString.this, list2, $composer5, ($dirty3 & 14) | 64);
                        if (ComposerKt.isTraceInProgress()) {
                            ComposerKt.traceEventEnd();
                        }
                    }
                });
            }
            Modifier modifier$iv = modifier2.then(controller.getModifiers());
            MeasurePolicy measurePolicy$iv = controller.getMeasurePolicy();
            $composer3.startReplaceableGroup(-1323940314);
            ComposerKt.sourceInformation($composer3, "CC(Layout)P(!1,2)73@2855L7,74@2910L7,75@2969L7,76@2981L460:Layout.kt#80mrfh");
            String str2 = str;
            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, str2);
            Object consume5 = $composer3.consume(CompositionLocalsKt.getLocalDensity());
            ComposerKt.sourceInformationMarkerEnd($composer3);
            Density density$iv = (Density) consume5;
            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, str2);
            Object consume6 = $composer3.consume(CompositionLocalsKt.getLocalLayoutDirection());
            ComposerKt.sourceInformationMarkerEnd($composer3);
            LayoutDirection layoutDirection$iv = (LayoutDirection) consume6;
            ComposerKt.sourceInformationMarkerStart($composer3, 2023513938, str2);
            Object consume7 = $composer3.consume(CompositionLocalsKt.getLocalViewConfiguration());
            ComposerKt.sourceInformationMarkerEnd($composer3);
            ViewConfiguration viewConfiguration$iv = (ViewConfiguration) consume7;
            Function0 factory$iv$iv = ComposeUiNode.Companion.getConstructor();
            Function3 skippableUpdate$iv$iv = LayoutKt.materializerOf(modifier$iv);
            int $changed$iv$iv = ((0 << 9) & 7168) | 6;
            onTextLayout3 = onTextLayout4;
            if (!($composer3.getApplier() instanceof Applier)) {
                ComposablesKt.invalidApplier();
            }
            $composer3.startReusableNode();
            if ($composer3.getInserting()) {
                $composer3.createNode(factory$iv$iv);
            } else {
                $composer3.useNode();
            }
            Composer $this$Layout_u24lambda_u240$iv = Updater.m2247constructorimpl($composer3);
            $dirty4 = $dirty3;
            Updater.m2254setimpl($this$Layout_u24lambda_u240$iv, measurePolicy$iv, ComposeUiNode.Companion.getSetMeasurePolicy());
            Updater.m2254setimpl($this$Layout_u24lambda_u240$iv, density$iv, ComposeUiNode.Companion.getSetDensity());
            Updater.m2254setimpl($this$Layout_u24lambda_u240$iv, layoutDirection$iv, ComposeUiNode.Companion.getSetLayoutDirection());
            Updater.m2254setimpl($this$Layout_u24lambda_u240$iv, viewConfiguration$iv, ComposeUiNode.Companion.getSetViewConfiguration());
            skippableUpdate$iv$iv.invoke(SkippableUpdater.m2238boximpl(SkippableUpdater.m2239constructorimpl($composer3)), $composer3, Integer.valueOf(($changed$iv$iv >> 3) & 112));
            $composer3.startReplaceableGroup(2058660585);
            content$iv.invoke($composer3, Integer.valueOf(($changed$iv$iv >> 9) & 14));
            $composer3.endReplaceableGroup();
            $composer3.endNode();
            $composer3.endReplaceableGroup();
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
        }
        ScopeUpdateScope endRestartGroup = $composer3.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Modifier modifier5 = modifier2;
        final TextStyle textStyle = style2;
        final Function1 function12 = onTextLayout3;
        final int i11 = overflow2;
        final boolean z = softWrap2;
        final int i12 = maxLines2;
        final int i13 = minLines2;
        final Map map2 = inlineContent;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.foundation.text.BasicTextKt$BasicText$5
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
                BasicTextKt.m695BasicTextVhcvRP8(AnnotatedString.this, modifier5, textStyle, function12, i11, z, i12, i13, map2, composer, RecomposeScopeImplKt.updateChangedFlags($changed | 1), i);
            }
        });
    }

    @Deprecated(level = DeprecationLevel.HIDDEN, message = "Maintained for binary compatibility")
    /* renamed from: BasicText-BpD7jsM */
    public static final /* synthetic */ void m694BasicTextBpD7jsM(final String text, Modifier modifier, TextStyle style, Function1 onTextLayout, int overflow, boolean softWrap, int maxLines, Composer $composer, final int $changed, final int i) {
        Object obj;
        Object obj2;
        int i2;
        boolean softWrap2;
        int i3;
        Modifier modifier2;
        TextStyle style2;
        Function1 onTextLayout2;
        int overflow2;
        int maxLines2;
        Intrinsics.checkNotNullParameter(text, "text");
        Composer $composer2 = $composer.startRestartGroup(1022429478);
        ComposerKt.sourceInformation($composer2, "C(BasicText)P(6,1,5,2,3:c#ui.text.style.TextOverflow,4)274@12210L234:BasicText.kt#423gt5");
        int $dirty = $changed;
        if ((i & 1) != 0) {
            $dirty |= 6;
        } else if (($changed & 14) == 0) {
            $dirty |= $composer2.changed(text) ? 4 : 2;
        }
        int i4 = i & 2;
        if (i4 != 0) {
            $dirty |= 48;
        } else if (($changed & 112) == 0) {
            $dirty |= $composer2.changed(modifier) ? 32 : 16;
        }
        int i5 = i & 4;
        if (i5 != 0) {
            $dirty |= 384;
            obj = style;
        } else if (($changed & 896) == 0) {
            obj = style;
            $dirty |= $composer2.changed(obj) ? 256 : 128;
        } else {
            obj = style;
        }
        int i6 = i & 8;
        if (i6 != 0) {
            $dirty |= 3072;
            obj2 = onTextLayout;
        } else if (($changed & 7168) == 0) {
            obj2 = onTextLayout;
            $dirty |= $composer2.changedInstance(obj2) ? 2048 : 1024;
        } else {
            obj2 = onTextLayout;
        }
        int i7 = i & 16;
        if (i7 != 0) {
            $dirty |= 24576;
            i2 = overflow;
        } else if (($changed & 57344) == 0) {
            i2 = overflow;
            $dirty |= $composer2.changed(i2) ? 16384 : 8192;
        } else {
            i2 = overflow;
        }
        int i8 = i & 32;
        if (i8 != 0) {
            $dirty |= ProfileVerifier.CompilationStatus.RESULT_CODE_ERROR_CANT_WRITE_PROFILE_VERIFICATION_RESULT_CACHE_FILE;
            softWrap2 = softWrap;
        } else if (($changed & 458752) == 0) {
            softWrap2 = softWrap;
            $dirty |= $composer2.changed(softWrap2) ? 131072 : 65536;
        } else {
            softWrap2 = softWrap;
        }
        int i9 = i & 64;
        if (i9 != 0) {
            $dirty |= 1572864;
            i3 = maxLines;
        } else if (($changed & 3670016) == 0) {
            i3 = maxLines;
            $dirty |= $composer2.changed(i3) ? 1048576 : 524288;
        } else {
            i3 = maxLines;
        }
        if (($dirty & 2995931) == 599186 && $composer2.getSkipping()) {
            $composer2.skipToGroupEnd();
            modifier2 = modifier;
            style2 = obj;
            onTextLayout2 = obj2;
            maxLines2 = i3;
            overflow2 = i2;
        } else {
            modifier2 = i4 != 0 ? Modifier.Companion : modifier;
            style2 = i5 != 0 ? TextStyle.Companion.getDefault() : obj;
            onTextLayout2 = i6 != 0 ? new Function1<TextLayoutResult, Unit>() { // from class: androidx.compose.foundation.text.BasicTextKt$BasicText$6
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(TextLayoutResult textLayoutResult) {
                    invoke2(textLayoutResult);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2(TextLayoutResult it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            } : obj2;
            overflow2 = i7 != 0 ? TextOverflow.Companion.m5041getClipgIe3tQ8() : i2;
            if (i8 != 0) {
                softWrap2 = true;
            }
            maxLines2 = i9 != 0 ? Integer.MAX_VALUE : i3;
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(1022429478, $dirty, -1, "androidx.compose.foundation.text.BasicText (BasicText.kt:265)");
            }
            m693BasicText4YKlhWE(text, modifier2, style2, onTextLayout2, overflow2, softWrap2, maxLines2, 1, $composer2, 12582912 | ($dirty & 14) | ($dirty & 112) | ($dirty & 896) | ($dirty & 7168) | (57344 & $dirty) | (458752 & $dirty) | ($dirty & 3670016), 0);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Modifier modifier3 = modifier2;
        final TextStyle textStyle = style2;
        final Function1 function1 = onTextLayout2;
        final int i10 = overflow2;
        final boolean z = softWrap2;
        final int i11 = maxLines2;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.foundation.text.BasicTextKt$BasicText$7
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

            public final void invoke(Composer composer, int i12) {
                BasicTextKt.m694BasicTextBpD7jsM(text, modifier3, textStyle, function1, i10, z, i11, composer, RecomposeScopeImplKt.updateChangedFlags($changed | 1), i);
            }
        });
    }

    @Deprecated(level = DeprecationLevel.HIDDEN, message = "Maintained for binary compatibility")
    /* renamed from: BasicText-4YKlhWE */
    public static final /* synthetic */ void m692BasicText4YKlhWE(final AnnotatedString text, Modifier modifier, TextStyle style, Function1 onTextLayout, int overflow, boolean softWrap, int maxLines, Map inlineContent, Composer $composer, final int $changed, final int i) {
        Object obj;
        Object obj2;
        int i2;
        boolean z;
        Modifier modifier2;
        TextStyle style2;
        Function1 onTextLayout2;
        int overflow2;
        boolean softWrap2;
        int maxLines2;
        Map inlineContent2;
        Intrinsics.checkNotNullParameter(text, "text");
        Composer $composer2 = $composer.startRestartGroup(-648605928);
        ComposerKt.sourceInformation($composer2, "C(BasicText)P(7,2,6,3,4:c#ui.text.style.TextOverflow,5,1)298@12896L273:BasicText.kt#423gt5");
        int $dirty = $changed;
        if ((i & 1) != 0) {
            $dirty |= 6;
        } else if (($changed & 14) == 0) {
            $dirty |= $composer2.changed(text) ? 4 : 2;
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
            obj = style;
        } else if (($changed & 896) == 0) {
            obj = style;
            $dirty |= $composer2.changed(obj) ? 256 : 128;
        } else {
            obj = style;
        }
        int i5 = i & 8;
        if (i5 != 0) {
            $dirty |= 3072;
            obj2 = onTextLayout;
        } else if (($changed & 7168) == 0) {
            obj2 = onTextLayout;
            $dirty |= $composer2.changedInstance(obj2) ? 2048 : 1024;
        } else {
            obj2 = onTextLayout;
        }
        int i6 = i & 16;
        if (i6 != 0) {
            $dirty |= 24576;
            i2 = overflow;
        } else if (($changed & 57344) == 0) {
            i2 = overflow;
            $dirty |= $composer2.changed(i2) ? 16384 : 8192;
        } else {
            i2 = overflow;
        }
        int i7 = i & 32;
        if (i7 != 0) {
            $dirty |= ProfileVerifier.CompilationStatus.RESULT_CODE_ERROR_CANT_WRITE_PROFILE_VERIFICATION_RESULT_CACHE_FILE;
            z = softWrap;
        } else if (($changed & 458752) == 0) {
            z = softWrap;
            $dirty |= $composer2.changed(z) ? 131072 : 65536;
        } else {
            z = softWrap;
        }
        int i8 = i & 64;
        if (i8 != 0) {
            $dirty |= 1572864;
        } else if (($changed & 3670016) == 0) {
            $dirty |= $composer2.changed(maxLines) ? 1048576 : 524288;
        }
        int i9 = i & 128;
        if (i9 != 0) {
            $dirty |= 4194304;
        }
        if (i9 == 128 && (23967451 & $dirty) == 4793490 && $composer2.getSkipping()) {
            $composer2.skipToGroupEnd();
            modifier2 = modifier;
            maxLines2 = maxLines;
            inlineContent2 = inlineContent;
            style2 = obj;
            onTextLayout2 = obj2;
            softWrap2 = z;
            overflow2 = i2;
        } else {
            modifier2 = i3 != 0 ? Modifier.Companion : modifier;
            style2 = i4 != 0 ? TextStyle.Companion.getDefault() : obj;
            onTextLayout2 = i5 != 0 ? new Function1<TextLayoutResult, Unit>() { // from class: androidx.compose.foundation.text.BasicTextKt$BasicText$8
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(TextLayoutResult textLayoutResult) {
                    invoke2(textLayoutResult);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2(TextLayoutResult it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            } : obj2;
            overflow2 = i6 != 0 ? TextOverflow.Companion.m5041getClipgIe3tQ8() : i2;
            softWrap2 = i7 != 0 ? true : z;
            maxLines2 = i8 != 0 ? Integer.MAX_VALUE : maxLines;
            inlineContent2 = i9 != 0 ? MapsKt.emptyMap() : inlineContent;
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventStart(-648605928, $dirty, -1, "androidx.compose.foundation.text.BasicText (BasicText.kt:288)");
            }
            m695BasicTextVhcvRP8(text, modifier2, style2, onTextLayout2, overflow2, softWrap2, maxLines2, 1, inlineContent2, $composer2, 146800640 | ($dirty & 14) | ($dirty & 112) | ($dirty & 896) | ($dirty & 7168) | (57344 & $dirty) | ($dirty & 458752) | ($dirty & 3670016), 0);
            if (ComposerKt.isTraceInProgress()) {
                ComposerKt.traceEventEnd();
            }
        }
        ScopeUpdateScope endRestartGroup = $composer2.endRestartGroup();
        if (endRestartGroup == null) {
            return;
        }
        final Modifier modifier3 = modifier2;
        final TextStyle textStyle = style2;
        final Function1 function1 = onTextLayout2;
        final int i10 = overflow2;
        final boolean z2 = softWrap2;
        final int i11 = maxLines2;
        final Map map = inlineContent2;
        endRestartGroup.updateScope(new Function2<Composer, Integer, Unit>() { // from class: androidx.compose.foundation.text.BasicTextKt$BasicText$9
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

            public final void invoke(Composer composer, int i12) {
                BasicTextKt.m692BasicText4YKlhWE(AnnotatedString.this, modifier3, textStyle, function1, i10, z2, i11, map, composer, RecomposeScopeImplKt.updateChangedFlags($changed | 1), i);
            }
        });
    }

    private static final Saver<Long, Long> selectionIdSaver(final SelectionRegistrar selectionRegistrar) {
        return SaverKt.Saver(new Function2<SaverScope, Long, Long>() { // from class: androidx.compose.foundation.text.BasicTextKt$selectionIdSaver$1
            /* JADX INFO: Access modifiers changed from: package-private */
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Long invoke(SaverScope saverScope, Long l) {
                return invoke(saverScope, l.longValue());
            }

            public final Long invoke(SaverScope Saver, long it) {
                Intrinsics.checkNotNullParameter(Saver, "$this$Saver");
                if (SelectionRegistrarKt.hasSelection(SelectionRegistrar.this, it)) {
                    return Long.valueOf(it);
                }
                return null;
            }
        }, new Function1<Long, Long>() { // from class: androidx.compose.foundation.text.BasicTextKt$selectionIdSaver$2
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Long invoke(Long l) {
                return invoke(l.longValue());
            }

            public final Long invoke(long it) {
                return Long.valueOf(it);
            }
        });
    }
}
