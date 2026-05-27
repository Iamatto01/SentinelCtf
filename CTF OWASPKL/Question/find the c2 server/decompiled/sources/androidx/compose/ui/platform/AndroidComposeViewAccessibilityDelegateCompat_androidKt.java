package androidx.compose.ui.platform;

import android.graphics.Region;
import androidx.compose.ui.geometry.Rect;
import androidx.compose.ui.layout.LayoutInfo;
import androidx.compose.ui.node.LayoutNode;
import androidx.compose.ui.node.SemanticsModifierNode;
import androidx.compose.ui.node.SemanticsModifierNodeKt;
import androidx.compose.ui.platform.AndroidComposeViewAccessibilityDelegateCompat;
import androidx.compose.ui.semantics.AccessibilityAction;
import androidx.compose.ui.semantics.SemanticsActions;
import androidx.compose.ui.semantics.SemanticsConfiguration;
import androidx.compose.ui.semantics.SemanticsConfigurationKt;
import androidx.compose.ui.semantics.SemanticsNode;
import androidx.compose.ui.semantics.SemanticsNodeKt;
import androidx.compose.ui.semantics.SemanticsOwner;
import androidx.compose.ui.semantics.SemanticsProperties;
import androidx.compose.ui.semantics.SemanticsPropertyKey;
import androidx.compose.ui.unit.LayoutDirection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.math.MathKt;
/* compiled from: AndroidComposeViewAccessibilityDelegateCompat.android.kt */
@Metadata(d1 = {"\u0000\\\n\u0000\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a\u001a\u0010\u0010\u001a\u00020\u0001*\u0006\u0012\u0002\b\u00030\u00112\b\u0010\u0012\u001a\u0004\u0018\u00010\u0013H\u0002\u001a\f\u0010\u0014\u001a\u00020\u0001*\u00020\u0002H\u0002\u001a\f\u0010\u0015\u001a\u00020\u0001*\u00020\u0002H\u0002\u001a\u001c\u0010\u0016\u001a\u0004\u0018\u00010\u0017*\b\u0012\u0004\u0012\u00020\u00170\u00182\u0006\u0010\u0019\u001a\u00020\u001aH\u0000\u001a\"\u0010\u001b\u001a\u0004\u0018\u00010\u001c*\u00020\u001c2\u0012\u0010\u001d\u001a\u000e\u0012\u0004\u0012\u00020\u001c\u0012\u0004\u0012\u00020\u00010\u001eH\u0002\u001a\u0018\u0010\u001f\u001a\u000e\u0012\u0004\u0012\u00020\u001a\u0012\u0004\u0012\u00020!0 *\u00020\"H\u0000\u001a\f\u0010#\u001a\u00020\u0001*\u00020\u0002H\u0002\u001a \u0010$\u001a\u00020\u0001*\b\u0012\u0004\u0012\u00020&0%2\f\u0010'\u001a\b\u0012\u0004\u0012\u00020&0%H\u0002\u001a\u0014\u0010(\u001a\u00020\u0001*\u00020\u00022\u0006\u0010)\u001a\u00020*H\u0002\u001a\u001b\u0010+\u001a\b\u0012\u0004\u0012\u00020&0%*\u00020&2\u0006\u0010,\u001a\u00020&H\u0080\u0002\"\u0018\u0010\u0000\u001a\u00020\u0001*\u00020\u00028BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u0003\u0010\u0004\"\u001a\u0010\u0005\u001a\u0004\u0018\u00010\u0001*\u00020\u00028BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u0005\u0010\u0006\"\u0018\u0010\u0007\u001a\u00020\u0001*\u00020\u00028BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u0007\u0010\u0004\"\u0018\u0010\b\u001a\u00020\u0001*\u00020\u00028BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\b\u0010\u0004\"\u0018\u0010\t\u001a\u00020\u0001*\u00020\u00028BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\t\u0010\u0004\"\u0018\u0010\n\u001a\u00020\u0001*\u00020\u00028BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\n\u0010\u0004\"\u001e\u0010\u000b\u001a\u00020\u0001*\u00020\u00028BX\u0082\u0004¢\u0006\f\u0012\u0004\b\f\u0010\r\u001a\u0004\b\u000b\u0010\u0004\"\u0018\u0010\u000e\u001a\u00020\u0001*\u00020\u00028BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u000f\u0010\u0004¨\u0006-"}, d2 = {"hasCollectionInfo", "", "Landroidx/compose/ui/semantics/SemanticsNode;", "getHasCollectionInfo", "(Landroidx/compose/ui/semantics/SemanticsNode;)Z", "isContainer", "(Landroidx/compose/ui/semantics/SemanticsNode;)Ljava/lang/Boolean;", "isPassword", "isRtl", "isScrollable", "isTextField", "isVisible", "isVisible$annotations", "(Landroidx/compose/ui/semantics/SemanticsNode;)V", "semanticsNodeIsStructurallySignificant", "getSemanticsNodeIsStructurallySignificant", "accessibilityEquals", "Landroidx/compose/ui/semantics/AccessibilityAction;", "other", "", "enabled", "excludeLineAndPageGranularities", "findById", "Landroidx/compose/ui/platform/ScrollObservationScope;", "", "id", "", "findClosestParentNode", "Landroidx/compose/ui/node/LayoutNode;", "selector", "Lkotlin/Function1;", "getAllUncoveredSemanticsNodesToMap", "", "Landroidx/compose/ui/platform/SemanticsNodeWithAdjustedBounds;", "Landroidx/compose/ui/semantics/SemanticsOwner;", "hasPaneTitle", "overlaps", "Landroidx/compose/ui/platform/OpenEndRange;", "", "it", "propertiesDeleted", "oldNode", "Landroidx/compose/ui/platform/AndroidComposeViewAccessibilityDelegateCompat$SemanticsNodeCopy;", "rangeUntil", "that", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class AndroidComposeViewAccessibilityDelegateCompat_androidKt {
    private static /* synthetic */ void isVisible$annotations(SemanticsNode semanticsNode) {
    }

    public static final OpenEndRange<Float> rangeUntil(float $this$rangeUntil, float that) {
        return new OpenEndFloatRange($this$rangeUntil, that);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean overlaps(OpenEndRange<Float> openEndRange, OpenEndRange<Float> openEndRange2) {
        return (openEndRange.isEmpty() || openEndRange2.isEmpty() || Math.max(openEndRange.getStart().floatValue(), openEndRange2.getStart().floatValue()) >= Math.min(openEndRange.getEndExclusive().floatValue(), openEndRange2.getEndExclusive().floatValue())) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final LayoutNode findClosestParentNode(LayoutNode $this$findClosestParentNode, Function1<? super LayoutNode, Boolean> function1) {
        for (LayoutNode currentParent = $this$findClosestParentNode.getParent$ui_release(); currentParent != null; currentParent = currentParent.getParent$ui_release()) {
            if (function1.invoke(currentParent).booleanValue()) {
                return currentParent;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean enabled(SemanticsNode $this$enabled) {
        return SemanticsConfigurationKt.getOrNull($this$enabled.getConfig(), SemanticsProperties.INSTANCE.getDisabled()) == null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean isVisible(SemanticsNode $this$isVisible) {
        return ($this$isVisible.isTransparent$ui_release() || $this$isVisible.getUnmergedConfig$ui_release().contains(SemanticsProperties.INSTANCE.getInvisibleToUser())) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean propertiesDeleted(SemanticsNode $this$propertiesDeleted, AndroidComposeViewAccessibilityDelegateCompat.SemanticsNodeCopy oldNode) {
        Iterator<Map.Entry<? extends SemanticsPropertyKey<?>, ? extends Object>> it = oldNode.getUnmergedConfig().iterator();
        while (it.hasNext()) {
            Map.Entry entry = it.next();
            if (!$this$propertiesDeleted.getConfig().contains(entry.getKey())) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean hasPaneTitle(SemanticsNode $this$hasPaneTitle) {
        return $this$hasPaneTitle.getConfig().contains(SemanticsProperties.INSTANCE.getPaneTitle());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean isPassword(SemanticsNode $this$isPassword) {
        return $this$isPassword.getConfig().contains(SemanticsProperties.INSTANCE.getPassword());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean isTextField(SemanticsNode $this$isTextField) {
        return $this$isTextField.getUnmergedConfig$ui_release().contains(SemanticsActions.INSTANCE.getSetText());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean isRtl(SemanticsNode $this$isRtl) {
        return $this$isRtl.getLayoutInfo().getLayoutDirection() == LayoutDirection.Rtl;
    }

    private static final Boolean isContainer(SemanticsNode $this$isContainer) {
        return (Boolean) SemanticsConfigurationKt.getOrNull($this$isContainer.getConfig(), SemanticsProperties.INSTANCE.getIsContainer());
    }

    private static final boolean getHasCollectionInfo(SemanticsNode $this$hasCollectionInfo) {
        return $this$hasCollectionInfo.getConfig().contains(SemanticsProperties.INSTANCE.getCollectionInfo());
    }

    private static final boolean isScrollable(SemanticsNode $this$isScrollable) {
        return $this$isScrollable.getConfig().contains(SemanticsActions.INSTANCE.getScrollBy());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean getSemanticsNodeIsStructurallySignificant(SemanticsNode $this$semanticsNodeIsStructurallySignificant) {
        if (Intrinsics.areEqual((Object) isContainer($this$semanticsNodeIsStructurallySignificant), (Object) false)) {
            return false;
        }
        return Intrinsics.areEqual((Object) isContainer($this$semanticsNodeIsStructurallySignificant), (Object) true) || getHasCollectionInfo($this$semanticsNodeIsStructurallySignificant) || isScrollable($this$semanticsNodeIsStructurallySignificant);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean excludeLineAndPageGranularities(SemanticsNode $this$excludeLineAndPageGranularities) {
        boolean z;
        SemanticsConfiguration collapsedSemanticsConfiguration;
        if (!isTextField($this$excludeLineAndPageGranularities) || Intrinsics.areEqual(SemanticsConfigurationKt.getOrNull($this$excludeLineAndPageGranularities.getUnmergedConfig$ui_release(), SemanticsProperties.INSTANCE.getFocused()), (Object) true)) {
            LayoutNode ancestor = findClosestParentNode($this$excludeLineAndPageGranularities.getLayoutNode$ui_release(), new Function1<LayoutNode, Boolean>() { // from class: androidx.compose.ui.platform.AndroidComposeViewAccessibilityDelegateCompat_androidKt$excludeLineAndPageGranularities$ancestor$1
                @Override // kotlin.jvm.functions.Function1
                public final Boolean invoke(LayoutNode it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                    SemanticsModifierNode outerSemantics = SemanticsNodeKt.getOuterSemantics(it);
                    SemanticsConfiguration ancestorSemanticsConfiguration = outerSemantics != null ? SemanticsModifierNodeKt.collapsedSemanticsConfiguration(outerSemantics) : null;
                    boolean z2 = true;
                    if (!(ancestorSemanticsConfiguration != null && ancestorSemanticsConfiguration.isMergingSemanticsOfDescendants()) || !ancestorSemanticsConfiguration.contains(SemanticsActions.INSTANCE.getSetText())) {
                        z2 = false;
                    }
                    return Boolean.valueOf(z2);
                }
            });
            if (ancestor != null) {
                SemanticsModifierNode outerSemantics = SemanticsNodeKt.getOuterSemantics(ancestor);
                if (outerSemantics == null || (collapsedSemanticsConfiguration = SemanticsModifierNodeKt.collapsedSemanticsConfiguration(outerSemantics)) == null) {
                    z = false;
                } else {
                    z = Intrinsics.areEqual(SemanticsConfigurationKt.getOrNull(collapsedSemanticsConfiguration, SemanticsProperties.INSTANCE.getFocused()), (Object) true);
                }
                if (!z) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean accessibilityEquals(AccessibilityAction<?> accessibilityAction, Object other) {
        if (accessibilityAction == other) {
            return true;
        }
        if ((other instanceof AccessibilityAction) && Intrinsics.areEqual(accessibilityAction.getLabel(), ((AccessibilityAction) other).getLabel())) {
            if (accessibilityAction.getAction() != null || ((AccessibilityAction) other).getAction() == null) {
                return accessibilityAction.getAction() == null || ((AccessibilityAction) other).getAction() != null;
            }
            return false;
        }
        return false;
    }

    public static final Map<Integer, SemanticsNodeWithAdjustedBounds> getAllUncoveredSemanticsNodesToMap(SemanticsOwner $this$getAllUncoveredSemanticsNodesToMap) {
        Intrinsics.checkNotNullParameter($this$getAllUncoveredSemanticsNodesToMap, "<this>");
        SemanticsNode root = $this$getAllUncoveredSemanticsNodesToMap.getUnmergedRootSemanticsNode();
        Map nodes = new LinkedHashMap();
        if (!root.getLayoutNode$ui_release().isPlaced() || !root.getLayoutNode$ui_release().isAttached()) {
            return nodes;
        }
        Region unaccountedSpace = new Region();
        Rect $this$getAllUncoveredSemanticsNodesToMap_u24lambda_u241_u24lambda_u240 = root.getBoundsInRoot();
        unaccountedSpace.set(new android.graphics.Rect(MathKt.roundToInt($this$getAllUncoveredSemanticsNodesToMap_u24lambda_u241_u24lambda_u240.getLeft()), MathKt.roundToInt($this$getAllUncoveredSemanticsNodesToMap_u24lambda_u241_u24lambda_u240.getTop()), MathKt.roundToInt($this$getAllUncoveredSemanticsNodesToMap_u24lambda_u241_u24lambda_u240.getRight()), MathKt.roundToInt($this$getAllUncoveredSemanticsNodesToMap_u24lambda_u241_u24lambda_u240.getBottom())));
        getAllUncoveredSemanticsNodesToMap$findAllSemanticNodesRecursive(unaccountedSpace, root, nodes, root);
        return nodes;
    }

    private static final void getAllUncoveredSemanticsNodesToMap$findAllSemanticNodesRecursive(Region unaccountedSpace, SemanticsNode root, Map<Integer, SemanticsNodeWithAdjustedBounds> map, SemanticsNode currentNode) {
        int virtualViewId;
        Rect boundsForFakeNode;
        LayoutInfo layoutInfo;
        boolean z = false;
        boolean notAttachedOrPlaced = (currentNode.getLayoutNode$ui_release().isPlaced() && currentNode.getLayoutNode$ui_release().isAttached()) ? false : true;
        if (!unaccountedSpace.isEmpty() || currentNode.getId() == root.getId()) {
            if (notAttachedOrPlaced && !currentNode.isFake$ui_release()) {
                return;
            }
            android.graphics.Rect boundsInRoot = new android.graphics.Rect(MathKt.roundToInt(currentNode.getTouchBoundsInRoot().getLeft()), MathKt.roundToInt(currentNode.getTouchBoundsInRoot().getTop()), MathKt.roundToInt(currentNode.getTouchBoundsInRoot().getRight()), MathKt.roundToInt(currentNode.getTouchBoundsInRoot().getBottom()));
            Region region = new Region();
            region.set(boundsInRoot);
            if (currentNode.getId() == root.getId()) {
                virtualViewId = -1;
            } else {
                virtualViewId = currentNode.getId();
            }
            if (region.op(unaccountedSpace, region, Region.Op.INTERSECT)) {
                Integer valueOf = Integer.valueOf(virtualViewId);
                android.graphics.Rect bounds = region.getBounds();
                Intrinsics.checkNotNullExpressionValue(bounds, "region.bounds");
                map.put(valueOf, new SemanticsNodeWithAdjustedBounds(currentNode, bounds));
                List children = currentNode.getReplacedChildren$ui_release();
                for (int i = children.size() - 1; -1 < i; i--) {
                    getAllUncoveredSemanticsNodesToMap$findAllSemanticNodesRecursive(unaccountedSpace, root, map, children.get(i));
                }
                unaccountedSpace.op(boundsInRoot, unaccountedSpace, Region.Op.REVERSE_DIFFERENCE);
            } else if (currentNode.isFake$ui_release()) {
                SemanticsNode parentNode = currentNode.getParent();
                if (parentNode != null && (layoutInfo = parentNode.getLayoutInfo()) != null && layoutInfo.isPlaced()) {
                    z = true;
                }
                if (z) {
                    boundsForFakeNode = parentNode.getBoundsInRoot();
                } else {
                    boundsForFakeNode = new Rect(0.0f, 0.0f, 10.0f, 10.0f);
                }
                map.put(Integer.valueOf(virtualViewId), new SemanticsNodeWithAdjustedBounds(currentNode, new android.graphics.Rect(MathKt.roundToInt(boundsForFakeNode.getLeft()), MathKt.roundToInt(boundsForFakeNode.getTop()), MathKt.roundToInt(boundsForFakeNode.getRight()), MathKt.roundToInt(boundsForFakeNode.getBottom()))));
            } else if (virtualViewId == -1) {
                Integer valueOf2 = Integer.valueOf(virtualViewId);
                android.graphics.Rect bounds2 = region.getBounds();
                Intrinsics.checkNotNullExpressionValue(bounds2, "region.bounds");
                map.put(valueOf2, new SemanticsNodeWithAdjustedBounds(currentNode, bounds2));
            }
        }
    }

    public static final ScrollObservationScope findById(List<ScrollObservationScope> list, int id) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        int size = list.size();
        for (int index = 0; index < size; index++) {
            if (list.get(index).getSemanticsNodeId() == id) {
                return list.get(index);
            }
        }
        return null;
    }
}
