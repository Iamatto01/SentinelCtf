package androidx.compose.material3;

import androidx.compose.animation.SingleValueAnimationKt;
import androidx.compose.animation.core.AnimationSpecKt;
import androidx.compose.runtime.Composer;
import androidx.compose.runtime.ComposerKt;
import androidx.compose.runtime.State;
import androidx.compose.ui.graphics.Color;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
/* compiled from: NavigationRail.kt */
@Metadata(d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\b\u0007\u0018\u00002\u00020\u0001B2\b\u0000\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0003\u0012\u0006\u0010\u0007\u001a\u00020\u0003ø\u0001\u0000¢\u0006\u0002\u0010\bJ\u0013\u0010\r\u001a\u00020\u000e2\b\u0010\u000f\u001a\u0004\u0018\u00010\u0001H\u0096\u0002J\b\u0010\u0010\u001a\u00020\u0011H\u0016J \u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00030\u00132\u0006\u0010\u0014\u001a\u00020\u000eH\u0001ø\u0001\u0000¢\u0006\u0004\b\u0015\u0010\u0016J \u0010\u0017\u001a\b\u0012\u0004\u0012\u00020\u00030\u00132\u0006\u0010\u0014\u001a\u00020\u000eH\u0001ø\u0001\u0000¢\u0006\u0004\b\u0018\u0010\u0016R\u001d\u0010\t\u001a\u00020\u00038AX\u0080\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0006\u001a\u0004\b\n\u0010\u000bR\u0019\u0010\u0002\u001a\u00020\u0003X\u0082\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\n\u0002\u0010\fR\u0019\u0010\u0005\u001a\u00020\u0003X\u0082\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\n\u0002\u0010\fR\u0019\u0010\u0004\u001a\u00020\u0003X\u0082\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\n\u0002\u0010\fR\u0019\u0010\u0006\u001a\u00020\u0003X\u0082\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\n\u0002\u0010\fR\u0019\u0010\u0007\u001a\u00020\u0003X\u0082\u0004ø\u0001\u0000ø\u0001\u0001ø\u0001\u0002¢\u0006\u0004\n\u0002\u0010\f\u0082\u0002\u000f\n\u0002\b\u0019\n\u0005\b¡\u001e0\u0001\n\u0002\b!¨\u0006\u0019"}, d2 = {"Landroidx/compose/material3/NavigationRailItemColors;", "", "selectedIconColor", "Landroidx/compose/ui/graphics/Color;", "selectedTextColor", "selectedIndicatorColor", "unselectedIconColor", "unselectedTextColor", "(JJJJJLkotlin/jvm/internal/DefaultConstructorMarker;)V", "indicatorColor", "getIndicatorColor", "(Landroidx/compose/runtime/Composer;I)J", "J", "equals", "", "other", "hashCode", "", "iconColor", "Landroidx/compose/runtime/State;", "selected", "iconColor$material3_release", "(ZLandroidx/compose/runtime/Composer;I)Landroidx/compose/runtime/State;", "textColor", "textColor$material3_release", "material3_release"}, k = 1, mv = {1, 7, 1}, xi = 48)
/* loaded from: classes.dex */
public final class NavigationRailItemColors {
    private final long selectedIconColor;
    private final long selectedIndicatorColor;
    private final long selectedTextColor;
    private final long unselectedIconColor;
    private final long unselectedTextColor;

    public /* synthetic */ NavigationRailItemColors(long j, long j2, long j3, long j4, long j5, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, j2, j3, j4, j5);
    }

    private NavigationRailItemColors(long selectedIconColor, long selectedTextColor, long selectedIndicatorColor, long unselectedIconColor, long unselectedTextColor) {
        this.selectedIconColor = selectedIconColor;
        this.selectedTextColor = selectedTextColor;
        this.selectedIndicatorColor = selectedIndicatorColor;
        this.unselectedIconColor = unselectedIconColor;
        this.unselectedTextColor = unselectedTextColor;
    }

    public final State<Color> iconColor$material3_release(boolean selected, Composer $composer, int $changed) {
        $composer.startReplaceableGroup(665215869);
        ComposerKt.sourceInformation($composer, "C(iconColor)319@13836L177:NavigationRail.kt#uh7d8r");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(665215869, $changed, -1, "androidx.compose.material3.NavigationRailItemColors.iconColor (NavigationRail.kt:318)");
        }
        State<Color> m67animateColorAsStateKTwxG1Y = SingleValueAnimationKt.m67animateColorAsStateKTwxG1Y(selected ? this.selectedIconColor : this.unselectedIconColor, AnimationSpecKt.tween$default(150, 0, null, 6, null), null, $composer, 48, 4);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return m67animateColorAsStateKTwxG1Y;
    }

    public final State<Color> textColor$material3_release(boolean selected, Composer $composer, int $changed) {
        $composer.startReplaceableGroup(253888561);
        ComposerKt.sourceInformation($composer, "C(textColor)332@14276L177:NavigationRail.kt#uh7d8r");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(253888561, $changed, -1, "androidx.compose.material3.NavigationRailItemColors.textColor (NavigationRail.kt:331)");
        }
        State<Color> m67animateColorAsStateKTwxG1Y = SingleValueAnimationKt.m67animateColorAsStateKTwxG1Y(selected ? this.selectedTextColor : this.unselectedTextColor, AnimationSpecKt.tween$default(150, 0, null, 6, null), null, $composer, 48, 4);
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return m67animateColorAsStateKTwxG1Y;
    }

    public final long getIndicatorColor(Composer $composer, int $changed) {
        $composer.startReplaceableGroup(618271448);
        ComposerKt.sourceInformation($composer, "C:NavigationRail.kt#uh7d8r");
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventStart(618271448, $changed, -1, "androidx.compose.material3.NavigationRailItemColors.<get-indicatorColor> (NavigationRail.kt:341)");
        }
        long j = this.selectedIndicatorColor;
        if (ComposerKt.isTraceInProgress()) {
            ComposerKt.traceEventEnd();
        }
        $composer.endReplaceableGroup();
        return j;
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other != null && (other instanceof NavigationRailItemColors) && Color.m2607equalsimpl0(this.selectedIconColor, ((NavigationRailItemColors) other).selectedIconColor) && Color.m2607equalsimpl0(this.unselectedIconColor, ((NavigationRailItemColors) other).unselectedIconColor) && Color.m2607equalsimpl0(this.selectedTextColor, ((NavigationRailItemColors) other).selectedTextColor) && Color.m2607equalsimpl0(this.unselectedTextColor, ((NavigationRailItemColors) other).unselectedTextColor) && Color.m2607equalsimpl0(this.selectedIndicatorColor, ((NavigationRailItemColors) other).selectedIndicatorColor)) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        int result = Color.m2613hashCodeimpl(this.selectedIconColor);
        return (((((((result * 31) + Color.m2613hashCodeimpl(this.unselectedIconColor)) * 31) + Color.m2613hashCodeimpl(this.selectedTextColor)) * 31) + Color.m2613hashCodeimpl(this.unselectedTextColor)) * 31) + Color.m2613hashCodeimpl(this.selectedIndicatorColor);
    }
}
