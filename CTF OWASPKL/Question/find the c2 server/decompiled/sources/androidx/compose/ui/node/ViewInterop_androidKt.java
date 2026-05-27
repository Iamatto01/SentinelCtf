package androidx.compose.ui.node;

import android.view.View;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: ViewInterop.android.kt */
@Metadata(d1 = {"\u0000.\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a\u0010\u0010\u0002\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0004H\u0000\u001a1\u0010\u0005\u001a\u0002H\u0006\"\b\b\u0000\u0010\u0006*\u00020\u0007*\u00020\b2\u0006\u0010\t\u001a\u00020\u00012\f\u0010\n\u001a\b\u0012\u0004\u0012\u0002H\u00060\u000bH\u0007¢\u0006\u0002\u0010\f\u001a\f\u0010\r\u001a\u00020\u000e*\u00020\bH\u0000\u001a\u000e\u0010\u000f\u001a\u0004\u0018\u00010\u000e*\u00020\bH\u0000\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0010"}, d2 = {"viewAdaptersKey", "", "tagKey", "key", "", "getOrAddAdapter", "T", "Landroidx/compose/ui/node/ViewAdapter;", "Landroid/view/View;", "id", "factory", "Lkotlin/Function0;", "(Landroid/view/View;ILkotlin/jvm/functions/Function0;)Landroidx/compose/ui/node/ViewAdapter;", "getViewAdapter", "Landroidx/compose/ui/node/MergedViewAdapter;", "getViewAdapterIfExists", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ViewInterop_androidKt {
    private static final int viewAdaptersKey = tagKey("ViewAdapter");

    public static final <T extends ViewAdapter> T getOrAddAdapter(View $this$getOrAddAdapter, int id, Function0<? extends T> factory) {
        Object it$iv$iv;
        Intrinsics.checkNotNullParameter($this$getOrAddAdapter, "<this>");
        Intrinsics.checkNotNullParameter(factory, "factory");
        MergedViewAdapter this_$iv = getViewAdapter($this$getOrAddAdapter);
        List $this$fastFirstOrNull$iv$iv = this_$iv.getAdapters();
        int index$iv$iv$iv = 0;
        int size = $this$fastFirstOrNull$iv$iv.size();
        while (true) {
            if (index$iv$iv$iv < size) {
                it$iv$iv = $this$fastFirstOrNull$iv$iv.get(index$iv$iv$iv);
                ViewAdapter it$iv = (ViewAdapter) it$iv$iv;
                if (it$iv.getId() == id) {
                    break;
                }
                index$iv$iv$iv++;
            } else {
                it$iv$iv = null;
                break;
            }
        }
        T t = (T) (it$iv$iv instanceof ViewAdapter ? (ViewAdapter) it$iv$iv : null);
        if (t != null) {
            return t;
        }
        T invoke = factory.invoke();
        this_$iv.getAdapters().add(invoke);
        return invoke;
    }

    public static final int tagKey(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        return 50331648 | key.hashCode();
    }

    public static final MergedViewAdapter getViewAdapterIfExists(View $this$getViewAdapterIfExists) {
        Intrinsics.checkNotNullParameter($this$getViewAdapterIfExists, "<this>");
        Object tag = $this$getViewAdapterIfExists.getTag(viewAdaptersKey);
        if (tag instanceof MergedViewAdapter) {
            return (MergedViewAdapter) tag;
        }
        return null;
    }

    public static final MergedViewAdapter getViewAdapter(View $this$getViewAdapter) {
        Intrinsics.checkNotNullParameter($this$getViewAdapter, "<this>");
        int i = viewAdaptersKey;
        Object tag = $this$getViewAdapter.getTag(i);
        MergedViewAdapter adapter = tag instanceof MergedViewAdapter ? (MergedViewAdapter) tag : null;
        if (adapter == null) {
            MergedViewAdapter adapter2 = new MergedViewAdapter();
            $this$getViewAdapter.setTag(i, adapter2);
            return adapter2;
        }
        return adapter;
    }
}
