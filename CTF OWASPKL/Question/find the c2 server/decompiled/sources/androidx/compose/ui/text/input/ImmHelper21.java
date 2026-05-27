package androidx.compose.ui.text.input;

import android.view.View;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: InputMethodManager.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0002\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0010\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\bH\u0017J\u0010\u0010\t\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\bH\u0017R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\n"}, d2 = {"Landroidx/compose/ui/text/input/ImmHelper21;", "Landroidx/compose/ui/text/input/ImmHelper;", "view", "Landroid/view/View;", "(Landroid/view/View;)V", "hideSoftInput", "", "imm", "Landroid/view/inputmethod/InputMethodManager;", "showSoftInput", "ui_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ImmHelper21 implements ImmHelper {
    private final View view;

    public ImmHelper21(View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        this.view = view;
    }

    @Override // androidx.compose.ui.text.input.ImmHelper
    public void showSoftInput(final android.view.inputmethod.InputMethodManager imm) {
        Intrinsics.checkNotNullParameter(imm, "imm");
        this.view.post(new Runnable() { // from class: androidx.compose.ui.text.input.ImmHelper21$$ExternalSyntheticLambda0
            @Override // java.lang.Runnable
            public final void run() {
                ImmHelper21.showSoftInput$lambda$0(imm, this);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void showSoftInput$lambda$0(android.view.inputmethod.InputMethodManager imm, ImmHelper21 this$0) {
        Intrinsics.checkNotNullParameter(imm, "$imm");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        imm.showSoftInput(this$0.view, 0);
    }

    @Override // androidx.compose.ui.text.input.ImmHelper
    public void hideSoftInput(android.view.inputmethod.InputMethodManager imm) {
        Intrinsics.checkNotNullParameter(imm, "imm");
        imm.hideSoftInputFromWindow(this.view.getWindowToken(), 0);
    }
}
