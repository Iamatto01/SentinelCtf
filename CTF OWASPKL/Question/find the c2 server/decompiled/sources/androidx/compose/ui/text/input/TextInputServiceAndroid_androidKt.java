package androidx.compose.ui.text.input;

import android.view.Choreographer;
import android.view.inputmethod.EditorInfo;
import androidx.compose.ui.text.TextRange;
import androidx.core.view.InputDeviceCompat;
import androidx.core.view.inputmethod.EditorInfoCompat;
import androidx.emoji2.text.EmojiCompat;
import java.util.concurrent.Executor;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: TextInputServiceAndroid.android.kt */
@Metadata(d1 = {"\u00008\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a\u0018\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0005H\u0002\u001a\f\u0010\u0007\u001a\u00020\b*\u00020\tH\u0000\u001a\u001c\u0010\n\u001a\u00020\u000b*\u00020\f2\u0006\u0010\r\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\u0010H\u0000\u001a\f\u0010\u0011\u001a\u00020\u000b*\u00020\fH\u0002\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000¨\u0006\u0012"}, d2 = {"DEBUG_CLASS", "", "hasFlag", "", "bits", "", "flag", "asExecutor", "Ljava/util/concurrent/Executor;", "Landroid/view/Choreographer;", "update", "", "Landroid/view/inputmethod/EditorInfo;", "imeOptions", "Landroidx/compose/ui/text/input/ImeOptions;", "textFieldValue", "Landroidx/compose/ui/text/input/TextFieldValue;", "updateWithEmojiCompat", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class TextInputServiceAndroid_androidKt {
    private static final String DEBUG_CLASS = "TextInputServiceAndroid";

    /* JADX INFO: Access modifiers changed from: private */
    public static final void updateWithEmojiCompat(EditorInfo $this$updateWithEmojiCompat) {
        if (EmojiCompat.isConfigured()) {
            EmojiCompat.get().updateEditorInfo($this$updateWithEmojiCompat);
        }
    }

    public static final void update(EditorInfo $this$update, ImeOptions imeOptions, TextFieldValue textFieldValue) {
        Intrinsics.checkNotNullParameter($this$update, "<this>");
        Intrinsics.checkNotNullParameter(imeOptions, "imeOptions");
        Intrinsics.checkNotNullParameter(textFieldValue, "textFieldValue");
        int m4796getImeActioneUduSuo = imeOptions.m4796getImeActioneUduSuo();
        int i = 6;
        if (ImeAction.m4773equalsimpl0(m4796getImeActioneUduSuo, ImeAction.Companion.m4785getDefaulteUduSuo())) {
            if (!imeOptions.getSingleLine()) {
                i = 0;
            }
        } else if (ImeAction.m4773equalsimpl0(m4796getImeActioneUduSuo, ImeAction.Companion.m4789getNoneeUduSuo())) {
            i = 1;
        } else if (ImeAction.m4773equalsimpl0(m4796getImeActioneUduSuo, ImeAction.Companion.m4787getGoeUduSuo())) {
            i = 2;
        } else if (ImeAction.m4773equalsimpl0(m4796getImeActioneUduSuo, ImeAction.Companion.m4788getNexteUduSuo())) {
            i = 5;
        } else if (ImeAction.m4773equalsimpl0(m4796getImeActioneUduSuo, ImeAction.Companion.m4790getPreviouseUduSuo())) {
            i = 7;
        } else if (ImeAction.m4773equalsimpl0(m4796getImeActioneUduSuo, ImeAction.Companion.m4791getSearcheUduSuo())) {
            i = 3;
        } else if (ImeAction.m4773equalsimpl0(m4796getImeActioneUduSuo, ImeAction.Companion.m4792getSendeUduSuo())) {
            i = 4;
        } else if (!ImeAction.m4773equalsimpl0(m4796getImeActioneUduSuo, ImeAction.Companion.m4786getDoneeUduSuo())) {
            throw new IllegalStateException("invalid ImeAction".toString());
        }
        $this$update.imeOptions = i;
        int m4797getKeyboardTypePjHm6EE = imeOptions.m4797getKeyboardTypePjHm6EE();
        if (KeyboardType.m4819equalsimpl0(m4797getKeyboardTypePjHm6EE, KeyboardType.Companion.m4839getTextPjHm6EE())) {
            $this$update.inputType = 1;
        } else if (KeyboardType.m4819equalsimpl0(m4797getKeyboardTypePjHm6EE, KeyboardType.Companion.m4832getAsciiPjHm6EE())) {
            $this$update.inputType = 1;
            $this$update.imeOptions |= Integer.MIN_VALUE;
        } else if (KeyboardType.m4819equalsimpl0(m4797getKeyboardTypePjHm6EE, KeyboardType.Companion.m4835getNumberPjHm6EE())) {
            $this$update.inputType = 2;
        } else if (KeyboardType.m4819equalsimpl0(m4797getKeyboardTypePjHm6EE, KeyboardType.Companion.m4838getPhonePjHm6EE())) {
            $this$update.inputType = 3;
        } else if (KeyboardType.m4819equalsimpl0(m4797getKeyboardTypePjHm6EE, KeyboardType.Companion.m4840getUriPjHm6EE())) {
            $this$update.inputType = 17;
        } else if (KeyboardType.m4819equalsimpl0(m4797getKeyboardTypePjHm6EE, KeyboardType.Companion.m4834getEmailPjHm6EE())) {
            $this$update.inputType = 33;
        } else if (KeyboardType.m4819equalsimpl0(m4797getKeyboardTypePjHm6EE, KeyboardType.Companion.m4837getPasswordPjHm6EE())) {
            $this$update.inputType = 129;
        } else if (KeyboardType.m4819equalsimpl0(m4797getKeyboardTypePjHm6EE, KeyboardType.Companion.m4836getNumberPasswordPjHm6EE())) {
            $this$update.inputType = 18;
        } else if (KeyboardType.m4819equalsimpl0(m4797getKeyboardTypePjHm6EE, KeyboardType.Companion.m4833getDecimalPjHm6EE())) {
            $this$update.inputType = InputDeviceCompat.SOURCE_MOUSE;
        } else {
            throw new IllegalStateException("Invalid Keyboard Type".toString());
        }
        if (!imeOptions.getSingleLine() && hasFlag($this$update.inputType, 1)) {
            $this$update.inputType |= 131072;
            if (ImeAction.m4773equalsimpl0(imeOptions.m4796getImeActioneUduSuo(), ImeAction.Companion.m4785getDefaulteUduSuo())) {
                $this$update.imeOptions |= 1073741824;
            }
        }
        if (hasFlag($this$update.inputType, 1)) {
            int m4795getCapitalizationIUNYP9k = imeOptions.m4795getCapitalizationIUNYP9k();
            if (KeyboardCapitalization.m4804equalsimpl0(m4795getCapitalizationIUNYP9k, KeyboardCapitalization.Companion.m4812getCharactersIUNYP9k())) {
                $this$update.inputType |= 4096;
            } else if (KeyboardCapitalization.m4804equalsimpl0(m4795getCapitalizationIUNYP9k, KeyboardCapitalization.Companion.m4815getWordsIUNYP9k())) {
                $this$update.inputType |= 8192;
            } else if (KeyboardCapitalization.m4804equalsimpl0(m4795getCapitalizationIUNYP9k, KeyboardCapitalization.Companion.m4814getSentencesIUNYP9k())) {
                $this$update.inputType |= 16384;
            }
            if (imeOptions.getAutoCorrect()) {
                $this$update.inputType |= 32768;
            }
        }
        $this$update.initialSelStart = TextRange.m4637getStartimpl(textFieldValue.m4846getSelectiond9O1mEE());
        $this$update.initialSelEnd = TextRange.m4632getEndimpl(textFieldValue.m4846getSelectiond9O1mEE());
        EditorInfoCompat.setInitialSurroundingText($this$update, textFieldValue.getText());
        $this$update.imeOptions |= 33554432;
    }

    public static final Executor asExecutor(final Choreographer $this$asExecutor) {
        Intrinsics.checkNotNullParameter($this$asExecutor, "<this>");
        return new Executor() { // from class: androidx.compose.ui.text.input.TextInputServiceAndroid_androidKt$$ExternalSyntheticLambda1
            @Override // java.util.concurrent.Executor
            public final void execute(Runnable runnable) {
                TextInputServiceAndroid_androidKt.asExecutor$lambda$1($this$asExecutor, runnable);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void asExecutor$lambda$1(Choreographer this_asExecutor, final Runnable runnable) {
        Intrinsics.checkNotNullParameter(this_asExecutor, "$this_asExecutor");
        this_asExecutor.postFrameCallback(new Choreographer.FrameCallback() { // from class: androidx.compose.ui.text.input.TextInputServiceAndroid_androidKt$$ExternalSyntheticLambda0
            @Override // android.view.Choreographer.FrameCallback
            public final void doFrame(long j) {
                runnable.run();
            }
        });
    }

    private static final boolean hasFlag(int bits, int flag) {
        return (bits & flag) == flag;
    }
}
