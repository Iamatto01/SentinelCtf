package androidx.core.graphics;

import android.graphics.BlendMode;
import android.graphics.BlendModeColorFilter;
import android.graphics.ColorFilter;
import androidx.core.graphics.BlendModeUtils;
/* loaded from: classes.dex */
public class BlendModeColorFilterCompat {
    public static ColorFilter createBlendModeColorFilterCompat(int color, BlendModeCompat blendModeCompat) {
        Object blendMode = BlendModeUtils.Api29Impl.obtainBlendModeFromCompat(blendModeCompat);
        if (blendMode != null) {
            return Api29Impl.createBlendModeColorFilter(color, blendMode);
        }
        return null;
    }

    private BlendModeColorFilterCompat() {
    }

    /* loaded from: classes.dex */
    static class Api29Impl {
        private Api29Impl() {
        }

        static ColorFilter createBlendModeColorFilter(int color, Object mode) {
            return new BlendModeColorFilter(color, (BlendMode) mode);
        }
    }
}
