package androidx.compose.ui.node;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: MyersDiff.kt */
@Metadata(d1 = {"\u00004\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0015\n\u0002\b\u0013\u001a(\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\bH\u0002\u001a]\u0010\t\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\u00032\u0006\u0010\f\u001a\u00020\u00032\u0006\u0010\r\u001a\u00020\u00032\u0006\u0010\u000e\u001a\u00020\u00032\u0006\u0010\u000f\u001a\u00020\b2\u0006\u0010\u0010\u001a\u00020\u00112\u0006\u0010\t\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u00032\u0006\u0010\u0013\u001a\u00020\u0014H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\u0015\u0010\u0016\u001a \u0010\u0017\u001a\u00020\u00062\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u000f\u001a\u00020\bH\u0002\u001a \u0010\u0018\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0007\u001a\u00020\bH\u0000\u001a8\u0010\u0019\u001a\u00020\u00012\u0006\u0010\u001a\u001a\u00020\u00032\u0006\u0010\u001b\u001a\u00020\u00032\u0006\u0010\u001c\u001a\u00020\u00032\u0006\u0010\u001d\u001a\u00020\u00032\u0006\u0010\u001e\u001a\u00020\n2\u0006\u0010\u001f\u001a\u00020\u0014H\u0000\u001a]\u0010\u0010\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\u00032\u0006\u0010\f\u001a\u00020\u00032\u0006\u0010\r\u001a\u00020\u00032\u0006\u0010\u000e\u001a\u00020\u00032\u0006\u0010\u000f\u001a\u00020\b2\u0006\u0010\u0010\u001a\u00020\u00112\u0006\u0010\t\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u00032\u0006\u0010\u0013\u001a\u00020\u0014H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b \u0010\u0016\u001aU\u0010!\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\u00032\u0006\u0010\f\u001a\u00020\u00032\u0006\u0010\r\u001a\u00020\u00032\u0006\u0010\u000e\u001a\u00020\u00032\u0006\u0010\u000f\u001a\u00020\b2\u0006\u0010\u0010\u001a\u00020\u00112\u0006\u0010\t\u001a\u00020\u00112\u0006\u0010\u0013\u001a\u00020\u0014H\u0002ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\b\"\u0010#\u001a\u001c\u0010$\u001a\u00020\u0001*\u00020\u00142\u0006\u0010%\u001a\u00020\u00032\u0006\u0010&\u001a\u00020\u0003H\u0002\u0082\u0002\u000b\n\u0005\b¡\u001e0\u0001\n\u0002\b\u0019¨\u0006'"}, d2 = {"applyDiff", "", "oldSize", "", "newSize", "diagonals", "Landroidx/compose/ui/node/IntStack;", "callback", "Landroidx/compose/ui/node/DiffCallback;", "backward", "", "oldStart", "oldEnd", "newStart", "newEnd", "cb", "forward", "Landroidx/compose/ui/node/CenteredArray;", "d", "snake", "", "backward-4l5_RBY", "(IIIILandroidx/compose/ui/node/DiffCallback;[I[II[I)Z", "calculateDiff", "executeDiff", "fillSnake", "startX", "startY", "endX", "endY", "reverse", "data", "forward-4l5_RBY", "midPoint", "midPoint-q5eDKzI", "(IIIILandroidx/compose/ui/node/DiffCallback;[I[I[I)Z", "swap", "i", "j", "ui_release"}, k = 2, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class MyersDiffKt {
    private static final IntStack calculateDiff(int oldSize, int newSize, DiffCallback cb) {
        int[] snake;
        int oldEnd = ((oldSize + newSize) + 1) / 2;
        IntStack diagonals = new IntStack(oldEnd * 3);
        IntStack stack = new IntStack(oldEnd * 4);
        stack.pushRange(0, oldSize, 0, newSize);
        int[] forward = CenteredArray.m4216constructorimpl(new int[(oldEnd * 2) + 1]);
        int[] backward = CenteredArray.m4216constructorimpl(new int[(oldEnd * 2) + 1]);
        int[] snake2 = Snake.m4382constructorimpl(new int[5]);
        while (stack.isNotEmpty()) {
            int newEnd = stack.pop();
            int newStart = stack.pop();
            int oldEnd2 = stack.pop();
            int oldStart = stack.pop();
            int max = oldEnd;
            int[] forward2 = forward;
            int[] snake3 = snake2;
            boolean found = m4288midPointq5eDKzI(oldStart, oldEnd2, newStart, newEnd, cb, forward, backward, snake2);
            if (!found) {
                snake2 = snake3;
                oldEnd = max;
                forward = forward2;
            } else {
                if (Snake.m4385getDiagonalSizeimpl(snake3) <= 0) {
                    snake = snake3;
                } else {
                    snake = snake3;
                    Snake.m4380addDiagonalToStackimpl(snake, diagonals);
                }
                stack.pushRange(oldStart, Snake.m4390getStartXimpl(snake), newStart, Snake.m4391getStartYimpl(snake));
                stack.pushRange(Snake.m4386getEndXimpl(snake), oldEnd2, Snake.m4387getEndYimpl(snake), newEnd);
                snake2 = snake;
                oldEnd = max;
                forward = forward2;
            }
        }
        diagonals.sortDiagonals();
        diagonals.pushDiagonal(oldSize, newSize, 0);
        return diagonals;
    }

    private static final void applyDiff(int oldSize, int newSize, IntStack diagonals, DiffCallback callback) {
        int posX = oldSize;
        int posY = newSize;
        while (diagonals.isNotEmpty()) {
            int i = diagonals.pop();
            int endY = diagonals.pop();
            int endX = diagonals.pop();
            while (posX > endX) {
                posX--;
                callback.remove(posX);
            }
            while (posY > endY) {
                posY--;
                callback.insert(posX, posY);
            }
            while (true) {
                int i2 = i - 1;
                if (i > 0) {
                    posX--;
                    posY--;
                    callback.same(posX, posY);
                    i = i2;
                }
            }
        }
        while (posX > 0) {
            posX--;
            callback.remove(posX);
        }
        while (posY > 0) {
            posY--;
            callback.insert(posX, posY);
        }
    }

    public static final void executeDiff(int oldSize, int newSize, DiffCallback callback) {
        Intrinsics.checkNotNullParameter(callback, "callback");
        IntStack diagonals = calculateDiff(oldSize, newSize, callback);
        applyDiff(oldSize, newSize, diagonals, callback);
    }

    /* renamed from: midPoint-q5eDKzI  reason: not valid java name */
    private static final boolean m4288midPointq5eDKzI(int oldStart, int oldEnd, int newStart, int newEnd, DiffCallback cb, int[] forward, int[] backward, int[] snake) {
        int oldSize = oldEnd - oldStart;
        int newSize = newEnd - newStart;
        if (oldSize < 1 || newSize < 1) {
            return false;
        }
        int max = ((oldSize + newSize) + 1) / 2;
        CenteredArray.m4222setimpl(forward, 1, oldStart);
        CenteredArray.m4222setimpl(backward, 1, oldEnd);
        int d = 0;
        while (d < max) {
            int d2 = d;
            boolean found = m4287forward4l5_RBY(oldStart, oldEnd, newStart, newEnd, cb, forward, backward, d2, snake);
            if (found) {
                return true;
            }
            boolean found2 = m4286backward4l5_RBY(oldStart, oldEnd, newStart, newEnd, cb, forward, backward, d2, snake);
            if (found2) {
                return true;
            }
            d = d2 + 1;
        }
        return false;
    }

    /* renamed from: forward-4l5_RBY  reason: not valid java name */
    private static final boolean m4287forward4l5_RBY(int oldStart, int oldEnd, int newStart, int newEnd, DiffCallback cb, int[] forward, int[] backward, int d, int[] snake) {
        int startX;
        int x;
        int i = oldEnd;
        int oldSize = i - oldStart;
        int newSize = newEnd - newStart;
        int i2 = 1;
        boolean checkForSnake = Math.abs(oldSize - newSize) % 2 == 1;
        int delta = oldSize - newSize;
        int k = -d;
        while (k <= d) {
            if (k == (-d) || (k != d && CenteredArray.m4219getimpl(forward, k + 1) > CenteredArray.m4219getimpl(forward, k - 1))) {
                startX = CenteredArray.m4219getimpl(forward, k + 1);
                x = startX;
            } else {
                startX = CenteredArray.m4219getimpl(forward, k - 1);
                x = startX + 1;
            }
            int y = (newStart + (x - oldStart)) - k;
            int startY = (d == 0 || x != startX) ? y : y - 1;
            int startY2 = y;
            while (x < i && startY2 < newEnd) {
                if (!cb.areItemsTheSame(x, startY2)) {
                    break;
                }
                x++;
                startY2++;
            }
            CenteredArray.m4222setimpl(forward, k, x);
            if (checkForSnake) {
                int backwardsK = delta - k;
                if (backwardsK >= (-d) + i2 && backwardsK <= d - 1) {
                    if (CenteredArray.m4219getimpl(backward, backwardsK) > x) {
                        i2 = 1;
                    } else {
                        fillSnake(startX, startY, x, startY2, false, snake);
                        return true;
                    }
                }
            }
            k += 2;
            i = oldEnd;
        }
        return false;
    }

    /* renamed from: backward-4l5_RBY  reason: not valid java name */
    private static final boolean m4286backward4l5_RBY(int oldStart, int oldEnd, int newStart, int newEnd, DiffCallback cb, int[] forward, int[] backward, int d, int[] snake) {
        int startX;
        int x;
        int oldSize = oldEnd - oldStart;
        int newSize = newEnd - newStart;
        boolean checkForSnake = (oldSize - newSize) % 2 == 0;
        int delta = oldSize - newSize;
        for (int k = -d; k <= d; k += 2) {
            if (k == (-d) || (k != d && CenteredArray.m4219getimpl(backward, k + 1) < CenteredArray.m4219getimpl(backward, k - 1))) {
                startX = CenteredArray.m4219getimpl(backward, k + 1);
                x = startX;
            } else {
                startX = CenteredArray.m4219getimpl(backward, k - 1);
                x = startX - 1;
            }
            int y = newEnd - ((oldEnd - x) - k);
            int startY = (d == 0 || x != startX) ? y : y + 1;
            int y2 = y;
            while (x > oldStart && y2 > newStart) {
                if (!cb.areItemsTheSame(x - 1, y2 - 1)) {
                    break;
                }
                x--;
                y2--;
            }
            CenteredArray.m4222setimpl(backward, k, x);
            if (checkForSnake) {
                int forwardsK = delta - k;
                if (forwardsK >= (-d) && forwardsK <= d && CenteredArray.m4219getimpl(forward, forwardsK) >= x) {
                    fillSnake(x, y2, startX, startY, true, snake);
                    return true;
                }
            }
        }
        return false;
    }

    public static final void fillSnake(int startX, int startY, int endX, int endY, boolean reverse, int[] data) {
        Intrinsics.checkNotNullParameter(data, "data");
        data[0] = startX;
        data[1] = startY;
        data[2] = endX;
        data[3] = endY;
        data[4] = reverse ? 1 : 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void swap(int[] $this$swap, int i, int j) {
        int tmp = $this$swap[i];
        $this$swap[i] = $this$swap[j];
        $this$swap[j] = tmp;
    }
}
