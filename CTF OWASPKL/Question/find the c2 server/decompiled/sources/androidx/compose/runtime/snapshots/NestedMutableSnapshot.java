package androidx.compose.runtime.snapshots;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: Snapshot.kt */
@Metadata(d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\b\u0000\u0018\u00002\u00020\u0001BI\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0014\u0010\u0006\u001a\u0010\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\t\u0018\u00010\u0007\u0012\u0014\u0010\n\u001a\u0010\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\t\u0018\u00010\u0007\u0012\u0006\u0010\u000b\u001a\u00020\u0001¢\u0006\u0002\u0010\fJ\b\u0010\u0015\u001a\u00020\u0016H\u0016J\b\u0010\u0017\u001a\u00020\tH\u0002J\b\u0010\u0018\u001a\u00020\tH\u0016R\u000e\u0010\r\u001a\u00020\u000eX\u0082\u000e¢\u0006\u0002\n\u0000R\u0011\u0010\u000b\u001a\u00020\u0001¢\u0006\b\n\u0000\u001a\u0004\b\u000f\u0010\u0010R\u0014\u0010\u0011\u001a\u00020\u00128VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0013\u0010\u0014¨\u0006\u0019"}, d2 = {"Landroidx/compose/runtime/snapshots/NestedMutableSnapshot;", "Landroidx/compose/runtime/snapshots/MutableSnapshot;", "id", "", "invalid", "Landroidx/compose/runtime/snapshots/SnapshotIdSet;", "readObserver", "Lkotlin/Function1;", "", "", "writeObserver", "parent", "(ILandroidx/compose/runtime/snapshots/SnapshotIdSet;Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function1;Landroidx/compose/runtime/snapshots/MutableSnapshot;)V", "deactivated", "", "getParent", "()Landroidx/compose/runtime/snapshots/MutableSnapshot;", "root", "Landroidx/compose/runtime/snapshots/Snapshot;", "getRoot", "()Landroidx/compose/runtime/snapshots/Snapshot;", "apply", "Landroidx/compose/runtime/snapshots/SnapshotApplyResult;", "deactivate", "dispose", "runtime_release"}, k = 1, mv = {1, 8, 0}, xi = 48)
/* loaded from: classes.dex */
public final class NestedMutableSnapshot extends MutableSnapshot {
    private boolean deactivated;
    private final MutableSnapshot parent;

    public final MutableSnapshot getParent() {
        return this.parent;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public NestedMutableSnapshot(int id, SnapshotIdSet invalid, Function1<Object, Unit> function1, Function1<Object, Unit> function12, MutableSnapshot parent) {
        super(id, invalid, function1, function12);
        Intrinsics.checkNotNullParameter(invalid, "invalid");
        Intrinsics.checkNotNullParameter(parent, "parent");
        this.parent = parent;
        parent.mo2261nestedActivated$runtime_release(this);
    }

    @Override // androidx.compose.runtime.snapshots.MutableSnapshot, androidx.compose.runtime.snapshots.Snapshot
    public Snapshot getRoot() {
        return this.parent.getRoot();
    }

    @Override // androidx.compose.runtime.snapshots.MutableSnapshot, androidx.compose.runtime.snapshots.Snapshot
    public void dispose() {
        if (!getDisposed$runtime_release()) {
            super.dispose();
            deactivate();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0089 A[Catch: all -> 0x00d4, TryCatch #0 {, blocks: (B:14:0x0034, B:16:0x003c, B:19:0x0043, B:23:0x005d, B:25:0x0065, B:26:0x0077, B:28:0x0081, B:30:0x0089, B:31:0x008e, B:27:0x007e), top: B:40:0x0034 }] */
    @Override // androidx.compose.runtime.snapshots.MutableSnapshot
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public androidx.compose.runtime.snapshots.SnapshotApplyResult apply() {
        /*
            r13 = this;
            androidx.compose.runtime.snapshots.MutableSnapshot r0 = r13.parent
            boolean r0 = r0.getApplied$runtime_release()
            if (r0 != 0) goto Ld7
            androidx.compose.runtime.snapshots.MutableSnapshot r0 = r13.parent
            boolean r0 = r0.getDisposed$runtime_release()
            if (r0 == 0) goto L12
            goto Ld7
        L12:
            java.util.Set r0 = r13.getModified$runtime_release()
            int r1 = r13.getId()
            if (r0 == 0) goto L2a
            androidx.compose.runtime.snapshots.MutableSnapshot r2 = r13.parent
            r3 = r13
            androidx.compose.runtime.snapshots.MutableSnapshot r3 = (androidx.compose.runtime.snapshots.MutableSnapshot) r3
            androidx.compose.runtime.snapshots.SnapshotIdSet r4 = r2.getInvalid$runtime_release()
            java.util.Map r2 = androidx.compose.runtime.snapshots.SnapshotKt.access$optimisticMerges(r2, r3, r4)
            goto L2b
        L2a:
            r2 = 0
        L2b:
            r3 = 0
            java.lang.Object r4 = androidx.compose.runtime.snapshots.SnapshotKt.getLock()
            r5 = 0
            monitor-enter(r4)
            r6 = 0
            r7 = r13
            androidx.compose.runtime.snapshots.Snapshot r7 = (androidx.compose.runtime.snapshots.Snapshot) r7     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.SnapshotKt.access$validateOpen(r7)     // Catch: java.lang.Throwable -> Ld4
            if (r0 == 0) goto L7e
            int r7 = r0.size()     // Catch: java.lang.Throwable -> Ld4
            if (r7 != 0) goto L43
            goto L7e
        L43:
            androidx.compose.runtime.snapshots.MutableSnapshot r7 = r13.parent     // Catch: java.lang.Throwable -> Ld4
            int r7 = r7.getId()     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.MutableSnapshot r8 = r13.parent     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.SnapshotIdSet r8 = r8.getInvalid$runtime_release()     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.SnapshotApplyResult r7 = r13.innerApplyLocked$runtime_release(r7, r2, r8)     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.SnapshotApplyResult$Success r8 = androidx.compose.runtime.snapshots.SnapshotApplyResult.Success.INSTANCE     // Catch: java.lang.Throwable -> Ld4
            boolean r8 = kotlin.jvm.internal.Intrinsics.areEqual(r7, r8)     // Catch: java.lang.Throwable -> Ld4
            if (r8 != 0) goto L5d
            monitor-exit(r4)
            return r7
        L5d:
            androidx.compose.runtime.snapshots.MutableSnapshot r8 = r13.parent     // Catch: java.lang.Throwable -> Ld4
            java.util.Set r8 = r8.getModified$runtime_release()     // Catch: java.lang.Throwable -> Ld4
            if (r8 != 0) goto L77
            java.util.HashSet r8 = new java.util.HashSet     // Catch: java.lang.Throwable -> Ld4
            r8.<init>()     // Catch: java.lang.Throwable -> Ld4
            r9 = r8
            r10 = 0
            androidx.compose.runtime.snapshots.MutableSnapshot r11 = r13.parent     // Catch: java.lang.Throwable -> Ld4
            r12 = r9
            java.util.Set r12 = (java.util.Set) r12     // Catch: java.lang.Throwable -> Ld4
            r11.setModified(r12)     // Catch: java.lang.Throwable -> Ld4
            java.util.Set r8 = (java.util.Set) r8     // Catch: java.lang.Throwable -> Ld4
        L77:
            r9 = r0
            java.util.Collection r9 = (java.util.Collection) r9     // Catch: java.lang.Throwable -> Ld4
            r8.addAll(r9)     // Catch: java.lang.Throwable -> Ld4
            goto L81
        L7e:
            r13.closeAndReleasePinning$runtime_release()     // Catch: java.lang.Throwable -> Ld4
        L81:
            androidx.compose.runtime.snapshots.MutableSnapshot r7 = r13.parent     // Catch: java.lang.Throwable -> Ld4
            int r7 = r7.getId()     // Catch: java.lang.Throwable -> Ld4
            if (r7 >= r1) goto L8e
            androidx.compose.runtime.snapshots.MutableSnapshot r7 = r13.parent     // Catch: java.lang.Throwable -> Ld4
            r7.advance$runtime_release()     // Catch: java.lang.Throwable -> Ld4
        L8e:
            androidx.compose.runtime.snapshots.MutableSnapshot r7 = r13.parent     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.SnapshotIdSet r8 = r7.getInvalid$runtime_release()     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.SnapshotIdSet r8 = r8.clear(r1)     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.SnapshotIdSet r9 = r13.getPreviousIds$runtime_release()     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.SnapshotIdSet r8 = r8.andNot(r9)     // Catch: java.lang.Throwable -> Ld4
            r7.setInvalid$runtime_release(r8)     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.MutableSnapshot r7 = r13.parent     // Catch: java.lang.Throwable -> Ld4
            r7.recordPrevious$runtime_release(r1)     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.MutableSnapshot r7 = r13.parent     // Catch: java.lang.Throwable -> Ld4
            int r8 = r13.takeoverPinnedSnapshot$runtime_release()     // Catch: java.lang.Throwable -> Ld4
            r7.recordPreviousPinnedSnapshot$runtime_release(r8)     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.MutableSnapshot r7 = r13.parent     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.SnapshotIdSet r8 = r13.getPreviousIds$runtime_release()     // Catch: java.lang.Throwable -> Ld4
            r7.recordPreviousList$runtime_release(r8)     // Catch: java.lang.Throwable -> Ld4
            androidx.compose.runtime.snapshots.MutableSnapshot r7 = r13.parent     // Catch: java.lang.Throwable -> Ld4
            int[] r8 = r13.getPreviousPinnedSnapshots$runtime_release()     // Catch: java.lang.Throwable -> Ld4
            r7.recordPreviousPinnedSnapshots$runtime_release(r8)     // Catch: java.lang.Throwable -> Ld4
            kotlin.Unit r6 = kotlin.Unit.INSTANCE     // Catch: java.lang.Throwable -> Ld4
            monitor-exit(r4)
            r3 = 1
            r13.setApplied$runtime_release(r3)
            r13.deactivate()
            androidx.compose.runtime.snapshots.SnapshotApplyResult$Success r3 = androidx.compose.runtime.snapshots.SnapshotApplyResult.Success.INSTANCE
            androidx.compose.runtime.snapshots.SnapshotApplyResult r3 = (androidx.compose.runtime.snapshots.SnapshotApplyResult) r3
            return r3
        Ld4:
            r6 = move-exception
            monitor-exit(r4)
            throw r6
        Ld7:
            androidx.compose.runtime.snapshots.SnapshotApplyResult$Failure r0 = new androidx.compose.runtime.snapshots.SnapshotApplyResult$Failure
            r1 = r13
            androidx.compose.runtime.snapshots.Snapshot r1 = (androidx.compose.runtime.snapshots.Snapshot) r1
            r0.<init>(r1)
            androidx.compose.runtime.snapshots.SnapshotApplyResult r0 = (androidx.compose.runtime.snapshots.SnapshotApplyResult) r0
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.NestedMutableSnapshot.apply():androidx.compose.runtime.snapshots.SnapshotApplyResult");
    }

    private final void deactivate() {
        if (!this.deactivated) {
            this.deactivated = true;
            this.parent.mo2262nestedDeactivated$runtime_release(this);
        }
    }
}
