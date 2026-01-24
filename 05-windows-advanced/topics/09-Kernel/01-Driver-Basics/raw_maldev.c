/*
 * Driver Basics - Kernel module template
 * Build with WDK
 */

#include <ntddk.h>

// ============================================================================
// DEVICE NAMES
// ============================================================================

#define DEV_NAME L"\\Device\\D"
#define SYM_NAME L"\\DosDevices\\D"

PDEVICE_OBJECT g_dev = 0;

// ============================================================================
// MEMORY
// ============================================================================

void* kmalloc(SIZE_T sz)
{
    return ExAllocatePoolWithTag(NonPagedPool, sz, 'laMD');
}

void kfree(void* p)
{
    if(p) ExFreePoolWithTag(p, 'laMD');
}

// ============================================================================
// IRP HANDLERS
// ============================================================================

NTSTATUS irp_create(PDEVICE_OBJECT d, PIRP irp)
{
    UNREFERENCED_PARAMETER(d);
    irp->IoStatus.Status = 0;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, 0);
    return 0;
}

NTSTATUS irp_close(PDEVICE_OBJECT d, PIRP irp)
{
    UNREFERENCED_PARAMETER(d);
    irp->IoStatus.Status = 0;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, 0);
    return 0;
}

NTSTATUS irp_ioctl(PDEVICE_OBJECT d, PIRP irp)
{
    UNREFERENCED_PARAMETER(d);

    PIO_STACK_LOCATION stk = IoGetCurrentIrpStackLocation(irp);
    ULONG code = stk->Parameters.DeviceIoControl.IoControlCode;
    PVOID buf = irp->AssociatedIrp.SystemBuffer;
    ULONG in_sz = stk->Parameters.DeviceIoControl.InputBufferLength;
    ULONG out_sz = stk->Parameters.DeviceIoControl.OutputBufferLength;

    NTSTATUS st = 0;
    ULONG info = 0;

    switch(code) {
        case 0x80002000:  // Custom IOCTL
            break;
        default:
            st = 0xC0000010;  // STATUS_INVALID_DEVICE_REQUEST
            break;
    }

    irp->IoStatus.Status = st;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, 0);
    return st;
}

// ============================================================================
// DEVICE SETUP
// ============================================================================

NTSTATUS dev_create(PDRIVER_OBJECT drv)
{
    UNICODE_STRING dev, sym;
    NTSTATUS st;

    RtlInitUnicodeString(&dev, DEV_NAME);
    RtlInitUnicodeString(&sym, SYM_NAME);

    st = IoCreateDevice(drv, 0, &dev, 0x22, 0x100, 0, &g_dev);
    if(!NT_SUCCESS(st)) return st;

    st = IoCreateSymbolicLink(&sym, &dev);
    if(!NT_SUCCESS(st)) {
        IoDeleteDevice(g_dev);
        return st;
    }

    g_dev->Flags |= 0x4;  // DO_DIRECT_IO
    g_dev->Flags &= ~0x80;  // Clear DO_DEVICE_INITIALIZING

    return 0;
}

void dev_delete(void)
{
    UNICODE_STRING sym;
    RtlInitUnicodeString(&sym, SYM_NAME);
    IoDeleteSymbolicLink(&sym);
    if(g_dev) IoDeleteDevice(g_dev);
}

// ============================================================================
// MDL - Map user buffer
// ============================================================================

void* mdl_map(PVOID buf, SIZE_T len, PMDL* pmdl)
{
    PMDL m = IoAllocateMdl(buf, (ULONG)len, 0, 0, 0);
    if(!m) return 0;

    __try {
        MmProbeAndLockPages(m, UserMode, IoReadAccess);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(m);
        return 0;
    }

    *pmdl = m;
    return MmGetSystemAddressForMdlSafe(m, NormalPagePriority);
}

void mdl_unmap(PMDL m)
{
    if(m) {
        MmUnlockPages(m);
        IoFreeMdl(m);
    }
}

// ============================================================================
// ZW FILE OPS
// ============================================================================

NTSTATUS zw_read(PUNICODE_STRING path, PVOID* buf, PSIZE_T sz)
{
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    FILE_STANDARD_INFORMATION fi;
    NTSTATUS st;

    InitializeObjectAttributes(&oa, path, 0x40 | 0x200, 0, 0);

    st = ZwCreateFile(&h, 0x80000000, &oa, &io, 0, 0x80, 1, 1, 0x20, 0, 0);
    if(!NT_SUCCESS(st)) return st;

    ZwQueryInformationFile(h, &io, &fi, sizeof(fi), FileStandardInformation);

    *sz = (SIZE_T)fi.EndOfFile.QuadPart;
    *buf = kmalloc(*sz);
    if(!*buf) {
        ZwClose(h);
        return 0xC000009A;  // STATUS_INSUFFICIENT_RESOURCES
    }

    st = ZwReadFile(h, 0, 0, 0, &io, *buf, (ULONG)*sz, 0, 0);
    ZwClose(h);
    return st;
}

// ============================================================================
// REGISTRY OPS
// ============================================================================

NTSTATUS zw_reg_read(PUNICODE_STRING path, PUNICODE_STRING val, PKEY_VALUE_PARTIAL_INFORMATION* info)
{
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    ULONG sz;
    NTSTATUS st;

    InitializeObjectAttributes(&oa, path, 0x40 | 0x200, 0, 0);

    st = ZwOpenKey(&h, 0x20019, &oa);
    if(!NT_SUCCESS(st)) return st;

    ZwQueryValueKey(h, val, KeyValuePartialInformation, 0, 0, &sz);

    *info = kmalloc(sz);
    if(!*info) {
        ZwClose(h);
        return 0xC000009A;
    }

    st = ZwQueryValueKey(h, val, KeyValuePartialInformation, *info, sz, &sz);
    ZwClose(h);
    return st;
}

// ============================================================================
// SPINLOCK
// ============================================================================

KSPIN_LOCK g_lock;

void lock_init(void)
{
    KeInitializeSpinLock(&g_lock);
}

void with_lock(void)
{
    KIRQL old;
    KeAcquireSpinLock(&g_lock, &old);
    // Critical section
    KeReleaseSpinLock(&g_lock, old);
}

// ============================================================================
// UNLOAD
// ============================================================================

void drv_unload(PDRIVER_OBJECT drv)
{
    UNREFERENCED_PARAMETER(drv);
    dev_delete();
}

// ============================================================================
// ENTRY
// ============================================================================

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNREFERENCED_PARAMETER(reg);

    drv->DriverUnload = drv_unload;
    drv->MajorFunction[0] = irp_create;   // IRP_MJ_CREATE
    drv->MajorFunction[2] = irp_close;    // IRP_MJ_CLOSE
    drv->MajorFunction[14] = irp_ioctl;   // IRP_MJ_DEVICE_CONTROL

    lock_init();
    return dev_create(drv);
}

// ============================================================================
// EOF
// ============================================================================
