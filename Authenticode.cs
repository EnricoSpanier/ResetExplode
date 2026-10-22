using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace ResetExplode;

/// <summary>Verificação de assinatura Authenticode feita pelo próprio Windows (WinVerifyTrust).</summary>
public static class Authenticode
{
    /// <summary>Devolve null se o arquivo tem assinatura válida de <paramref name="publisher"/>; senão, o motivo da rejeição.</summary>
    public static string? Check(string path, string publisher)
    {
        int trust = WinVerifyTrustFile(path);
        if (trust == unchecked((int)0x800B0100)) return "sem assinatura digital";
        if (trust != 0) return $"assinatura digital inválida (0x{trust:X8})";
        string signer = "";
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = X509Certificate.CreateFromSignedFile(path);
            signer = new X509Certificate2(cert).Subject;
#pragma warning restore SYSLIB0057
        }
        catch { }
        return signer.Contains(publisher, StringComparison.OrdinalIgnoreCase) ? null : $"assinado por outro fabricante ({signer})";
    }

    // ---- WinVerifyTrust (verificação de assinatura Authenticode feita pelo próprio Windows) ----
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, ref WINTRUST_DATA pWVTData);

    internal static int WinVerifyTrustFile(string path)
    {
        var file = new WINTRUST_FILE_INFO { pcwszFilePath = path };
        file.cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>();
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(file, pFile, false);
            var data = new WINTRUST_DATA
            {
                dwUIChoice = 2,          // WTD_UI_NONE
                fdwRevocationChecks = 0, // WTD_REVOKE_NONE
                dwUnionChoice = 1,       // WTD_CHOICE_FILE
                pFile = pFile,
                dwStateAction = 0,       // WTD_STATEACTION_IGNORE
                dwProvFlags = 0x10,      // WTD_REVOCATION_CHECK_NONE
            };
            data.cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>();
            return WinVerifyTrust(new IntPtr(-1), new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"), ref data);
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }
}
