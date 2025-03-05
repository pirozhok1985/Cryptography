using System.Runtime.InteropServices;
using System.Text;

namespace KeyAttestation.Client.Utils;

public class Native
{
    private const string OpenSslLibrary = "libcrypto.so";
    
    [DllImport(OpenSslLibrary, CallingConvention = CallingConvention.Cdecl, EntryPoint = "OSSL_PROVIDER_load")]
    public static extern IntPtr LoadOsslProvider(IntPtr libraryContext, StringBuilder providerName);
    
    [DllImport(OpenSslLibrary, CallingConvention = CallingConvention.Cdecl, EntryPoint = "OSSL_STORE_open")]
    public static extern IntPtr OpenOsslStore(StringBuilder keyHandle, IntPtr uiMethod, IntPtr uiData, IntPtr postProcess, IntPtr postProcessData);
    
    [DllImport(OpenSslLibrary, CallingConvention = CallingConvention.Cdecl, EntryPoint = "OSSL_STORE_load")]
    public static extern IntPtr LoadOsslStore(IntPtr storeContext);
    
    [DllImport(OpenSslLibrary, CallingConvention = CallingConvention.Cdecl, EntryPoint = "OSSL_STORE_INFO_get0_PKEY")]
    public static extern IntPtr GetPrivateKey(IntPtr storeInfoContext);
    
    [DllImport(OpenSslLibrary, CallingConvention = CallingConvention.Cdecl, EntryPoint = "EVP_PKEY_free")]
    public static extern void FreePrivateKey(IntPtr privateKey);
    
    [DllImport(OpenSslLibrary, CallingConvention = CallingConvention.Cdecl, EntryPoint = "OSSL_STORE_close")]
    public static extern void CloseOsslStore(IntPtr storeContext);
    
    [DllImport(OpenSslLibrary, CallingConvention = CallingConvention.Cdecl, EntryPoint = "OSSL_PROVIDER_unload")]
    public static extern void UnloadOsslProvider(IntPtr providerContext);
}