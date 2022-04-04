using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Libraries
{
    sealed class vaultcli
    {
        [DllImport("vaultcli.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool VaultEnumerateItems(
            IntPtr hVault,
            int unknown,
            out int dwItems,
            out IntPtr ppVaultGuids
        );

        [DllImport("vaultcli.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool VaultEnumerateVaults(
            int unknown,
            out int dwVaults,
            out IntPtr ppVaultGuids
        );

        [DllImport("vaultcli.dll", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = "VaultGetItem")]
        public static extern bool VaultGetItem7(
            IntPtr hVault,
            ref Guid guid,
            IntPtr SchemaId,
            IntPtr Resource,
            IntPtr Identity,
            //IntPtr unknownPtr,
            int unknown,
            out IntPtr hitem
        );

        [DllImport("vaultcli.dll", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = "VaultGetItem")]
        public static extern bool VaultGetItem8(
            IntPtr hVault,
            ref Guid guid,
            IntPtr SchemaId,
            IntPtr Resource, 
            IntPtr Identity,
            IntPtr PackageSid,
            //IntPtr unknownPtr,
            int unknown,
            out IntPtr hitem
        );

        [DllImport("vaultcli.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool VaultOpenVault(
            ref Guid guid,
            int dwVaults,
            out IntPtr hItems
        );
    }
}