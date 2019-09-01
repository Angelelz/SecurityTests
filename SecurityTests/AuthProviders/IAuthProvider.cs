using System;

namespace SecurityTests
{
    public enum AuthCacheType
    {
        Persistent,
        Local,
    }

    public interface IAuthProvider
    {
        byte[] Encrypt(byte[] data);
        byte[] PromptToDecrypt(byte[] data);
        void ClaimCurrentCacheType(AuthCacheType authCacheType);
        AuthCacheType CurrentCacheType { get; }
    }

    static class AuthProviderFactory
    {
        public static IAuthProvider GetInstance(IntPtr keePassWindowHandle, AuthCacheType authCacheType)
        {
            var provider = WinHelloProvider.CreateInstance(authCacheType);

            return new WinHelloProviderForegroundDecorator(provider, keePassWindowHandle);
        }
    }
}