using System;
using System.Collections.Generic;

namespace SecurityTests
{
    interface IKeyStorage
    {
        int Count { get; }

        List<string> ListAll();
        void AddOrUpdate(string dbPath, KeePassWinHello.ProtectedKey protectedKey);
        bool TryGetValue(string dbPath, out KeePassWinHello.ProtectedKey protectedKey);
        bool ContainsKey(string dbPath);
        void Remove(string dbPath);
        void Purge();
        void Clear();
    }

    static class KeyStorageFactory
    {
        public static IKeyStorage Create(IAuthProvider authProvider)
        {
                return new KeyWindowsStorage();
        }
    }
}