using System;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using KeePass.Forms;
using KeePassLib.Keys;
using KeePassLib.Serialization;
using KeePassLib.Security;

namespace SecurityTests
{
    interface IKeyManager
    {
        int KeysCount { get; }

        void RevokeAll();
        void ClaimCurrentCacheType(AuthCacheType authCacheType);
    }

    class KeyManager : IKeyManager
    {
        public IKeyStorage _keyStorage;
        private readonly KeyCipher _keyCipher;
        private readonly IntPtr _keePassMainWindowHandle;

        public int  KeysCount   { get { return _keyStorage.Count; } }

        public KeyManager(IntPtr windowHandle)
        {
            //Console.WriteLine("Handle: " + windowHandle);
            _keePassMainWindowHandle = windowHandle;
            _keyCipher = new KeyCipher(windowHandle);
            _keyStorage = KeyStorageFactory.Create(_keyCipher.AuthProvider);
            Console.WriteLine("Created KeyManager Instance.");
        }

        public string DecryptString(string dbPath)
        {

            
            if (ExtractCompositeKey(dbPath, out CompositeKey compositeKey))
            {

                KcpPassword pass = (KcpPassword)compositeKey.GetUserKey(typeof(KcpPassword));
                var mpass = pass.Password;
                return mpass.ReadString();
            }
            else
                return null;
                
        }

        public void EncryptString(string keyname, string mypass)
        {
            var ck = new CompositeKey();
            var kps = new KcpPassword(mypass);
            ck.AddUserKey(kps);
            _keyStorage.AddOrUpdate(keyname, KeePassWinHello.ProtectedKey.Create(ck, _keyCipher));
            
        }



        public void RevokeAll()
        {
            _keyStorage.Clear();
        }

        public void ClaimCurrentCacheType(AuthCacheType authCacheType)
        {
            try
            {
                _keyCipher.AuthProvider.ClaimCurrentCacheType(authCacheType);
                _keyStorage.Clear();
                _keyStorage = KeyStorageFactory.Create(_keyCipher.AuthProvider);
                // todo migrate
            }
            catch
            {

                MessageBox.Show(AuthProviderUIContext.Current, "Creating persistent key for Credential Manager has been canceled", "KeePassWinHello", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private static void CloseFormWithResult(KeyPromptForm keyPromptForm, DialogResult result)
        {
            // Remove flushing
            keyPromptForm.Visible = false;
            keyPromptForm.Opacity = 0;

            keyPromptForm.DialogResult = result;
            keyPromptForm.Close();
        }

        private static void ReOpenKeyPromptForm(MainForm mainWindow, IOConnectionInfo dbFile)
        {
            Action action = () => mainWindow.OpenDatabase(dbFile, null, false);
            mainWindow.Invoke(action);
        }

        private bool IsKeyForDataBaseExist(string dbPath)
        {
            return !String.IsNullOrEmpty(dbPath)
                && _keyStorage.ContainsKey(dbPath);
        }

        private bool ExtractCompositeKey(string dbPath, out CompositeKey compositeKey)
        {
            compositeKey = null;

            if (String.IsNullOrEmpty(dbPath))
                return false;

            KeePassWinHello.ProtectedKey encryptedData;
            if (!_keyStorage.TryGetValue(dbPath, out encryptedData))
                return false;

            if (!(encryptedData != null))
                MessageBox.Show("encryptedDataNull");
            
            try
            {
                using (AuthProviderUIContext.With("Authentication to hack", _keePassMainWindowHandle))
                {
                    
                    compositeKey = encryptedData.GetCompositeKey(_keyCipher);
                    
                    return true;
                }
            }
            catch (Exception)
            {
                _keyStorage.Remove(dbPath);
                //throw;
                return false;
            }
        }

        private static void SetCompositeKey(KeyPromptForm keyPromptForm, CompositeKey compositeKey)
        {
            var fieldInfo = keyPromptForm.GetType().GetField("m_pKey", BindingFlags.Instance | BindingFlags.NonPublic);
            if (fieldInfo != null)
                fieldInfo.SetValue(keyPromptForm, compositeKey);
        }

        private static bool IsDBLocking(FileClosingEventArgs e)
        {
            try
            {
                var FlagsProperty = typeof(FileClosingEventArgs).GetProperty("Flags");
                if (FlagsProperty == null)
                    return true;

                var FlagsType = FlagsProperty.PropertyType;
                int FlagsValue = Convert.ToInt32(FlagsProperty.GetValue(e, null));

                var names = Enum.GetNames(FlagsType);
                for (int i = 0; i != names.Length; ++i)
                {
                    if (names[i] == "Locking")
                    {
                        int Locking = Convert.ToInt32(Enum.GetValues(FlagsType).GetValue(i));
                        if ((FlagsValue & Locking) != Locking)
                        {
                            return false;
                        }
                        break;
                    }
                }
            }
            catch { }
            return true;
        }

        private static string GetDbPath(KeyPromptForm keyPromptForm)
        {
            var ioInfo = GetIoInfo(keyPromptForm);
            if (ioInfo == null)
                return null;
            return ioInfo.Path;
        }

        private static IOConnectionInfo GetIoInfo(KeyPromptForm keyPromptForm)
        {
            var fieldInfo = keyPromptForm.GetType().GetField("m_ioInfo", BindingFlags.Instance | BindingFlags.NonPublic);
            if (fieldInfo == null)
                return null;
            return fieldInfo.GetValue(keyPromptForm) as IOConnectionInfo;
        }
    }
}
