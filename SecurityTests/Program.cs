using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityTests
{
    class Program
    {
        public static bool _isDefaultKeyName = true;
        public static string pkn;
        static void Main()
        {
            string keyname = "TestKey";
            
            Console.WriteLine("Starting...");

            Console.Write("Provide a Key name or press 'y' to use default KeePassWinHello key: ");
            var pname = Console.ReadLine();
            keyname = (pname == "") ? keyname : pname;
            pkn = (pname.ToLower() == "y") ? WinHelloProvider.RetreivePersistentKeyName() : WinHelloProvider.CustomKeyName(keyname);

            if (pkn == WinHelloProvider.RetreivePersistentKeyName())
            {
                IntPtr ip = new IntPtr();
                var myManager = new KeyManager(ip);
                if (WinHelloProvider.CheckProperty())
                {
                    Console.WriteLine("The Default key is signed. Replacing...");
                    WinHelloProvider.CreatePersistentKey(true);
                }
                else
                {
                    Console.WriteLine("The key is not signed. Decryting all credentials found");
                    var credentials = myManager._keyStorage.ListAll();

                    foreach(var credential in credentials)
                    {
                        Console.WriteLine(" ");
                        string dbPath = credential.Substring(16);
                        Console.WriteLine(dbPath + " password is: " + myManager.DecryptString(dbPath));
                    }
                }
            }
            else
            {
                _isDefaultKeyName = false;
                IntPtr ip = new IntPtr();
                var myManager = new KeyManager(ip);

                Console.Write("Enter the string you with to encrypt:");
                string toEncrypt = Console.ReadLine();
                toEncrypt = (toEncrypt == "") ? "This is the default encrypted string" : toEncrypt;

                EncryptData(myManager, keyname, toEncrypt);

                DecryptData(myManager, keyname);

                DeleteKeyAndCredential(myManager, keyname);
            }

            void EncryptData(KeyManager myManager, string dataName, string dataToEncrypt)
            {
                Console.WriteLine("Encrypting " + dataName + " data.");
                myManager.EncryptString(dataName, dataToEncrypt);
            }

            void DecryptData(KeyManager myManager, string dataName)
            {
                Console.WriteLine("Decrypting " + keyname + " data." + "\n");
                Console.WriteLine(keyname + " password is: " + myManager.DecryptString(keyname) + "\n");

            }

            void DeleteKeyAndCredential(KeyManager myManager, string dataName)
            {
                WinHelloProvider.DeletePersistentKey2();
                KeyWindowsStorage.DeleteCred(dataName);
            }





            Console.ReadKey();
        }
    }
}
