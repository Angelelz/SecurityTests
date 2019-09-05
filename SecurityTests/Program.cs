using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityTests
{
    class Program
    {
        static void Main()
        {
            Console.WriteLine("Starting");
            IntPtr ip = new IntPtr();
            var myManager = new KeyManager(ip);
            Console.WriteLine(myManager.OnKeyPrompt());
            Console.ReadKey();
        }
    }
}
