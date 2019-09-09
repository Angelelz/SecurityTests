# SecurityTests
Console app to extract the password of KeePass databases that uses KeePassWinHello plugin v3.1 with persistent key.

# To use:
- When you execute the app for the first time, it will replace the signed key used by KeePassWinHello plugin with another that is not signed. The plugin will automatically use that one and update its credential.
- When you execute the app with a key that is not signed, it will automatically show all the passwords saved by KeePassWinHello plugin.

- The option to use a different key name was used for testing purposes.
