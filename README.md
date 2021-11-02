# BE-Shellcode
Code for Battleyes shellcode
- Exception handler that checks for return addresses that match report criteria
- find hidden system threads by checking kernel time delta
- detect hooks that want to catch exceptions (KiUserExceptionDispatcher)
- detect blacklisted dlls (+checks for import etc) + blacklisted drivers
- check integrity of important functions
- check all threads in local process and find RIPs that match report criteria
- find blacklisted signatures
