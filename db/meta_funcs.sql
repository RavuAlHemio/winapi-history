UPDATE symbols SET is_meta_func=1 WHERE raw_name = 'DllCanUnloadNow'; -- called by COM servers
UPDATE symbols SET is_meta_func=1 WHERE raw_name = 'DllGetActivationFactory'; -- called by Windows Runtime servers
UPDATE symbols SET is_meta_func=1 WHERE raw_name = 'DllGetClassObject'; -- called by COM servers
UPDATE symbols SET is_meta_func=1 WHERE raw_name = 'DllInstall'; -- called by regsvr32
UPDATE symbols SET is_meta_func=1 WHERE raw_name = 'DllMain'; -- executed when DLL is loaded
UPDATE symbols SET is_meta_func=1 WHERE raw_name IN ('DllRegisterServer', 'DllUnregisterServer'); -- called by regsvr32
UPDATE symbols SET is_meta_func=1 WHERE raw_name = 'DriverProc'; -- executed by kernel
UPDATE symbols SET is_meta_func=1 WHERE raw_name = 'GetProxyDllInfo'; -- called by COM servers on proxy DLLs
UPDATE symbols SET is_meta_func=1 WHERE raw_name = 'KbdLayerDescriptor'; -- keyboard layout in a keyboard layout DLL
UPDATE symbols SET is_meta_func=1 WHERE raw_name = 'ServiceMain'; -- executed by service manager
