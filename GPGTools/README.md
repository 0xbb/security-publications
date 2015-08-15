## GPGTools installerHelper - setuid Local Privilege Escalation

##### Author:
* Bruno Bierbaumer

##### Tracking and CVE:
* [CVE-2014-4677](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2014-4677)

##### Affected version(s):
* < GPGTools 2014.12-b4

##### Fixed version:
* GPGTools 2015.06
* GPGTools 2015.08 - vulnerability disclosed ([Release Notes](https://gpgtools.org/releases/gpgsuite/2015.08/release-notes.html)) 

### Vulnerability:
GPGTools ships with a set-setuid installHelper binary:

```
$ ls -l /Library/Frameworks/Libmacgpg.framework/Versions/Current/Resources/

-rw-r--r--  1 root  wheel   1252 Oct 23  2013 Info.plist
-rw-r--r--  1 root  wheel    407 Oct 23  2013 Keyservers.plist
drwxr-xr-x  3 root  wheel    102 Aug 15 13:06 de.lproj
drwxr-xr-x  3 root  wheel    102 Aug 15 13:06 en.lproj
-rwsr-xr-x  1 root  wheel  68576 Oct 23  2013 installerHelper
-rw-r--r--  1 root  wheel    550 Oct 23  2013 org.gpgtools.Libmacgpg.xpc.plist
drwxr-xr-x  3 root  wheel    102 Aug 15 13:06 pinentry-mac.app
```

installHelper is used to install signed pkg-files as a normal user without root privileges:
```
$ /Library/Frameworks/Libmacgpg.framework/Versions/Current/Resources/installerHelper

Usage: installerHelper pkg-file [xml-file]
This tool checks the signature of an pkg file and installs it.
You can specify a xml-file to override the standard choices.
```

[installHelper](https://github.com/GPGTools/Libmacgpg/blob/246bbc62841847e591bc80c5926834c481bb96bb/installerHelper/main.m) installs pkg-files by passing 
the pkg-file path and the xml-file path into the ``installPackage`` function:
```objc
BOOL installPackage(NSString *pkgPath, NSString *xmlPath) {
	// Run the installer command.
	NSString *commandString;
	if (xmlPath) {
		commandString = [NSString stringWithFormat:@"/usr/sbin/installer -applyChoiceChangesXML \"%@\" -pkg \"%@\" -target /", xmlPath, pkgPath];
	}
	else {
		commandString = [NSString stringWithFormat:@"/usr/sbin/installer -pkg \"%@\" -target /", pkgPath];
	}
	
	const char *command = [commandString UTF8String];
	
	uid_t uid = getuid();
	int result = setuid(0);
	if (result == 0) {
		//Run only this command with root privileges.
		result = system(command);
		setuid(uid);
	} else {
		printf("This tool needs the setuid-bit to be set and the owner must be root!\nStart a normal installation using the GUI.\n");
		
		commandString = [NSString stringWithFormat:@"/usr/bin/open -Wnb com.apple.installer \"%@\"", pkgPath];
		command = [commandString UTF8String];
		
		result = system(command);
	}
	
	
	return !!result;
}
```
``installPackage`` directly passed the two paths into the ``system`` function and therefore is vulnerable to command injection.

### Exploitation / Proof of Concept:

The PoC makes use of the command substitution (`` `command` ``) applied by ``system`` to injection user-defined commands.

Before ``installPackage`` is called several  requirements need to be fulfilled ([see here](https://github.com/GPGTools/Libmacgpg/blob/246bbc62841847e591bc80c5926834c481bb96bb/installerHelper/main.m#L13-L48)):
* the pkg-file must exist
* the pkg-file must be signed with GPGTools's key
* if passed the xml-file must exist

A signed pkg-file (``Install.pkg``) can be obtained by downloading an [older release of GPGTools](./GPGTools/GPG%20Suite%20-%202013.10.22.dmg).   
Versions after 2014.12-b4 won't work, because the signing key has been replaced to prevent downgrading of fixed installHelper versions to vulnerable ones. 

After fulfilling the pkg-file requirements we want to inject commands via the xml-file path.   
Therefore we create a  file called `` `dummy` `` and pass it as xml-file to installHelper.  
installHelper will accept it as a valid path and the command ``dummy`` will get executed with elevated rights.  
So if we put an executable file named ``dummy`` into ``$PATH`` it will get executed.

For futher details check out the full PoC: [CVE-2014-4677.sh](./GPGTools/CVE-2014-4677.sh)

![CVE-2014-4677-PoC](./GPGTools/images/CVE-2014-4677.png)

