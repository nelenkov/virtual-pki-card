Virtual PKI Smart Card
======================

Virtual PKI smart card using CyanogenMod 9.1 software card emulation. 
See related article for details: 

http://nelenkov.blogspot.com/2012/10/emulating-pki-smart-card-with.html

### How to use

Running the Android application requires CyanogenMod 9.1 or later 
with software card emulation patches applied. The app will start 
on other version, but the applet will never get activated. Make 
sure you are using a compatible CM version. You also need a 
supported NFC-enabled device. Tested with Galaxy Nexus, should 
work with any PN544-based device.

#### Build and install the Android app

1. Import the 'se-emulator' project in Eclipse.
2. Run on a compatible device.
3. Place a PKCS#12 file in /sdcard/ and install via the app UI.
4. Set a PIN. 
5. Run the client application on a machine with a contactless 
reader connected (see below). 
6. Place phone on reader to activate applet. 

#### Build and start the host client

1. Import the 'se-pki-client' in Eclipse.
2. Make sure the PC/SC stack on your machine works. 
3. Connect a supported contactless reader. 
4. Edit the run.sh script as necessary. 
5. Run the app and place phone on reader to start.


