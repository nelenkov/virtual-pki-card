#!/bin/sh

JAVA_HOME=/usr/local/jdk
$JAVA_HOME/bin/java -Dsun.security.smartcardio.library=/usr/local/lib/libpcsclite.so -cp bin/ org.nick.sepkiclient.Main $*

