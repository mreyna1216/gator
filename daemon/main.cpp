/**
 * Copyright (C) ARM Limited 2010-2011. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

typedef unsigned long long uint64_t;
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include "Child.h"
#include "SessionData.h"
#include "OlySocket.h"
#include "Logging.h"
#include "OlyUtility.h"

#define DEBUG false 

extern Child* child;
extern void handleException();
int shutdownFilesystem();
static pthread_mutex_t numSessions_mutex;
static int numSessions = 0;
static OlySocket* socket = NULL;
static bool driverRunningAtStart = false;

struct cmdline_t {
	int port;
	char* sessionXML;
};

void cleanUp() {
	if (shutdownFilesystem() == -1) {
		logg->logMessage("Error shutting down gator filesystem");
	}
	delete socket;
	delete util;
	delete logg;
}

// CTRL C Signal Handler
void handler(int signum) {
	logg->logMessage("Received signal %d, gator daemon exiting", signum);
	if (numSessions > 0) {
		// Kill child threads
		logg->logMessage("Killing process group as %d child was running when signal was received", numSessions);
		kill(0, SIGINT);
	}

	cleanUp();
	exit(0);
}

// Child exit Signal Handler
void child_exit(int signum) {
	int status;
	int pid = wait(&status);
	if (pid != -1) {
		pthread_mutex_lock(&numSessions_mutex);
		numSessions--;
		pthread_mutex_unlock(&numSessions_mutex);
		logg->logMessage("Child process %d exited with status %d", pid, status);
	}
}

// retval: -1 = failure; 0 = was already mounted; 1 = successfully mounted
int mountGatorFS() {
	// If already mounted,
	if (access("/dev/gator/buffer", F_OK) != -1)
		return 0;

	// else, mount the filesystem
	mkdir("/dev/gator", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	if (mount("nodev", "/dev/gator", "gatorfs", 0, NULL) != 0)
		return -1;
	else
		return 1;
}

int setupFilesystem() {
	// Verify root permissions
	uid_t euid = geteuid();
	if (euid) {
		logg->logError(__FILE__, __LINE__, "gatord must be launched with root privileges");
		handleException();
	}

	if (mountGatorFS() >= 0) {
		logg->logMessage("Driver already running at startup");
		driverRunningAtStart = true;
	} else {
		// Load driver
		char command[512];
		strcpy(command, "insmod ");
		if (util->getApplicationFullPath(&command[7], sizeof(command) - 64) != 0) {
			logg->logMessage("Unable to determine the full path of gatord, the cwd will be used");
		}
		strcat(command, "gator.ko >/dev/null 2>&1");
		if (system(command) != 0) {
			logg->logMessage("Unable to load gator.ko driver with command: %s", command);
			logg->logError(__FILE__, __LINE__, "Unable to load (insmod) gator.ko driver. %s", DRIVER_ERROR);
			handleException();
		}

		if (mountGatorFS() == -1) {
			logg->logError(__FILE__, __LINE__, "Unable to mount the gator filesystem needed for profiling.");
			handleException();
		}
	}

	return 0;
}

int shutdownFilesystem() {
	umount("/dev/gator");
	if (driverRunningAtStart == true || system("rmmod gator >/dev/null 2>&1") == 0) {
		return 0;
	}

	return -1;
}

struct cmdline_t parseCommandLine(int argc, char** argv) {
	struct cmdline_t cmdline;
	cmdline.port = 8080;
	cmdline.sessionXML = NULL;

	for (int i = 1; i < argc; i++) {
		// Is the argument a number?
		if (atoi(argv[i]) > 0) {
			cmdline.port = atoi(argv[i]);
			continue;
		}

		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "--help") == 0) {
			logg->logError(__FILE__, __LINE__,
				"Streamline gatord version %d. All parameters are optional:\n"
				"port_number\tport upon which the server listens; default is 8080\n"
				"session_xml\tfilename of a session xml used for local capture\n"
				"-v/--version\tversion information\n"
				"-h/--help\tthis help page\n", PROTOCOL_VERSION);
			handleException();
		} else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
			logg->logError(__FILE__, __LINE__, "Streamline gatord version %d", PROTOCOL_VERSION);
			handleException();
		} else {
			// Assume it is an .xml file
			cmdline.sessionXML = argv[i];
		}
	}

	// Error checking
	if (cmdline.port != 8080 && cmdline.sessionXML != NULL) {
		logg->logError(__FILE__, __LINE__, "Only a port or a session xml can be specified, not both");
		handleException();
	}

	return cmdline;
}

// Gator data flow: collector -> collector fifo -> sender
int main(int argc, char** argv, char *envp[]) {
	logg = new Logging(DEBUG);  // Set up global thread-safe logging
	util = new OlyUtility();	// Set up global utility class

	prctl(PR_SET_NAME, (unsigned int)&"gatord-main", 0, 0, 0);
	pthread_mutex_init(&numSessions_mutex, NULL);

	signal(SIGINT, handler);
	signal(SIGTERM, handler);
	signal(SIGABRT, handler);

	// Set to high priority
	setpriority(PRIO_PROCESS, syscall(__NR_gettid), -19);

	// Initialize session data
	gSessionData.initialize();

	// Parse the command line parameters
	struct cmdline_t cmdline = parseCommandLine(argc, argv);

	// Call before setting up the SIGCHLD handler, as system() spawns child processes
	setupFilesystem();

	// Handle child exit codes
	signal(SIGCHLD, child_exit);

	// Ignore the SIGPIPE signal so that any send to a broken socket will return an error code instead of asserting a signal
	// Handling the error at the send function call is much easier than trying to do anything intelligent in the sig handler
	signal(SIGPIPE, SIG_IGN);

	// If the command line argument is a session xml file, no need to open a socket
	if (cmdline.sessionXML) {
		child = new Child(cmdline.sessionXML);
		child->run();
		delete child;
	} else {
		socket = new OlySocket(cmdline.port, true);
		// Forever loop, can be exited via a signal or exception
		while (1) {
			logg->logMessage("Waiting on connection...");
			socket->acceptConnection();

			int pid = fork();
			if (pid < 0) {
				// Error
				logg->logError(__FILE__, __LINE__, "Fork process failed. Please power cycle the target device if this error persists.");
			} else if (pid == 0) {
				// Child
				strncpy(argv[0],"gatorc",strlen(argv[0])); // rename command line name to gatorc
				socket->closeServerSocket();
				child = new Child(socket, numSessions + 1);
				child->run();
				delete child;
				exit(0);
			} else {
				// Parent
				socket->closeSocket();

				pthread_mutex_lock(&numSessions_mutex);
				numSessions++;
				pthread_mutex_unlock(&numSessions_mutex);

				// Maximum number of connections is 2
				int wait = 0;
				while (numSessions > 1) {
					// Throttle until one of the children exits before continuing to accept another socket connection
					logg->logMessage("%d sessions active!", numSessions);
					if (wait++ >= 10) { // Wait no more than 10 seconds
						// Kill last created child
						kill(pid, SIGALRM);
						break;
					}
					sleep(1);
				}
			}
		}
	}

	cleanUp();
	return 0;
}
