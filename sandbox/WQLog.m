//
//  WQLog.m
//  sandbox
//

#import "WQLog.h"

#import <signal.h>
#import <execinfo.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

// The crash handlers cannot allocate, so the log has to be reachable without
// Objective-C or locks: one fixed-size static buffer, appended with write(2).
static char gSignalPath[PATH_MAX];
static int gSignalFd = -1;
static const size_t kLogLimit = 512 * 1024;

static NSString *wq_log_path(void) {
    static NSString *path;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *caches = [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject];
        if (caches.length == 0) caches = NSTemporaryDirectory();
        path = [caches stringByAppendingPathComponent:@"wq.log"];
        strlcpy(gSignalPath, path.fileSystemRepresentation, sizeof(gSignalPath));
    });
    return path;
}

@implementation WQLog

+ (NSString *)logPath { return wq_log_path(); }

+ (void)message:(NSString *)text {
    [self log:@"%@", text ?: @""];
}

+ (void)log:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSDateFormatter *formatter = [NSDateFormatter new];
    formatter.dateFormat = @"HH:mm:ss";
    NSString *stamped = [NSString stringWithFormat:@"%@ %@\n",
                         [formatter stringFromDate:[NSDate date]], line];
    NSLog(@"[wq] %@", line);

    NSData *data = [stamped dataUsingEncoding:NSUTF8StringEncoding];
    if (data.length == 0) return;

    int fd = open(gSignalPath[0] ? gSignalPath : wq_log_path().fileSystemRepresentation,
                  O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;

    struct stat st;
    if (fstat(fd, &st) == 0 && (size_t)st.st_size > kLogLimit) {
        ftruncate(fd, 0);
    }
    write(fd, data.bytes, data.length);
    close(fd);
}

+ (NSString *)logContents {
    NSString *contents = [NSString stringWithContentsOfFile:wq_log_path()
                                                  encoding:NSUTF8StringEncoding
                                                     error:NULL];
    return contents ?: @"";
}

+ (void)clearLog {
    [@"" writeToFile:wq_log_path() atomically:YES encoding:NSUTF8StringEncoding error:NULL];
}

// MARK: Crash handling

static void wq_write_raw(const char *text) {
    if (gSignalFd < 0) gSignalFd = open(gSignalPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (gSignalFd < 0) return;
    write(gSignalFd, text, strlen(text));
}

static void wq_signal_handler(int signalNumber) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "!!! signal %d (%s) — process was terminated here\n",
             signalNumber, strsignal(signalNumber));
    wq_write_raw(buffer);
    signal(signalNumber, SIG_DFL);
    raise(signalNumber);
}

static void wq_exception_handler(NSException *exception) {
    NSString *text = [NSString stringWithFormat:@"!!! exception %@: %@\n%@\n",
                      exception.name, exception.reason,
                      [exception.callStackSymbols componentsJoinedByString:@"\n"]];
    wq_write_raw(text.UTF8String);
}

+ (void)installCrashHandlers {
    wq_log_path();   // fills gSignalPath
    NSSetUncaughtExceptionHandler(&wq_exception_handler);
    // SIGKILL cannot be caught; installing it would be a false promise.
    int numbers[] = { SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGFPE };
    for (size_t i = 0; i < sizeof(numbers) / sizeof(numbers[0]); i++) {
        signal(numbers[i], wq_signal_handler);
    }
    [self log:@"=== session start ==="];
}

@end
