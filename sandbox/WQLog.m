//
//  WQLog.m
//  sandbox
//

#import "WQLog.h"

#import <UIKit/UIKit.h>

#import <signal.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

// The signal handler cannot allocate, so it needs a plain C path and fd.
static char gSignalPath[PATH_MAX];
static char gSignalBuffer[16384];
static volatile int gSignalBufferLength = -1;

// Batched writer state (main-thread only).
static NSMutableString *gPending;
static NSLock *gWriteLock;
static const NSUInteger kFlushThreshold = 16384;
static const size_t kLogLimit = 1024 * 1024;

static NSString *wq_log_path(void) {
    static NSString *path;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // Documents is exposed in the Files app when UIFileSharingEnabled is
        // set, which is how the log is retrieved when the app misbehaves.
        NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        if (documents.length == 0) documents = NSTemporaryDirectory();
        path = [documents stringByAppendingPathComponent:@"wq.log"];
        strlcpy(gSignalPath, path.fileSystemRepresentation, sizeof(gSignalPath));
    });
    return path;
}

static void wq_append(NSString *text) {
    if (text.length == 0) return;
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    int fd = open(gSignalPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;

    struct stat st;
    if (fstat(fd, &st) == 0 && (size_t)st.st_size > kLogLimit) ftruncate(fd, 0);
    write(fd, data.bytes, data.length);
    close(fd);
}

@implementation WQLog

+ (NSString *)logPath { return wq_log_path(); }

+ (void)log:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    [self message:line];
}

+ (void)message:(NSString *)text {
    if (text == nil) return;
    wq_log_path();

    static NSDateFormatter *formatter;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        formatter = [NSDateFormatter new];
        formatter.dateFormat = @"HH:mm:ss.SSS";
    });

    NSString *stamped = [NSString stringWithFormat:@"%@ %@\n",
                         [formatter stringFromDate:[NSDate date]], text];
    NSLog(@"[wq] %@", text);

    if (!gWriteLock) gWriteLock = [NSLock new];
    [gWriteLock lock];
    if (!gPending) gPending = [NSMutableString new];
    [gPending appendString:stamped];
    BOOL flushNow = gPending.length >= kFlushThreshold;
    [gWriteLock unlock];

    // Refusals during a scan can produce thousands of lines; writing each one
    // separately made the app look frozen.
    if (flushNow) [self flush];
}

+ (void)flush {
    if (!gWriteLock) return;
    [gWriteLock lock];
    NSString *pending = [gPending copy];
    [gPending setString:@""];
    [gWriteLock unlock];
    if (pending.length) wq_append(pending);
}

+ (NSString *)logContents {
    [self flush];
    NSData *data = [NSData dataWithContentsOfFile:wq_log_path()
                                         options:NSDataReadingMappedIfSafe
                                           error:NULL];
    if (!data) return @"";
    // The tail is what matters when the file is large.
    NSUInteger limit = 200 * 1024;
    if (data.length > limit) data = [data subdataWithRange:NSMakeRange(data.length - limit, limit)];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
}

+ (void)clearLog {
    [self flush];
    [@"" writeToFile:wq_log_path() atomically:YES encoding:NSUTF8StringEncoding error:NULL];
}

// MARK: Crash handling

static void wq_signal_handler(int signalNumber) {
    // Drain the in-memory buffer without Objective-C or locks.
    if (gSignalBufferLength > 0) {
        int fd = open(gSignalPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            write(fd, gSignalBuffer, (size_t)gSignalBufferLength);
            close(fd);
        }
        gSignalBufferLength = 0;
    }
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "!!! signal %d (%s) — process terminated here\n",
             signalNumber, strsignal(signalNumber));
    int fd = open(gSignalPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        write(fd, buffer, strlen(buffer));
        close(fd);
    }
    signal(signalNumber, SIG_DFL);
    raise(signalNumber);
}

static void wq_exception_handler(NSException *exception) {
    NSString *text = [NSString stringWithFormat:@"!!! exception %@: %@\n%@\n",
                      exception.name, exception.reason,
                      [exception.callStackSymbols componentsJoinedByString:@"\n"]];
    wq_append(text);
}

+ (void)installCrashHandlers {
    wq_log_path();   // fills gSignalPath

    // Duplicate the pending buffer where the signal handler can reach it.
    if (!gPending) gPending = [NSMutableString new];
    gSignalBufferLength = 0;

    NSSetUncaughtExceptionHandler(&wq_exception_handler);
    int numbers[] = { SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGFPE };
    for (size_t i = 0; i < sizeof(numbers) / sizeof(numbers[0]); i++) {
        signal(numbers[i], wq_signal_handler);
    }

    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidEnterBackgroundNotification
                                                      object:nil
                                                       queue:nil
                                                  usingBlock:^(NSNotification *note) {
        [WQLog flush];
    }];
    [self message:@"=== session start ==="];
}

@end
