//
//  WQLog.h
//  sandbox
//
//  File log written to Documents so it is reachable from the Files app even
//  when the in-app viewer cannot be opened. Lines are buffered and flushed in
//  batches: opening and closing the file per line was far too slow.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WQLog : NSObject

/// Queues a line. Formatting is immediate, the write is batched.
+ (void)log:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2);

/// Swift-friendly variant: no format string, so no vararg type mismatch.
+ (void)message:(NSString *)text NS_SWIFT_NAME(message(_:));

/// Writes buffered lines. Called on backgrounding and before a crash dump.
+ (void)flush NS_SWIFT_NAME(flush());

/// Installs uncaught-exception and fatal-signal handlers.
+ (void)installCrashHandlers;

/// Documents/wq.log — visible in the Files app.
+ (NSString *)logPath NS_SWIFT_NAME(logPath());
+ (NSString *)logContents NS_SWIFT_NAME(logContents());
+ (void)clearLog NS_SWIFT_NAME(clearLog());

@end

NS_ASSUME_NONNULL_END
