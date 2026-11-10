//
//  WQLog.h
//  sandbox
//
//  File log + crash handlers. Scans run outside the app's own data, so when
//  something kills the process the only evidence is what was written first.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WQLog : NSObject

/// Appends a line to Library/Caches/wq.log (trimmed at 512 KB).
+ (void)log:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2);

/// Swift-friendly variant: no format string, so no vararg type mismatch.
+ (void)message:(NSString *)text NS_SWIFT_NAME(message(_:));

/// Installs uncaught-exception and fatal-signal handlers that flush the log
/// and record the reason. Safe to call more than once.
+ (void)installCrashHandlers;

+ (NSString *)logPath NS_SWIFT_NAME(logPath());
+ (NSString *)logContents NS_SWIFT_NAME(logContents());
+ (void)clearLog NS_SWIFT_NAME(clearLog());

@end

NS_ASSUME_NONNULL_END
