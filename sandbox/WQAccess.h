//
//  WQAccess.h
//  sandbox
//
//  Sandbox access layer built on worse_query.
//  Exploit: https://github.com/forcequitOS/worse_query (GPL-3.0-or-later)
//

#import <Foundation/Foundation.h>
#include <stdint.h>

NS_ASSUME_NONNULL_BEGIN

/// One container (or filesystem entry) reachable through worse_query.
@interface WQItem : NSObject
@property (nonatomic, copy) NSString *path;
@property (nonatomic, copy) NSString *name;
/// `MCMMetadataIdentifier` when it can be read, otherwise the container UUID.
@property (nonatomic, copy, nullable) NSString *identifier;
/// Bundle id parsed from the identifier, when the identifier looks like one.
@property (nonatomic, copy, nullable) NSString *bundleID;
@property (nonatomic, assign) uint64_t containerClass;
@property (nonatomic, assign) BOOL isDirectory;
@property (nonatomic, assign) long long size;
@property (nonatomic, copy, nullable) NSDate *modified;
@end

@interface WQAccess : NSObject

/// worse_query covers iOS 26.0 – 26.7.2 and 27.0 – 27.2.x. NO elsewhere.
+ (BOOL)isSupported;

/// The App Group this app is entitled to, or nil when the build or install
/// method did not give it one (worse_query cannot work without a group).
+ (nullable NSString *)appGroup;

/// Path of the App Group container, creating it if iOS has not done so yet.
/// nil when the group exists but the container cannot be resolved.
+ (nullable NSString *)appGroupContainerPath;
+ (void)setAppGroupOverride:(nullable NSString *)group;

/// Consumes a sandbox extension for `path` (and, if needed, its parents) and
/// verifies the path is actually openable. Cached; the oldest handle is
/// released when the kernel limit is reached.
+ (BOOL)ensureAccess:(NSString *)path;
/// Grants without the parent walk; use ensureAccess in normal code.
+ (BOOL)grant:(NSString *)path;
/// Drops every cached extension.
+ (void)releaseGrants;

/// Forgets which paths were refused, so the next call asks again.
+ (void)forgetDeniedPaths;
/// Number of cached extensions.
+ (NSUInteger)grantCount;

/// Last failure reason for the calling thread, or nil.
+ (nullable NSString *)lastError;
+ (void)clearLastError;

/// Containers found through the container manager (classes 1…14), falling back
/// to listing the well known container parents.
+ (NSArray<WQItem *> *)containers;
/// Container discovery diagnostics from the last call (one line per step).
+ (NSString *)containerSummary;

/// `MCMMetadataIdentifier` for a container, when the file is readable.
+ (nullable NSString *)containerIdentifier:(NSString *)path;

/// Directory listing (empty array and `lastError` set on failure).
+ (NSArray<WQItem *> *)contentsOfDirectory:(NSString *)path NS_SWIFT_NAME(contentsOfDirectory(_:));

/// File contents, capped at `maxBytes` (nil and `lastError` set on failure).
+ (nullable NSData *)dataAtPath:(NSString *)path maxBytes:(NSUInteger)maxBytes NS_SWIFT_NAME(data(atPath:maxBytes:));

+ (BOOL)isReadable:(NSString *)path;
+ (BOOL)exists:(NSString *)path;

/// Children of a container parent that cannot be listed (iOS 27 gives no
/// extension for the parent). Brute-forces file ids; slow on first use, so
/// callers should ask the user before running it. Returns paths only.
+ (NSArray<NSString *> *)leakedChildrenOfDirectory:(NSString *)path limit:(NSUInteger)limit
    NS_SWIFT_NAME(leakedChildren(ofDirectory:limit:));

/// Alias of contentsOfDirectory. Directories below a container parent can
/// only be discovered with -leakedChildrenOfDirectory:limit:, which is slow
/// enough that it must stay behind an explicit user action.
+ (NSArray<WQItem *> *)childrenOfDirectory:(NSString *)path
    NS_SWIFT_NAME(children(ofDirectory:));

/// Turns paths returned by -leakedChildrenOfDirectory:limit: into items.
+ (NSArray<WQItem *> *)itemsForLeakedPaths:(NSArray<NSString *> *)paths
    NS_SWIFT_NAME(items(forLeakedPaths:));

/// Breadth-first search below `root`. An empty `query` matches everything.
/// `progress` returns NO to stop the walk.
+ (NSArray<WQItem *> *)searchPath:(NSString *)root
                            query:(NSString *)query
                         maxDepth:(NSUInteger)maxDepth
                            limit:(NSUInteger)limit
                         progress:(nullable BOOL (^)(NSString *current))progress
    NS_SWIFT_NAME(searchPath(_:query:maxDepth:limit:progress:));

@end

NS_ASSUME_NONNULL_END
