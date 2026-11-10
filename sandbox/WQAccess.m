//
//  WQAccess.m
//  sandbox
//
//  Sandbox access layer built on worse_query.
//  Exploit: https://github.com/forcequitOS/worse_query (GPL-3.0-or-later)
//

#import "WQAccess.h"
#import "Exploit/worse_query.h"
#import "Exploit/pathleak.h"

#import <dlfcn.h>
#import <dirent.h>
#import <errno.h>
#import <fcntl.h>
#import <stdio.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/xattr.h>
#import <unistd.h>
#import <xpc/xpc.h>

// SecTask lives in Security.framework and the two entry points are private,
// so they are resolved at runtime instead of being linked directly.
typedef struct __SecTask *SecTaskRef;
typedef SecTaskRef (*SecTaskCreateFromSelf_fn)(CFAllocatorRef);
typedef CFTypeRef (*SecTaskCopyValueForEntitlement_fn)(SecTaskRef, CFStringRef, CFErrorRef *);

static NSArray<NSString *> *wq_entitled_groups(void) {
    void *security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL);
    if (!security) security = dlopen("/usr/lib/libSecurity.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!security) return nil;

    SecTaskCreateFromSelf_fn create = (SecTaskCreateFromSelf_fn)dlsym(security, "SecTaskCreateFromSelf");
    SecTaskCopyValueForEntitlement_fn copy = (SecTaskCopyValueForEntitlement_fn)dlsym(security, "SecTaskCopyValueForEntitlement");
    if (!create || !copy) { dlclose(security); return nil; }

    SecTaskRef task = create(kCFAllocatorDefault);
    if (!task) { dlclose(security); return nil; }
    CFTypeRef value = copy(task, CFSTR("com.apple.security.application-groups"), NULL);
    CFRelease(task);
    dlclose(security);

    if (!value) return nil;
    if (CFGetTypeID(value) != CFArrayGetTypeID()) { CFRelease(value); return nil; }
    NSArray *groups = (__bridge_transfer NSArray *)value;
    return [groups isKindOfClass:NSArray.class] ? groups : nil;
}

#pragma mark - Item

@implementation WQItem
- (NSString *)description {
    return [NSString stringWithFormat:@"<WQItem %@ (%@) class=%llu>", self.name, self.path, self.containerClass];
}
@end

#pragma mark - Container manager

typedef void *(*cq_create_fn)(void);
typedef void (*cq_u64_fn)(void *, uint64_t);
typedef void (*cq_ids_fn)(void *, xpc_object_t);
typedef void *(*cq_single_fn)(void *);
typedef void (*cq_free_fn)(void *);
typedef void (*cq_iterate_fn)(void *, bool (^)(void *));
typedef const char *(*co_path_fn)(void *);
typedef const char *(*co_id_fn)(void *);
typedef xpc_object_t (*co_metadata_fn)(void *);

static void *wq_mcm_handle(void) {
    static void *handle;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        handle = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    });
    return handle;
}

#pragma mark - Access

static NSMutableDictionary<NSString *, NSNumber *> *gGrants;
static NSMutableArray<NSString *> *gGrantOrder;
static NSRecursiveLock *gGrantLock;
// The kernel caps how many extensions one process may hold.
static const NSUInteger kWQMaxGrants = 180;

static NSString *gGroupOverride;
static NSString *gContainerSummary = @"not scanned";
static NSString *gLastError;

static void wq_set_error(NSString *message) {
    gLastError = [message copy];
}

@implementation WQAccess

+ (BOOL)isSupported {
    // worse_query covers iOS 26.0 – 26.7.2 and 27.0 – 27.2.x.
    NSOperatingSystemVersion v = NSProcessInfo.processInfo.operatingSystemVersion;
    if (v.majorVersion == 26) return v.minorVersion <= 7;
    if (v.majorVersion == 27) return v.minorVersion <= 2;
    return NO;
}

+ (NSString *)appGroup {
    if (gGroupOverride.length) return gGroupOverride;

    static NSString *group;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSArray *groups = wq_entitled_groups();
        for (id candidate in groups) {
            if (![candidate isKindOfClass:NSString.class]) continue;
            if ([NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:candidate]) {
                group = [candidate copy];
                break;
            }
        }
        NSLog(@"[WQAccess] entitled groups: %@ → using %@",
              groups.count ? [groups componentsJoinedByString:@", "] : @"none", group ?: @"NONE");
    });
    return group;
}

+ (void)setAppGroupOverride:(NSString *)group {
    gGroupOverride = [group copy];
}

+ (NSString *)lastError { return gLastError; }
+ (void)clearLastError { gLastError = nil; }

+ (void)releaseGrants {
    @synchronized (NSNull.null) {
        for (NSString *key in gGrantOrder) worse_query_release(gGrants[key].longLongValue);
        [gGrants removeAllObjects];
        [gGrantOrder removeAllObjects];
    }
}

+ (NSUInteger)grantCount {
    @synchronized (NSNull.null) { return gGrantOrder.count; }
}

static NSString *wq_normalize(NSString *path) {
    NSString *p = path.stringByStandardizingPath;
    if ([p hasPrefix:@"/var/"]) p = [@"/private" stringByAppendingString:p];
    return p;
}

// A grant "works" when the path can be opened afterwards.
//
// Only a sandbox denial (EPERM) means the token did not help. EACCES is
// ordinary POSIX permission on root-owned system containers, which no token
// can change — WQ Files treats that as success too, since the extension was
// still issued. ENOENT/ENOTDIR mean the path itself is wrong, which a token
// cannot fix either, so those are failures.
static BOOL wq_path_opens(NSString *path) {
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) { close(fd); return YES; }
    return errno == EACCES;
}

+ (BOOL)ensureAccess:(NSString *)path {
    if (path.length == 0) return NO;
    if (wq_path_opens(path)) return YES;
    if ([self grant:path] && wq_path_opens(path)) return YES;

    // The extension covers the folder it was issued for; ask for the parent
    // (and one level above) when the target itself is not covered.
    NSString *candidate = path;
    for (NSUInteger level = 0; level < 3; level++) {
        candidate = candidate.stringByDeletingLastPathComponent;
        if (candidate.length <= 1) break;
        if ([self grant:candidate] && wq_path_opens(path)) return YES;
        struct stat parentStat;
        if (lstat(candidate.fileSystemRepresentation, &parentStat) != 0) break;
    }
    return NO;
}

+ (BOOL)grant:(NSString *)path {
    if (path.length == 0) return NO;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gGrants = [NSMutableDictionary new];
        gGrantOrder = [NSMutableArray new];
        gGrantLock = [NSRecursiveLock new];
    });

    NSString *key = wq_normalize(path);
    NSString *group = [self appGroup];
    if (group.length == 0) return NO;

    [gGrantLock lock];
    NSNumber *known = gGrants[key];
    if (known) {
        [gGrantOrder removeObject:key];
        [gGrantOrder addObject:key];
        [gGrantLock unlock];
        return YES;
    }
    while (gGrantOrder.count >= kWQMaxGrants) {
        NSString *oldest = gGrantOrder.firstObject;
        worse_query_release(gGrants[oldest].longLongValue);
        [gGrants removeObjectForKey:oldest];
        [gGrantOrder removeObjectAtIndex:0];
    }
    [gGrantLock unlock];

    struct stat st;
    if (lstat(key.fileSystemRepresentation, &st) != 0) return NO;

    // iOS 26 needs the legacy flag set, iOS 27 the current one. Try the likely
    // one first and fall back; remember which one worked.
    static int preferLegacy = -1;
    BOOL legacyFirst = preferLegacy >= 0 ? (BOOL)preferLegacy : (NSProcessInfo.processInfo.operatingSystemVersion.majorVersion < 27);
    int64_t handle = worse_query(key, group, legacyFirst, false);
    BOOL usedLegacy = legacyFirst;

    if (handle >= 0 && !wq_path_opens(key)) {
        worse_query_release(handle);
        handle = -8;
    }
    if (handle < 0 && handle != -255 && handle != -1 && handle != -2) {
        int64_t alternate = worse_query(key, group, !legacyFirst, false);
        if (alternate >= 0 && !wq_path_opens(key)) {
            worse_query_release(alternate);
            alternate = -8;
        }
        if (alternate >= 0) {
            handle = alternate;
            usedLegacy = !legacyFirst;
        }
    }
    if (handle < 0) {
        NSLog(@"[WQAccess] grant failed for %@: %lld (%@)", key, handle, worse_query_error(handle));
        return NO;
    }
    preferLegacy = usedLegacy ? 1 : 0;

    [gGrantLock lock];
    gGrants[key] = @(handle);
    [gGrantOrder addObject:key];
    [gGrantLock unlock];
    return YES;
}

+ (BOOL)exists:(NSString *)path {
    if (path.length == 0) return NO;
    if (access(path.fileSystemRepresentation, F_OK) == 0) return YES;
    return [self ensureAccess:path] && access(path.fileSystemRepresentation, F_OK) == 0;
}

+ (BOOL)isReadable:(NSString *)path {
    return [self ensureAccess:path];
}

#pragma mark - Container discovery

static WQItem *wq_item_at_path(NSString *path, uint64_t containerClass) {
    struct stat st;
    if (lstat(wq_normalize(path).fileSystemRepresentation, &st) != 0) return nil;
    WQItem *item = [WQItem new];
    item.path = wq_normalize(path);
    item.name = item.path.lastPathComponent;
    item.containerClass = containerClass;
    item.isDirectory = S_ISDIR(st.st_mode);
    item.size = (long long)st.st_size;
    item.modified = [NSDate dateWithTimeIntervalSince1970:st.st_mtimespec.tv_sec];
    return item;
}

static NSString *wq_container_identifier(NSString *path);

+ (NSString *)containerIdentifier:(NSString *)path {
    return wq_container_identifier(path);
}

static NSString *wq_container_identifier(NSString *path) {
    NSString *plistPath = [path stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
    // Reading the metadata is itself a sandbox-checked operation, so go
    // through dataAtPath (which grants) rather than +dictionaryWithContentsOfFile:.
    [WQAccess ensureAccess:path];
    NSData *data = [WQAccess dataAtPath:plistPath maxBytes:(1 << 20)];
    if (!data) return nil;

    id plist = [NSPropertyListSerialization propertyListWithData:data
                                                         options:NSPropertyListImmutable
                                                          format:NULL
                                                           error:NULL];
    if (![plist isKindOfClass:NSDictionary.class]) return nil;
    id identifier = ((NSDictionary *)plist)[@"MCMMetadataIdentifier"];
    return [identifier isKindOfClass:NSString.class] ? identifier : nil;
}

static NSString *wq_bundle_id_from_identifier(NSString *identifier) {
    if (identifier.length == 0) return nil;
    if (![identifier containsString:@"."]) return nil;
    if ([identifier hasPrefix:@"systemgroup."] || [identifier hasPrefix:@"group."]) return nil;
    // "com.apple.mobilesafari" or "com.foo.bar.widget" — both are identifiers.
    return identifier;
}

+ (NSArray<WQItem *> *)containers {
    NSMutableArray<WQItem *> *items = [NSMutableArray array];
    NSMutableArray<NSString *> *diagnostics = [NSMutableArray array];

    void *mgr = wq_mcm_handle();
    BOOL usedQuery = NO;
    if (mgr) {
        cq_create_fn create = (cq_create_fn)dlsym(mgr, "container_query_create");
        cq_u64_fn setClass = (cq_u64_fn)dlsym(mgr, "container_query_set_class");
        cq_iterate_fn iterate = (cq_iterate_fn)dlsym(mgr, "container_query_iterate_results_sync");
        cq_free_fn freeQuery = (cq_free_fn)dlsym(mgr, "container_query_free");
        co_path_fn getPath = (co_path_fn)dlsym(mgr, "container_object_get_path");
        co_id_fn getIdentifier = (co_id_fn)dlsym(mgr, "container_object_get_identifier");
        co_metadata_fn getMetadata = (co_metadata_fn)dlsym(mgr, "container_object_get_info");

        if (create && setClass && iterate && freeQuery && getPath) {
            NSMutableSet<NSString *> *seen = [NSMutableSet set];
            for (uint64_t cls = 1; cls <= 14; cls++) {
                void *query = create();
                if (!query) continue;
                __block NSUInteger count = 0;
                setClass(query, cls);
                @try {
                    iterate(query, ^bool(void *object) {
                        const char *raw = object ? getPath(object) : NULL;
                        if (!raw || !raw[0]) return true;
                        NSString *path = wq_normalize([NSString stringWithUTF8String:raw] ?: @"");
                        if (path.length == 0 || [seen containsObject:path]) return true;
                        [seen addObject:path];
                        WQItem *item = wq_item_at_path(path, cls);
                        if (item) {
                            const char *rawIdentifier = getIdentifier ? getIdentifier(object) : NULL;
                            NSString *fromObject = rawIdentifier && rawIdentifier[0]
                                ? [NSString stringWithUTF8String:rawIdentifier] : nil;

                            // Newer builds hide the identifier from the object
                            // and expose it in the metadata dictionary instead.
                            if (!fromObject && getMetadata) {
                                xpc_object_t info = getMetadata(object);
                                if (info && xpc_get_type(info) == XPC_TYPE_DICTIONARY) {
                                    const char *value = xpc_dictionary_get_string(info, "MCMMetadataIdentifier");
                                    if (value && value[0]) fromObject = [NSString stringWithUTF8String:value];
                                }
                            }
                            // Only fall back to reading the metadata plist when
                            // the object did not expose its identifier: one
                            // grant + read per container is not free.
                            item.identifier = fromObject ?: item.name;
                            item.bundleID = wq_bundle_id_from_identifier(item.identifier);
                            [items addObject:item];
                            count++;
                        }
                        return true;
                    });
                } @catch (NSException *exception) {
                    NSLog(@"[WQAccess] class %llu: %@", cls, exception.reason);
                }
                freeQuery(query);
                if (count) {
                    usedQuery = YES;
                    [diagnostics addObject:[NSString stringWithFormat:@"c%llu:%lu", cls, (unsigned long)count]];
                }
            }
        }
    }

    if (!usedQuery) {
        [diagnostics addObject:@"container manager returned nothing; falling back to parent listing"];
        NSArray<NSString *> *parents = @[
            @"/var/mobile/Containers/Data/Application",
            @"/var/mobile/Containers/Data/PluginKitPlugin",
            @"/var/mobile/Containers/Data/InternalDaemon",
            @"/var/mobile/Containers/Shared/AppGroup",
            @"/var/containers/Data/System",
            @"/var/containers/Shared/SystemGroup",
        ];
        for (NSString *parent in parents) {
            NSArray<WQItem *> *children = [self childrenOfDirectory:parent];
            NSString *failure = [self lastError];
            [items addObjectsFromArray:children];
            [diagnostics addObject:[NSString stringWithFormat:@"%@:%lu%@", parent.lastPathComponent,
                                    (unsigned long)children.count, failure ? @" (denied)" : @""]];
        }
    }

    gContainerSummary = diagnostics.count ? [diagnostics componentsJoinedByString:@" "] : @"no containers";
    return items;
}

+ (NSString *)containerSummary { return gContainerSummary; }

#pragma mark - Filesystem

+ (NSArray<WQItem *> *)contentsOfDirectory:(NSString *)path {
    wq_set_error(nil);
    if (path.length == 0) return @[];
    [self ensureAccess:path];

    NSString *dirPath = wq_normalize(path);
    DIR *dir = opendir(dirPath.fileSystemRepresentation);
    if (!dir) {
        // The token may target the parent, or the path may be a symlink we
        // must follow after granting its resolved target.
        NSString *resolved = dirPath.stringByResolvingSymlinksInPath;
        if (![resolved isEqualToString:dirPath] && [self ensureAccess:resolved]) {
            dir = opendir(resolved.fileSystemRepresentation);
        }
    }
    if (!dir) {
        int err = errno;
        wq_set_error([NSString stringWithFormat:@"%s (errno %d)", strerror(err), err]);
        return @[];
    }

    NSMutableArray<WQItem *> *items = [NSMutableArray array];
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        NSString *child = [dirPath stringByAppendingPathComponent:[NSString stringWithUTF8String:entry->d_name]];
        WQItem *item = wq_item_at_path(child, 0);
        if (!item) continue;   // dangling symlink or raced away
        [items addObject:item];
    }
    closedir(dir);

    [items sortUsingComparator:^NSComparisonResult(WQItem *a, WQItem *b) {
        if (a.isDirectory != b.isDirectory) return a.isDirectory ? NSOrderedAscending : NSOrderedDescending;
        return [a.name caseInsensitiveCompare:b.name];
    }];
    return items;
}

+ (NSData *)dataAtPath:(NSString *)path maxBytes:(NSUInteger)maxBytes {
    wq_set_error(nil);
    NSString *resolved = wq_normalize(path);
    if (![self ensureAccess:resolved]) {
        wq_set_error(@"sandbox extension was refused");
        return nil;
    }

    int fd = open(resolved.fileSystemRepresentation, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        wq_set_error([NSString stringWithFormat:@"open: %s (errno %d)", strerror(errno), errno]);
        return nil;
    }

    NSMutableData *data = [NSMutableData dataWithCapacity:MIN((NSUInteger)65536, maxBytes)];
    uint8_t buffer[65536];
    while (data.length < maxBytes) {
        size_t want = MIN(sizeof(buffer), maxBytes - data.length);
        ssize_t got = read(fd, buffer, want);
        if (got > 0) { [data appendBytes:buffer length:(NSUInteger)got]; continue; }
        if (got == 0) break;
        if (errno == EINTR) continue;
        wq_set_error([NSString stringWithFormat:@"read: %s (errno %d)", strerror(errno), errno]);
        close(fd);
        return nil;
    }
    close(fd);
    return data;
}

+ (NSArray<NSString *> *)leakedChildrenOfDirectory:(NSString *)path limit:(NSUInteger)limit {
    if (path.length == 0) return @[];
    NSString *base = wq_normalize(path);

    // A token for a child of the parent is enough for fsgetpath to resolve.
    uint64_t maxInode = pathleak_inode_hint(nil, base);
    if (maxInode == 0) {
        wq_set_error(@"could not determine the file id range for this volume");
        return @[];
    }

    __block BOOL cancelled = NO;
    NSArray<NSString *> *paths = pathleak(base, maxInode, limit, &cancelled);
    return paths ?: @[];
}

+ (NSArray<WQItem *> *)childrenOfDirectory:(NSString *)path {
    NSArray<WQItem *> *direct = [self contentsOfDirectory:path];
    if (direct.count > 0) return direct;

    NSString *failure = [self lastError];
    if (failure.length && [failure containsString:@"Permission denied"]) {
        // EACCES on a root-owned parent cannot be fixed by an extension.
        return direct;
    }

    NSArray<NSString *> *leaked = [self leakedChildrenOfDirectory:path limit:0];
    if (leaked.count == 0) return direct;

    NSMutableArray<WQItem *> *items = [NSMutableArray arrayWithCapacity:leaked.count];
    for (NSString *child in leaked) {
        // lstat() on the child still needs an extension of its own.
        [self ensureAccess:child];
        WQItem *item = wq_item_at_path(child, 0);
        if (item) [items addObject:item];
    }
    [items sortUsingComparator:^NSComparisonResult(WQItem *a, WQItem *b) {
        if (a.isDirectory != b.isDirectory) return a.isDirectory ? NSOrderedAscending : NSOrderedDescending;
        return [a.name caseInsensitiveCompare:b.name];
    }];
    return items;
}

+ (NSArray<WQItem *> *)searchPath:(NSString *)root
                            query:(NSString *)query
                          maxDepth:(NSUInteger)maxDepth
                             limit:(NSUInteger)limit
                          progress:(BOOL (^)(NSString *))progress {
    NSMutableArray<WQItem *> *matches = [NSMutableArray array];
    if (root.length == 0 || limit == 0) return matches;

    NSString *start = wq_normalize(root);
    NSMutableArray<NSArray *> *queue = [NSMutableArray arrayWithObject:@[start, @0]];
    NSMutableSet<NSString *> *visited = [NSMutableSet set];
    NSString *needle = query.lowercaseString;

    while (queue.count && matches.count < limit) {
        NSArray *node = queue.firstObject;
        [queue removeObjectAtIndex:0];
        NSString *dir = node[0];
        NSUInteger depth = [node[1] unsignedIntegerValue];
        if ([visited containsObject:dir]) continue;
        [visited addObject:dir];
        if (progress && !progress(dir)) break;
        if (depth > maxDepth) continue;

        NSArray<WQItem *> *children = [self contentsOfDirectory:dir];
        for (WQItem *child in children) {
            if (needle.length == 0 || [child.name.lowercaseString containsString:needle]) {
                [matches addObject:child];
                if (matches.count >= limit) break;
            }
            if (child.isDirectory && ![child.name hasPrefix:@"."]) [queue addObject:@[child.path, @(depth + 1)]];
        }
    }
    return matches;
}

@end
