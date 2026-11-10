//
//  SubscriptionScanner.swift
//  sandbox
//
//  Finds subscription records inside the containers worse_query reaches.
//
//  Measured reach on iOS 27.2 (device):
//    AppGroup                     189 entries   <- listable
//    /var/containers/Data/System   22 entries   <- listable
//    Data/Application, PluginKitPlugin, InternalDaemon,
//    Shared/SystemGroup, Bundle/Application    <- parent has no extension
//
//  Everything here is streamed: the container list is walked one entry at a
//  time, files are read with a hard size cap, and nothing is retained except
//  the parsed records. The first version kept every path and file in memory
//  and the app was killed part-way through the 189 app groups.
//

import Foundation

// MARK: - Record

struct SandboxSubscription: Identifiable, Hashable {
    enum Source: String {
        case receipt = "Receipt"
        case transaction = "JWS transaction"
        case store = "Store file"
    }

    let id = UUID()
    var productID: String
    var transactionID: String?
    var originalTransactionID: String?
    var purchaseDate: Date?
    var expiresDate: Date?
    var revokedDate: Date?
    var source: Source
    /// Container (or app) the record was found in.
    var owner: String
    var sourcePath: String
    var isTrial: Bool = false

    var isExpired: Bool {
        guard let expires = expiresDate else { return false }
        return expires < Date()
    }

    var statusText: String {
        if revokedDate != nil { return "Revoked" }
        if let expires = expiresDate { return isExpired ? "Expired" : "Active" }
        return "Non-renewing"
    }

    /// Drives the row badge.
    var statusColor: String {
        if revokedDate != nil { return "red" }
        if expiresDate == nil { return "gray" }
        return isExpired ? "orange" : "green"
    }

    static func == (lhs: SandboxSubscription, rhs: SandboxSubscription) -> Bool {
        lhs.transactionID == rhs.transactionID &&
        lhs.productID == rhs.productID &&
        lhs.sourcePath == rhs.sourcePath
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(transactionID)
        hasher.combine(productID)
        hasher.combine(sourcePath)
    }
}

// MARK: - Scanner

final class SubscriptionScanner {
    struct ScanProgress {
        var scanned: Int = 0
        var total: Int = 0
        var current: String = ""
        var found: Int = 0
        /// Path of the last file examined, so a stall is visible.
        var lastPath: String = ""
    }

    enum ScanError: LocalizedError {
        case noAccess
        case outOfMemory

        var errorDescription: String? {
            switch self {
            case .noAccess: return "no sandbox extension is available"
            case .outOfMemory: return "the scan was stopped to avoid running out of memory"
            }
        }
    }

    /// Directories inside an app container that can hold StoreKit artifacts.
    private static let appSubpaths = [
        "Library/Caches",
        "Library/Application Support",
        "Library/Preferences",
        "Documents",
    ]

    /// Containers whose identifier suggests App Store / StoreKit data.
    private static let storeKeywords = ["storekit", "appstore", "itunesstore", "commerce", "store"]

    private static let interestingExtensions: Set<String> = [
        "jws", "storekit", "receipt", "transaction",
    ]

    /// A single receipt/JWS is a few KB. 1 MB is already generous and stops a
    /// stray database or asset from being loaded.
    private static let maxFileBytes: UInt = 1 << 20
    /// Ceiling for the whole scan, so a pathological tree cannot fill memory.
    private static let maxTotalThreadsRead: Int = 4000

    var onProgress: ((ScanProgress) -> Void)?
    private var cancelled = false
    private var filesRead = 0

    func cancel() { cancelled = true }

    // MARK: Scan

    func scan(includeAppContainers: Bool = false) -> [SandboxSubscription] {
        filesRead = 0
        var records: [SandboxSubscription] = []
        var seen = Set<String>()

        func add(_ record: SandboxSubscription) {
            // Bounded de-duplication: a device with many stores can otherwise
            // grow this set without limit.
            guard records.count < 5000 else { return }
            let key = "\(record.transactionID ?? "")|\(record.productID)|\(record.sourcePath)"
            guard !seen.contains(key) else { return }
            seen.insert(key)
            records.append(record)
        }

        func harvest(_ path: String, owner: String, source: SandboxSubscription.Source) {
            guard !cancelled else { return }
            guard filesRead < Self.maxTotalThreadsRead else { return }
            filesRead += 1

            guard let data = WQAccess.data(atPath: path, maxBytes: Self.maxFileBytes) else { return }
            defer { /* data released here; nothing is retained */ }

            if let transaction = JWSParser.parse(data), let productID = transaction.productID {
                add(SandboxSubscription(
                    productID: productID,
                    transactionID: transaction.transactionID,
                    originalTransactionID: transaction.originalTransactionID,
                    purchaseDate: transaction.purchaseDate,
                    expiresDate: transaction.expiresDate,
                    revokedDate: transaction.revocationDate,
                    source: .transaction,
                    owner: owner,
                    sourcePath: path
                ))
                return
            }
            if let payload = ReceiptParser.parse(data) {
                for purchase in payload.inApp {
                    guard let productID = purchase.productID else { continue }
                    add(SandboxSubscription(
                        productID: productID,
                        transactionID: purchase.transactionID,
                        originalTransactionID: purchase.originalTransactionID,
                        purchaseDate: purchase.purchaseDate,
                        expiresDate: purchase.expiresDate,
                        revokedDate: purchase.cancellationDate,
                        source: source,
                        owner: owner,
                        sourcePath: path,
                        isTrial: purchase.isTrialPeriod || purchase.isInIntroOfferPeriod
                    ))
                }
            }
        }

        WQLog.message("scan start (app containers: \(includeAppContainers ? "yes" : "no"))")

        let roots = Self.scanRoots(includeAppContainers: includeAppContainers)
        report(total: Swift.max(roots.count, 1), current: "Locating containers")

        for (rootIndex, root) in roots.enumerated() {
            if cancelled { break }
            report(total: roots.count, scanned: rootIndex, current: root.name, found: records.count)

            // Walk this root one directory at a time; children are released as
            // soon as they have been examined.
            var queue: [(path: String, depth: Int)] = [(root.path, 0)]
            var visited = Set<String>()

            while let node = queue.popLast() {
                if cancelled { break }
                if node.depth > 4 { continue }
                guard visited.count < 2000, !visited.contains(node.path) else { continue }
                visited.insert(node.path)

                report(total: roots.count, scanned: rootIndex, current: root.name,
                       found: records.count, lastPath: node.path)

                let children = WQAccess.contentsOfDirectory(node.path)
                WQLog.message("  \(node.path) -> \(children.count) entries")

                for item in children {
                    if cancelled { break }
                    if item.isDirectory {
                        if item.depthIsWorthWalking {
                            queue.append((item.path, node.depth + 1))
                        }
                        continue
                    }
                    guard item.size > 0, item.size <= Int64(Self.maxFileBytes) else { continue }
                    let name = item.name.lowercased()
                    let ext = (item.path as NSString).pathExtension.lowercased()
                    guard name.contains("receipt") || name.contains("transaction") ||
                          name.contains("storekit") || Self.interestingExtensions.contains(ext) else { continue }
                    harvest(item.path, owner: root.name, source: .transaction)
                }
            }

            // StoreKit writes receipts under fixed names inside app containers.
            for subpath in Self.appSubpaths {
                for leaf in ["_MASReceipt/receipt", "StoreKit/receipt", "receipt"] {
                    let candidate = root.path + "/" + subpath + "/" + leaf
                    guard WQAccess.exists(candidate) else { continue }
                    harvest(candidate, owner: root.name, source: .receipt)
                }
            }
        }

        WQLog.message("scan done: \(records.count) records from \(filesRead) files\(cancelled ? " (cancelled)" : "")")
        return records.sorted {
            ($0.purchaseDate ?? .distantPast) > ($1.purchaseDate ?? .distantPast)
        }
    }

    private func report(total: Int, scanned: Int = 0, current: String = "",
                        found: Int = 0, lastPath: String = "") {
        onProgress?(ScanProgress(scanned: scanned, total: Swift.max(total, 1),
                                 current: current, found: found, lastPath: lastPath))
    }

    // MARK: Roots

    struct Root {
        let name: String
        let path: String
    }

    static func scanRoots(includeAppContainers: Bool) -> [Root] {
        var roots: [Root] = []
        var seen = Set<String>()

        func add(_ name: String, _ path: String) {
            guard !seen.contains(path) else { return }
            seen.insert(path)
            roots.append(Root(name: name, path: path))
        }

        // 1. App groups: listable on 27.x. Only groups whose name suggests
        //    commerce are worth a deep walk; the rest are cheap to skip.
        let groups = WQAccess.contentsOfDirectory("/var/mobile/Containers/Shared/AppGroup")
        WQLog.message("app groups: \(groups.count)")
        for item in groups {
            let identifier = (item.identifier ?? item.name).lowercased()
            guard storeKeywords.contains(where: { identifier.contains($0) }) else { continue }
            add(ownerName(for: item), item.path)
        }

        // 2. System container root: a "System Data" folder.
        let system = WQAccess.contentsOfDirectory("/var/containers/Data/System")
        WQLog.message("system data: \(system.count)")
        for item in system {
            let identifier = (item.identifier ?? item.name).lowercased()
            guard storeKeywords.contains(where: { identifier.contains($0) }) else { continue }
            add(ownerName(for: item), item.path)
        }

        // 3. System groups: the parent refuses an extension, but known names
        //    open when asked for directly.
        for name in knownSystemGroupNames() {
            let path = "/var/containers/Shared/SystemGroup/" + name
            guard WQAccess.exists(path) else { continue }
            add(name, path)
        }

        // 4. App containers need a file id scan; only on request.
        if includeAppContainers {
            let leaked = WQAccess.leakedChildren(ofDirectory: "/var/mobile/Containers/Data/Application",
                                                 limit: 400)
            WQLog.message("leaked app containers: \(leaked.count)")
            for path in leaked {
                add((path as NSString).lastPathComponent, path)
            }
        }

        return roots
    }

    /// Names of system group containers worth probing. Kept small: each miss
    /// costs a full query round trip.
    static func knownSystemGroupNames() -> [String] {
        [
            "systemgroup.com.apple.storekit",
            "systemgroup.com.apple.appstore",
            "systemgroup.com.apple.itunesstore",
            "systemgroup.com.apple.commerce",
            "systemgroup.com.apple.appstored",
        ]
    }

    /// A readable name for a container: bundle id when known, else its UUID.
    static func ownerName(for item: WQItem) -> String {
        if let bundleID = item.bundleID, !bundleID.isEmpty { return bundleID }
        if let identifier = item.identifier, !identifier.isEmpty { return identifier }
        return item.name
    }
}

private extension WQItem {
    /// Skip caches and bundles of frameworks — they never hold receipts and
    /// walking them is what made the first version explode.
    var depthIsWorthWalking: Bool {
        let lowercased = name.lowercased()
        if lowercased.hasSuffix(".app") || lowercased.hasSuffix(".framework") { return false }
        if lowercased.hasSuffix(".bundle") { return false }
        if lowercased == "node_modules" || lowercased == "caches" { return false }
        // Hidden directories are system bookkeeping, except .com.apple.*
        if name.hasPrefix(".") { return name.hasPrefix(".com.apple") }
        return true
    }
}
